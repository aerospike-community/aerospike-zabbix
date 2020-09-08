#!/usr/bin/env python3
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#

# Copyright 2013-2020 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Description: Zabbix script for Aerospike

__author__ = "Aerospike"
__copyright__ = "Copyright 2020 Aerospike"
__version__ = "3.0.0"


import sys
import socket
import re
import argparse
import struct
import time
import getpass
from ctypes import create_string_buffer

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4

arg_host = "127.0.0.1"
arg_port = 3000
arg_stat = None
user = None
password = None

DEFAULT_TIMEOUT = 5

# =============================================================================
#
# Client
#
# -----------------------------------------------------------------------------

_OK = 0
_INVALID_COMMAND = 54

_ADMIN_MSG_VERSION = 0
_ADMIN_MSG_TYPE = 2

_AUTHENTICATE = 0
_LOGIN = 20

_USER_FIELD_ID = 0
_CREDENTIAL_FIELD_ID = 3
_CLEAR_PASSWORD_FIELD_ID = 4
_SESSION_TOKEN_FIELD_ID = 5
_SESSION_TTL_FIELD_ID = 6

_HEADER_SIZE = 24
_HEADER_REMAINING = 16


class Enumeration(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

    def __getitem__(self, name):
        if name in self:
            return name
        raise AttributeError

AuthMode = Enumeration([
    # Use internal authentication only.  Hashed password is stored on the server.
	# Do not send clear password. This is the default.

	"INTERNAL",

    # Use external authentication (like LDAP).  Specific external authentication is
	# configured on server.  If TLS defined, send clear password on node login via TLS.
	# Throw exception if TLS is not defined.

	"EXTERNAL",

    # Use external authentication (like LDAP).  Specific external authentication is
	# configured on server.  Send clear password on node login whether or not TLS is defined.
	# This mode should only be used for testing purposes because it is not secure authentication.

	"EXTERNAL_INSECURE",
])

class ClientError(Exception):
        pass

class Client(object):

    def __init__(self, addr, port, timeout=DEFAULT_TIMEOUT):
        self.addr = addr
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self, tls_enable=False, tls_name=None, tls_keyfile=None, tls_keyfile_pw=None, tls_certfile=None,
                 tls_cafile=None, tls_capath=None, tls_ciphers=None, tls_protocols=None, tls_cert_blacklist=None,
                 tls_crl_check=False, tls_crl_check_all=False):
        s = None
        for addrinfo in socket.getaddrinfo(self.addr, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = addrinfo
            ssl_context = None

            try:
                s = socket.socket(af, socktype, proto)
                s.settimeout(self.timeout)
            except socket.error:
                s = None
                continue

            if tls_enable:
                try:
                    from ssl.ssl_context import SSLContext
                    from OpenSSL import SSL
                except Exception:
                    raise ClientError("No module named pyOpenSSL")

                try:
                    ssl_context = SSLContext(enable_tls=tls_enable, encrypt_only=None,
                                  cafile=tls_cafile, capath=tls_capath,
                                  keyfile=tls_keyfile, keyfile_password=tls_keyfile_pw,
                                  certfile=tls_certfile, protocols=tls_protocols,
                                  cipher_suite=tls_ciphers,
                                  cert_blacklist=tls_cert_blacklist,
                                  crl_check=tls_crl_check,
                                  crl_check_all=tls_crl_check_all).ctx
                    s = SSL.Connection(ssl_context,s)
                except Exception as ex:
                    raise ClientError("Could not connect to server at %s %s: %s" % (self.addr, self.port, str(ex)))

            try:
                s.connect(sa)
                if ssl_context:
                    s.set_app_data(tls_name)
                    # timeout on wrapper might give errors
                    s.setblocking(1)
                    s.do_handshake()
            except Exception as msg:
                s.close()
                s = None
                print ("Connect Error %s" % msg)
                continue

            break

        if s is None:
            raise ClientError("Could not connect to server at %s %s" % (self.addr, self.port))

        self.sock = s

    def close(self):
        if self.sock is not None:
            self.sock.settimeout(None)
            self.sock.close()
            self.sock = None

    def auth(self, username, password, auth_mode=AuthMode.INTERNAL):
        # login and authentication
        credential = self._hashpassword(password)

        if auth_mode == AuthMode.INTERNAL:
            sz = len(user) + len(credential) + 34 # 2 * 5 + 24
            send_buf = self._admin_write_header(sz, _LOGIN, 2)
            fmt_str = "! I B %ds I B %ds" % (len(user), len(credential))
            struct.pack_into(fmt_str, send_buf, _HEADER_SIZE,
                             len(user) + 1, _USER_FIELD_ID, user.encode(),
                             len(credential) + 1, _CREDENTIAL_FIELD_ID, credential)

        else:
            sz = len(user) + len(credential) + len(password) + 39  # 3 * 5 + 24
            send_buf = self._admin_write_header(sz, _LOGIN, 3)
            fmt_str = "! I B %ds I B %ds I B %ds" % (len(user), len(credential), len(password))
            struct.pack_into(fmt_str, send_buf, _HEADER_SIZE,
                             len(user) + 1, _USER_FIELD_ID, user.encode(),
                             len(credential) + 1, _CREDENTIAL_FIELD_ID, credential,
                             len(password) + 1, _CLEAR_PASSWORD_FIELD_ID, password.encode())

        try:
            # OpenSSL wrapper doesn't support ctypes
            send_buf = self._buffer_to_string(send_buf)
            self.sock.sendall(send_buf.encode())
            recv_buff = self._recv(_HEADER_SIZE)
            rv = self._admin_parse_header(recv_buff)

            result = rv[2]
            if result != _OK:
                # login failed

                if result == _INVALID_COMMAND:
                    # login is invalid command, so cluster does not support ldap
                    return self._authenticate(user, password=credential, password_field_id=_CREDENTIAL_FIELD_ID)

                # login failed
                return result

            sz = int(rv[0] & 0xFFFFFFFFFFFF) - _HEADER_REMAINING
            field_count = rv[4]
            if sz < 0 or field_count < 1:
                raise ClientError("Login failed to retrieve session token")

            recv_buff = self._recv(sz)

            return 0

        except Exception as ex:
            raise ClientError("Autentication Error %s for '%s' " %(str(ex), username))

    def info(self, request):
        self._send_request(request)
        res = self._recv_response()
        out = re.split("\s+", res, maxsplit=1)

        if len(out) == 2:
            if out[0].strip("") != request:
                raise ClientError("Error: requeted %s, got %s" % (request, res))
            return out[1]
        else:
            raise ClientError("Failed to parse response: %s" % (res))

    def _send(self, data):
        if self.sock:
            try:
                self.sock.send(data)
            except IOError as e:
                raise ClientError(e)
            except socket.error as e:
                raise ClientError(e)
        else:
            raise ClientError('socket not available')

    def _send_request(self, request, info_msg_version=2, info_msg_type=1):
        if request:
            request += '\n'
        proto = (info_msg_version << 56) | (info_msg_type << 48) | (len(request)+1)
        fmt_str = "! Q %ds B" % len(request)
        buf = struct.pack(fmt_str, proto, request.encode(), 10)

        self._send(buf)

    def _recv(self, sz):
        out = ""
        pos = 0
        start_time = time.time()
        while pos < sz:
            buf = None
            try:
                buf = self.sock.recv(sz-pos)
            except IOError as e:
                raise ClientError(e)

            if pos == 0:
                out = buf
            else:
                out += buf

            pos += len(buf)
            if self.timeout and time.time() - start_time > self.timeout:
                raise ClientError(socket.timeout())
        return out

    def _recv_response(self):
        try:
            buf = self.sock.recv(8)
            q = struct.unpack_from('! Q', buf, 0)
            sz = q[0] & 0xFFFFFFFFFFFF
            if sz > 0:
                response_bytes = self._recv(sz)
                return response_bytes.decode('utf-8')
        except Exception as ex:
            raise IOError("Error: %s" % str(ex))

    def _hashpassword(self, password):
        if password == None:
            return ""

        if len(password) != 60 or password.startswith("$2a$") == False:
            try:
                import bcrypt

            except Exception as e:
                # bcrypt not installed. This should only be
                # fatal when authentication is required.
                raise e

            return bcrypt.hashpw(password.encode(), b"$2a$10$7EqJtq98hPqEX7fNZaFWoO")

        return ""

    def _admin_write_header(self, sz, command, field_count):
        send_buf = create_string_buffer(sz)      # from ctypes
        sz = (_ADMIN_MSG_VERSION << 56) | (_ADMIN_MSG_TYPE << 48) | (sz - 8)

        g_struct_admin_header_out = struct.Struct('! Q B B B B 12x')
        g_struct_admin_header_out.pack_into(send_buf, 0, sz, 0, 0, command, field_count)

        return send_buf

    def _admin_parse_header(self, data):
        g_struct_admin_header_in = struct.Struct('! Q B B B B 12x')
        return g_struct_admin_header_in.unpack(data)

    def _buffer_to_string(self, buf):
        buf_str = ""
        for s in buf:
            buf_str += s.decode()
        return buf_str

    def _authenticate(self, user, password, password_field_id):
        sz = len(user) + len(password) + 34 # 2 * 5 + 24
        send_buf = self._admin_write_header(sz, _AUTHENTICATE, 2)
        fmt_str = "! I B %ds I B %ds" % (len(user), len(password))
        struct.pack_into(fmt_str, send_buf, _HEADER_SIZE,
                         len(user) + 1, _USER_FIELD_ID, user,
                         len(password) + 1, password_field_id, password)
        try:
            # OpenSSL wrapper doesn't support ctypes
            send_buf = self._buffer_to_string(send_buf)
            self.sock.sendall(send_buf)
            recv_buff = self._recv(_HEADER_SIZE)
            rv = self._admin_parse_header(recv_buff)
            return rv[2]
        except Exception as ex:
            raise IOError("Error: %s" % str(ex))

# =============================================================================
#
# Std. Out Stream
#
# -----------------------------------------------------------------------------

class OutputStream():
    def __init__(self):
        self.list = ["{", "\t\"data\":["]
        self.first = True

    def add(self, metricname, metricvalue):
        if not self.first:
            self.list.append("\t,")
        self.first = False

        #
        # Find  unit of measurement for the statstic
        #
        metricunits = ''
        if "pct" in metricname:
            metricunits = '%'
        # All Byte metrics have "bytes" in the name except the values in this set.
        elif "bytes" in metricname or metricname in {"ibtr_memory_used", "nbtr_memory_used", "si_accounted_memory"}:
            metricunits = 'Bytes'

        # Convert non numeric values to numeric
        if metricvalue == "true" or metricvalue == "on":
            metricvalue = "1"
            metricunits = "Bool"
        elif metricvalue == "false" or metricvalue == "off":
            metricvalue = "0"
            metricunits = "Bool"

        if metricname in {"cluster_key", "cluster_principal", "paxos_principal"}:
            metricvalue = str(int(metricvalue,16)) # Convert HEX id to numerical
        # dc_state is a metric in pre 5.0 server
        elif metricname == "dc_state":
            if metricvalue == "CLUSTER_INACTIVE":
                metricvalue = "0"
            elif metricvalue == "CLUSTER_UP":
                metricvalue = "1"
            elif metricvalue == "CLUSTER_DOWN":
                metricvalue = "2"
            else:
                # CLUSTER_WINDOW_SHIP
                metricvalue = "3"
                

        self.list.append("\t{")
        self.list.append("\t\t\"{#METRICNAME}\":\""+metricname+"\",")
        self.list.append("\t\t\"{#METRICVALUE}\":\""+metricvalue+"\",")
        self.list.append("\t\t\"{#METRICUNITS}\":\""+metricunits+"\"")
        self.list.append("\t}")

    def printStream(self):
        self.list.append("\t]")
        self.list.append("}")
        print("\n".join(self.list))

# =============================================================================
#
# Argument Parsing
#
# -----------------------------------------------------------------------------
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-u'
                    , '--usage'
                    , '--help'
                    , action="help"
                    , help="Show this help message and exit")
parser.add_argument("-U"
                    , "--user"
                    , help="user name")
parser.add_argument("-P"
                    , "--password"
                    , nargs="?"
                    , const="prompt"
                    , help="password")
parser.add_argument("--credentials-file"
                    , dest="credentials"
                    , help="Path to the credentials file. Use this in place of --user and --password.")
parser.add_argument("--auth-mode"
                    , dest="auth_mode"
                    , default=str(AuthMode.INTERNAL)
                    , help="Authentication mode. Values: " + str(list(AuthMode)) + " (default: %(default)s)")
parser.add_argument("-v"
                    , "--verbose"
                    , action="store_true"
                    , dest="verbose"
                    , help="Enable verbose logging")
group = parser.add_mutually_exclusive_group()
group.add_argument("-n"
                    , "--namespace"
                    , dest="namespace"
                    , help="Namespace name. eg: bar")
group.add_argument("-l"
                    , "--latency"
                    , dest="latency"
                    , action="store_const"
                    , const = True
                    , help="Options: see output of asinfo -v 'latency:hist' -l")
group.add_argument("-x"
                    , "--xdr"
                    , dest="dc"
                    , help="Datacenter name. eg: myDC1")
group2 = parser.add_mutually_exclusive_group()
group2.add_argument("-t"
                    , "--set"
                    , dest="set"
                    , help="Set name. eg: testSet. Statistic for a particular set in a particular namespace.")
group2.add_argument("-b"
                    , "--bin"
                    , dest="bin"
                    , action="store_const"
                    , const=True
                    , help="Bin usage information for a particular namspace.")
group2.add_argument("-i"
                    , "--sindex"
                    , dest="sindex"
                    , help="Secondary Index name. eg: age. Statistic for a particular secondary index in a particular namespace.")
parser.add_argument("-s"
                    , "--stat"
                    , dest="stat"
                    , help="Statistic name. eg: cluster_size")
parser.add_argument("-p"
                    , "---port"
                    , dest="port"
                    , default=3000
                    , help="PORT for Aerospike server (default: %(default)s)")
parser.add_argument("-h"
                    , "--host"
                    , dest="host"
                    , default="127.0.0.1"
                    , help="HOST for Aerospike server (default: %(default)s)")
parser.add_argument("-d"
                    , dest="dummy"
                    , help="Dummy variable for templating")
parser.add_argument("--timeout"
                    , dest="timeout"
                    , default=DEFAULT_TIMEOUT
                    , help="Set timeout value in seconds to node level operations. " +
                           "TLS connection does not support timeout. (default: %(default)s)")
parser.add_argument("--tls-enable"
                    , action="store_true"
                    , dest="tls_enable"
                    , help="Enable TLS")
parser.add_argument("--tls-name"
                    , dest="tls_name"
                    , help="The expected name on the server side certificate")
parser.add_argument("--tls-keyfile"
                    , dest="tls_keyfile"
                    , help="The private keyfile for your client TLS Cert")
parser.add_argument("--tls-keyfile-pw"
                    , dest="tls_keyfile_pw"
                    , help="Password to load protected tls-keyfile")
parser.add_argument("--tls-certfile"
                    , dest="tls_certfile"
                    , help="The client TLS cert")
parser.add_argument("--tls-cafile"
                    , dest="tls_cafile"
                    , help="The CA for the server's certificate")
parser.add_argument("--tls-capath"
                    , dest="tls_capath"
                    , help="The path to a directory containing CA certs and/or CRLs")
parser.add_argument("--tls-ciphers"
                    , dest="tls_ciphers"
                    , help="Ciphers to include. See https://www.openssl.org/docs/man1.1.0/man1/ciphers.html for cipher list format")
parser.add_argument("--tls-protocols"
                    , dest="tls_protocols"
                    , help="The TLS protocol to use. Available choices: TLSv1, TLSv1.1, TLSv1.2, all. An optional + or - can be appended before the protocol to indicate specific inclusion or exclusion.")
parser.add_argument("--tls-cert-blacklist"
                    , dest="tls_cert_blacklist"
                    , help="Blacklist including serial number of certs to revoke")
parser.add_argument("--tls-crl-check"
                    , dest="tls_crl_check"
                    , action="store_true"
                    , help="Checks SSL/TLS certs against vendor's Certificate Revocation Lists for revoked certificates. CRLs are found in path specified by --tls-capath. Checks the leaf certificates only")
parser.add_argument("--tls-crl-check-all"
                    , dest="tls_crl_check_all"
                    , action="store_true"
                    , help="Check on all entries within the CRL chain")

args = parser.parse_args()

notNone = any(arg is not None for arg in [args.set, args.bin, args.sindex])
if notNone and args.namespace is None:
    parser.error("--set, --bin, and --sindex require --namespace")

user = None
password = None

if args.user is not None:
    user = args.user
    if args.password == "prompt":
        args.password = getpass.getpass("Enter Password:")
    password = args.password

if args.credentials:
    try:
        cred_file = open(args.credentials,'r')
        user = cred_file.readline().strip()
        password = cred_file.readline().strip()
    except IOError:
        print("Unable to read credentials file: %s"%args.credentials)

# =============================================================================
#
# Mainline
#
# -----------------------------------------------------------------------------

try:
    client = Client(addr=args.host,port=args.port, timeout=args.timeout)
    client.connect(tls_enable=args.tls_enable, tls_name=args.tls_name,
                   tls_keyfile=args.tls_keyfile, tls_keyfile_pw=args.tls_keyfile_pw, tls_certfile=args.tls_certfile,
                   tls_cafile=args.tls_cafile, tls_capath=args.tls_capath, tls_ciphers=args.tls_ciphers,
                   tls_protocols=args.tls_protocols, tls_cert_blacklist=args.tls_cert_blacklist,
                   tls_crl_check=args.tls_crl_check, tls_crl_check_all=args.tls_crl_check_all)
except Exception as e:
    print("Failed to connect to the Aerospike cluster at %s:%s"%(args.host,args.port))
    print(e)
    sys.exit(STATE_UNKNOWN)

if user:
    try:
        status = client.auth(username=user, password=password, auth_mode=args.auth_mode)
        if status != 0:
            print("Failed to authenticate connection to the Aerospike cluster at %s:%s, status: %s"%(args.host,args.port, str(status)))
            sys.exit(STATE_UNKNOWN)
    except Exception as e:
        print("Failed to authenticate connection to the Aerospike cluster at %s:%s"%(args.host,args.port))
        print(e)
        sys.exit(STATE_UNKNOWN)

asinfo_cmd = "statistics"

# Find server version to find correct asinfo commands.
req = 'build'
try:
    version = client.info(req).split('.')
except Exception as e:
        print("Failed to execute asinfo command %s on the Aerospike cluster at %s:%s"%(req, args.host, args.port))
        print(e)
        sys.exit(STATE_UNKNOWN)

use_latencies_cmd = int(version[0]) > 5 or (int(version[0]) == 5 and int(version[1]) >= 1)
latency_histogram = ''
latency_time = ''

if args.dc:
        asinfo_cmd = 'dc/' + args.dc

        # Version 5.0+ got removed dc/DC_NAME and added get-stats:context=xdr;dc=DC_NAME
        if int(version[0]) >= 5:
            asinfo_cmd = 'get-stats:context=xdr;dc=' + args.dc

# namespace must be checked after sets, bins, and sindex
elif args.set:
    asinfo_cmd = 'sets/' + args.namespace + '/' + args.set
elif args.bin:
    asinfo_cmd = 'bins/' + args.namespace
elif args.sindex:
    asinfo_cmd = 'sindex/' + args.namespace + '/' + args.sindex
elif args.namespace:
    asinfo_cmd = 'namespace/' + args.namespace
elif args.latency:
    if use_latencies_cmd:
        asinfo_cmd = 'latencies:'
    else:
        asinfo_cmd = 'latency:'
    if args.stat:
        latency_histogram, latency_time = args.stat.rsplit('-', 1)
        print(latency_histogram, latency_time)
        asinfo_cmd += "hist=" + latency_histogram

try:
    res = client.info(asinfo_cmd).strip()
except Exception as e:
    print("Failed to execute asinfo command %s on the Aerospike cluster at %s:%s"%(asinfo_cmd, args.host, args.port))
    print(e)
    sys.exit(STATE_UNKNOWN)

client.close()

if res == None:
    print("request to ",args.host,":",args.port," returned no data.")
    sys.exit(STATE_CRITICAL)

if res == -1:
    print("request to ",args.host,":",args.port," returned error.")
    sys.exit(STATE_CRITICAL)

# Create lists of latency options
latency_metrics = ["tps"] 
if use_latencies_cmd:
    latency_metrics.extend([str(2**i) + 'ms' for i in range(0, 17)])
else: 
    latency_metrics.extend(["1ms", "8ms", "64ms"])

if args.stat is not None:
    stat = args.stat
    metric = None
    if args.latency:
        # remove appended historgram value.
        stat, metric = args.stat.rsplit('-', 1)
    if stat not in res:
        print("%s is not a known statistic." %args.stat)
        sys.exit(STATE_UNKNOWN)
    elif metric and (metric not in latency_metrics):
        if use_latencies_cmd:
            print("%s is not a know latencies histogram." % metric)
        else:
            print("%s is not a know latency histogram." % metric)
        sys.exit(STATE_UNKNOWN)

if res.endswith(";"):
    res = res[:-1]
res = res.strip()

# Output stream collects output to send to stdout and looks up metrics
stream = OutputStream()

'''
Note:  Responses are all single line.  Returns are added.

latencies response example:
"batch-index:;{test}-read:msec,10807.9,4.21,0.89,0.17,0.03,0.01,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00;
{test}-write:msec,10872.4,4.98,1.06,0.18,0.04,0.01,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00;{test}-udf:;
{test}-query:;{bar}-read:;{bar}-write:;{bar}-udf:;{bar}-query:"

latency response example:
"batch-index:;{test}-read:16:34:50-GMT,ops/sec,>1ms,>8ms,>64ms;16:35:00,0.0,0.00,0.00,0.00;
{test}-write:16:34:50-GMT,ops/sec,>1ms,>8ms,>64ms;16:35:00,0.0,0.00,0.00,0.00;{test}-udf:;
{test}-query:;{bar}-read:;{bar}-write:;{bar}-udf:;{bar}-query:"

set response example, similar to namespace, bins, sindex:
objects=100010:tombstones=0:memory_data_bytes=0:truncate_lut=0:stop-writes-count=0:disable-eviction=false;
'''
metric_found = False
if args.latency:
    res = res.split(';')
    metric_found = False
    table_data = res
    while table_data != []:
        labels = table_data.pop(0)
        # keep popping if there's a line with error
        if labels.startswith('error'):
            continue
        hist_name, data = labels.split(':', 1)
        # If looking for a single metric
        if args.stat:
            if hist_name == latency_histogram:
                metric_found = True
            else:
                continue
        if use_latencies_cmd:
            # Generate labels for latencies cmd
            data = data.split(',')
        else:
            # following line has data with "latency:" cmd
            data = table_data.pop(0).split(',')
        # Check to see if empty
        if len(data) <= 1:
            continue
        labels = ['tps']
        labels.extend(["pct_gt_" + ms for ms in latency_metrics[1:]])

        # Get rid of duration data (latency:) or units (latencies:)
        data.pop(0)
        latency_idx = 0
        latency_found = False
        while data:
            label = labels.pop(0)
            # If looking for a single metric
            if args.stat:
                if latency_time in label:
                    latency_found = True
                else:
                    latency_idx += 1
                    data.pop(0)
                    continue
            metricname = "%s_%s" % (hist_name, label)
            metricvalue = data.pop(0)
            stream.add(metricname, metricvalue)
            latency_idx += 1
            if latency_found:
                break
        if metric_found:
            break
else:
    if args.set:
        res = res.split(':')
    elif args.bin:
        res = res.split(',')
    else:
        res = res.split(';')
    for s in res:
        # bin/<namespace> returns bin names seperated by ',' at end
        if "=" not in s:
            continue
        metricname = re.split('=|\t',s)[-2]
        metricvalue = s.split("=")[-1]

        # indicates we are looking for a single metric
        if args.stat is not None:
            if args.stat != metricname:
                continue
            metric_found = True

        stream.add(metricname, metricvalue)
        if metric_found:
            break

stream.printStream()
sys.exit(STATE_OK)
