#!/usr/bin/python
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#

# Copyright 2013-2017 Aerospike, Inc.
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
__copyright__ = "Copyright 2016 Aerospike"
__version__ = "1.2.0"

import sys
import types
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
arg_value = "statistics"
arg_stat = None
user = None
password = None

# =============================================================================
#
# Client
#
# -----------------------------------------------------------------------------

STRUCT_PROTO = struct.Struct('! Q')
STRUCT_AUTH = struct.Struct('! xxBB12x')
STRUCT_FIELD = struct.Struct('! IB')

MSG_VERSION = 0
MSG_TYPE = 2
AUTHENTICATE = 0
USER = 0
CREDENTIAL = 3
SALT = "$2a$10$7EqJtq98hPqEX7fNZaFWoO"

class ClientError(Exception):
        pass

class Client(object):

        def __init__(self, addr, port, timeout=0.7):
                self.addr = addr
                self.port = port
                self.timeout = timeout
                self.sock = None

        def connect(self, keyfile=None, certfile=None, ca_certs=None, ciphers=None, tls_enable=False, encrypt_only=False,
                capath=None, protocols=None, cert_blacklist=None, crl_check=False, crl_check_all=False, tls_name=None):
                s = None
                for res in socket.getaddrinfo(self.addr, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                        af, socktype, proto, canonname, sa = res
                        ssl_context = None
                        try:
                                s = socket.socket(af, socktype, proto)
                        except socket.error as msg:
                                s = None
                                continue
                        if tls_enable:
                                from ssl_context import SSLContext
                                from OpenSSL import SSL
                                ssl_context = SSLContext(enable_tls=tls_enable, encrypt_only=encrypt_only, cafile=ca_certs, capath=capath,
                                           keyfile=keyfile, certfile=certfile, protocols=protocols,
                                           cipher_suite=ciphers, cert_blacklist=cert_blacklist,
                                           crl_check=crl_check, crl_check_all=crl_check_all).ctx
                                s = SSL.Connection(ssl_context,s)
                        try:
                                s.connect(sa)
                                if ssl_context:
                                        s.set_app_data(tls_name)
                                        s.do_handshake()
                        except socket.error as msg:
                                s.close()
                                s = None
                                print "Connect Error" % msg
                                continue
                        break

                if s is None:
                        raise ClientError(
                                "Could not connect to server at %s %s" % (self.addr, self.port))

                self.sock = s
                return self

        def close(self):
                if self.sock is not None:
                        self.sock.settimeout(None)
                        self.sock.close()
                        self.sock = None

        def auth(self, username, password, timeout=None):

                import bcrypt

                if password == None:
                        password = ''
                credential = bcrypt.hashpw(password, SALT)

                if timeout is None:
                        timeout = self.timeout

                l = 8 + 16
                l += 4 + 1 + len(username)
                l += 4 + 1 + len(credential)

                buf = create_string_buffer(l)
                offset = 0

                proto = (MSG_VERSION << 56) | (MSG_TYPE << 48) | (l - 8)
                STRUCT_PROTO.pack_into(buf, offset, proto)
                offset += STRUCT_PROTO.size

                STRUCT_AUTH.pack_into(buf, offset, AUTHENTICATE, 2)
                offset += STRUCT_AUTH.size

                STRUCT_FIELD.pack_into(buf, offset, len(username) + 1, USER)
                offset += STRUCT_FIELD.size
                fmt = "! %ds" % len(username)
                struct.pack_into(fmt, buf, offset, username)
                offset += len(username)

                STRUCT_FIELD.pack_into(buf, offset, len(credential) + 1, CREDENTIAL)
                offset += STRUCT_FIELD.size
                fmt = "! %ds" % len(credential)
                struct.pack_into(fmt, buf, offset, credential)
                offset += len(credential)

                self.send(buf)

                buf = self.recv(8, timeout)
                rv = STRUCT_PROTO.unpack(buf)
                proto = rv[0]
                pvers = (proto >> 56) & 0xFF
                ptype = (proto >> 48) & 0xFF
                psize = (proto & 0xFFFFFFFFFFFF)

                buf = self.recv(psize, timeout)
                status = ord(buf[1])

                if status != 0:
                        raise ClientError("Autentication Error %d for '%s' " %
                                                          (status, username))

        def send(self, data):
                if self.sock:
                        try:
                                r = self.sock.sendall(data)
                        except IOError as e:
                                raise ClientError(e)
                        except socket.error as e:
                                raise ClientError(e)
                else:
                        raise ClientError('socket not available')

        def send_request(self, request, pvers=2, ptype=1):
                if request:
                        request += '\n'
                sz = len(request) + 8
                buf = create_string_buffer(len(request) + 8)
                offset = 0

                proto = (pvers << 56) | (ptype << 48) | len(request)
                STRUCT_PROTO.pack_into(buf, offset, proto)
                offset = STRUCT_PROTO.size

                fmt = "! %ds" % len(request)
                struct.pack_into(fmt, buf, offset, request)
                offset = offset + len(request)

                self.send(buf)

        def recv(self, sz, timeout):
                out = ""
                pos = 0
                start_time = time.time()
                while pos < sz:
                        buf = None
                        try:
                                buf = self.sock.recv(sz)
                        except IOError as e:
                                raise ClientError(e)
                        if pos == 0:
                                out = buf
                        else:
                                out += buf
                        pos += len(buf)
                        if timeout and time.time() - start_time > timeout:
                                raise ClientError(socket.timeout())
                return out

        def recv_response(self, timeout=None):
                buf = self.recv(8, timeout)
                rv = STRUCT_PROTO.unpack(buf)
                proto = rv[0]
                pvers = (proto >> 56) & 0xFF
                ptype = (proto >> 48) & 0xFF
                psize = (proto & 0xFFFFFFFFFFFF)

                if psize > 0:
                        return self.recv(psize, timeout)
                return ""

        def info(self, request):
                self.send_request(request)
                res = self.recv_response(timeout=self.timeout)
                out = re.split("\s+", res, maxsplit=1)
                if len(out) == 2:
                        return out[1]
                else:
                        raise ClientError("Failed to parse response: %s" % (res))

###
# Argument parsing
###
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
                    , help="Options: see output of asinfo -v 'latency:hist' -l")
group.add_argument("-x"
                    , "--xdr"
                    , dest="dc"
                    , help="Datacenter name. eg: myDC1")
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
parser.add_argument("--tls_enable"
                    , action="store_true"
                    , dest="tls_enable"
                    , help="Enable TLS")
parser.add_argument("--tls_encrypt_only"
                    , action="store_true"
                    , dest="tls_encrypt_only"
                    , help="TLS Encrypt Only")
parser.add_argument("--tls_keyfile"
                    , dest="tls_keyfile"
                    , help="The private keyfile for your client TLS Cert")
parser.add_argument("--tls_certfile"
                    , dest="tls_certfile"
                    , help="The client TLS cert")
parser.add_argument("--tls_cafile"
                    , dest="tls_cafile"
                    , help="The CA for the server's certificate")
parser.add_argument("--tls_capath"
                    , dest="tls_capath"
                    , help="The path to a directory containing CA certs and/or CRLs")
parser.add_argument("--tls_protocols"
                    , dest="tls_protocols"
                    , help="The TLS protocol to use. Available choices: SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2, all. An optional + or - can be appended before the protocol to indicate specific inclusion or exclusion.")
parser.add_argument("--tls_blacklist"
                    , dest="tls_blacklist"
                    , help="Blacklist including serial number of certs to revoke")
parser.add_argument("--tls_ciphers"
                    , dest="tls_ciphers"
                    , help="Ciphers to include. See https://www.openssl.org/docs/man1.0.1/apps/ciphers.html for cipher list format")
parser.add_argument("--tls_crl"
                    , dest="tls_crl"
                    , action="store_true"
                    , help="Checks SSL/TLS certs against vendor's Certificate Revocation Lists for revoked certificates. CRLs are found in path specified by --tls_capath. Checks the leaf certificates only")
parser.add_argument("--tls_crlall"
                    , dest="tls_crlall"
                    , action="store_true"
                    , help="Check on all entries within the CRL chain")
parser.add_argument("--tls_name"
                    , dest="tls_name"
                    , help="The expected name on the server side certificate")

args = parser.parse_args()

if args.dc:
  arg_value='dc/'+args.dc
elif args.namespace:
  arg_value='namespace/'+args.namespace
elif args.latency:
  arg_value='latency:hist='+args.latency

user = None
password = None

if args.user != None:
    user = args.user
    if args.password == "prompt":
        args.password = getpass.getpass("Enter Password:")
    password = args.password



####
#def usage():
#    print "Usage:"
#    print " -h host (default 127.0.0.1)"
#    print " -p port (default 3000)"
#    print " -U user"
#    print " -P password"
#    print " -s \"statistic\" (Eg: \"free-pct-memory\")"
#    print " -n \"namespace\" (Eg: \"namespace/test\")"
#    print " -x \"xdr\" (Eg: \"datacenter1\")"
#    print " -d \"dummy\""
#    return
####
#
####
### Process passed in arguments
#try:
#    opts, args = getopt.getopt(sys.argv[1:], "h:p:s:n:x:U:P:d", ["host=","port=","statistics=","namespace=","xdr=","User=","Password=","dummy="])
#
### If we don't get in options passed print usage.
#except getopt.GetoptError, err:
#    print str(err)
#    usage()
#    sys.exit(-1)
#
#for o, a in opts:
#    if (o == "-h" or o == "--host"):
#        arg_host = a
#    if (o == "-p" or o == "--port"):
#        arg_port = int(a)
#    if (o == "-s" or o == "--statistics"):
#        arg_stat = a
#    if (o == "-n" or o == "--namespace"):
#        arg_value = "namespace/" + a
#    if (o == "-x" or o == "--xdr"):
#        arg_value = "dc/" + a
#    if (o == "-U" or o == "--User"):
#        user = a
#    if (o == "-p" or o == "--Password"):
#        password = a
#
#if user != None:
#    if password == None:
#        password = getpass.getpass("Enter Password:")
#
#

#
# MAINLINE
#

#config = {
#        'hosts' : [ ( arg_host, arg_port ) ]
#}
try:
    #client = aerospike.client(config).connect(user,password)
    client = Client(addr=args.host,port=args.port)
    client.connect(keyfile=args.tls_keyfile, certfile=args.tls_certfile, ca_certs=args.tls_cafile, ciphers=args.tls_ciphers, tls_enable=args.tls_enable,
                   encrypt_only=args.tls_encrypt_only, capath=args.tls_capath, protocols=args.tls_protocols, cert_blacklist=args.tls_blacklist,
                   crl_check=args.tls_crl,crl_check_all=args.tls_crlall, tls_name=args.tls_name)
except Exception as e:
    print("Failed to connect to the Aerospike cluster at %s:%s"%(args.host,args.port))
    print e
    sys.exit(STATE_UNKNOWN)

if user:
    client.auth(user,password)

#r = client.info_node(arg_value,(arg_host,arg_port))
r = client.info(arg_value)
client.close()

#pprint.pprint(r)

if args.stat != None and args.stat not in r:
    print "%s is not a known statistic." %args.stat
    sys.exit(STATE_UNKNOWN)

if r == -1:
    print "request to ",args.host,":",args.port," returned error."
    sys.exit(STATE_CRITICAL)
    
if r == None:
    print "request to ",args.host,":",args.port," returned no data."
    sys.exit(STATE_CRITICAL)

print "{"
print "\t\"data\":["
first = True
r = r.strip()
for s in r.split(";"):
    metricname=re.split('=|\t',s)[-2]
    metricvalue=s.split("=")[-1]
    if args.stat != None:
        if args.stat != metricname:
            continue
    if not first:
        print "\t,"
    first = False
    if metricvalue == "true" or metricvalue == "on":
        metricvalue = "1"
    elif metricvalue == "false" or metricvalue == "off":
        metricvalue = "0"
    if metricname == "cluster_key":
        metricvalue = str(int(metricvalue,16)) # Convert HEX id to numerical
    print "\t{"
    print "\t\t\"{#METRICNAME}\":\""+metricname+"\","
    print "\t\t\"{#METRICVALUE}\":\""+metricvalue+"\""
    print "\t}"

print "\t]"
print "}"
sys.exit(STATE_OK)
