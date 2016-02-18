#!/usr/bin/python
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#
#

import sys
import types
import getopt
import re
import aerospike
#import pprint


STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4

arg_host = "127.0.0.1"
arg_port = 3000
arg_value = "statistics"
arg_stat = None


###
def usage():
    print "Usage:"
    print " -h host (default 127.0.0.1)"
    print " -p port (default 3000)"
    print " -s \"statistic\" (Eg: \"free-pct-memory\")"
    print " -n \"namespace\" (Eg: \"namespace/test\")"
    return
###

###
## Process passed in arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], "h:p:s:n::c:w:", ["host=","port=","statistics=","namespace"])

## If we don't get in options passed print usage.
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(-1)

for o, a in opts:
    if (o == "-h" or o == "--host"):
        arg_host = a
    if (o == "-p" or o == "--port"):
        arg_port = int(a)
    if (o == "-s" or o == "--statistics"):
        arg_stat = a
    if (o == "-n" or o == "--namespace"):
        arg_value = "namespace/" + a

#
# MAINLINE
#

config = {
        'hosts' : [ ( arg_host, arg_port ) ]
}
client = aerospike.client(config).connect()
r = client.info_node(arg_value,(arg_host,arg_port))
client.close()

#pprint.pprint(r)

if arg_stat != None and arg_stat not in r:
    print "%s is not a known statistic." %arg_stat
    sys.exit(STATE_UNKNOWN)

if r == -1:
    print "request to ",arg_host,":",arg_port," returned error."
    sys.exit(STATE_CRITICAL)
    
if r == None:
    print "request to ",arg_host,":",arg_port," returned no data."
    sys.exit(STATE_CRITICAL)

print "{"
print "\t\"data\":["
first = True
r = r.strip()
for s in r.split(";"):
    metricname=re.split('=|\t',s)[-2]
    metricvalue=s.split("=")[-1]
    if arg_stat != None:
        if arg_stat != metricname:
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
