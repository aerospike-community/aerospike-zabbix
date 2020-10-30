# Introduction

`aerospike_discovery.py` simplifies [Zabbix](https://www.zabbix.com/) monitoring of Aerospike clusters.

The Zabbix plug-in is compatible with Aerospike database 4.x and Aerospike database 5, last tested with database server versions 4.9.9 and 5.1.0.

## Aerospike Monitoring Stack
For monitoring and alerting you should consider using the Prometheus and Grafana based [Aerospike Monitoring Stack](https://github.com/aerospike/aerospike-monitoring). This is the monitoring solution being developed by Aerospike.

## Community Development

This repository has been turned over to the community. If you wish to contribute code, go ahead and clone this repo, modify the code, and create a pull request.

Active contributors can then ask to become maintainers for the repo. The wiki can similarly be modified by any code contributor who has been granted pull permissions.

### Features

- Can monitor any metric returned by
  - `$ asinfo -v 'statistics' [-h <HOST>]`
  - `$ asinfo -v 'namespace/<NAMESPACE_NAME>' [-h host]`
  - `$ asinfo -v 'dc/<DC_NAME>' [-h host]` pre 5.0
  - `$ asinfo -v 'get-stats:context=xdr;dc=<DC_NAME>' [-h host]` 5.0+
  - `$ asinfo -v 'latency:' [-h host]` pre 5.1
  - `$ asinfo -v 'latencies:' [-h host]` 5.1+
  - `$ asinfo -v 'sets/<NAMESPACE_NAME>/<SET_NAME>' [-h host]`
  - `$ asinfo -v 'sindex/<NAMESPACE_NAME>/<SINDEX_NAME>' [-h host]`
  - `$ asinfo -v 'bins/<NAMESPACE_NAME>' [-h host]`

### Known Issues

- Metrics that return values other than numerics, `true/false`, `on/off` are not handled
with the exception of dc_state (pre 5.0).  All values returned are numeric. 
- The example template shows some errors in the zabbix UI caused by returned configuration 
paramaters which are not converted to numeric.
- SELinux (CentOS) interferes with simple net checks built into Zabbix.
  * Get around this by setting SELinux to disabled or permissive in `/etc/selinux.config`

### Requirements

Additional python modules are required and installed using pip:
```
sudo pip install -r requirements.txt
```

See requirements.txt.

### Installing Zabbix

Many popular distributions have Zabbix packages provided. You can follow along with their [official install documentation](https://www.zabbix.com/documentation/4.4/manual/installation/install_from_packages) or use a third party guide like the one [written by Digital Ocean](https://www.digitalocean.com/community/tutorials/how-to-install-zabbix-on-ubuntu-configure-it-to-monitor-multiple-vps-servers).

Note: Zabbix 4.4+ needed. Older versions may not be able to import aerospike template.


### Getting Started

1. Enable [external scripts](https://www.zabbix.com/documentation/4.4/manual/config/items/itemtypes/external)
for Zabbix Server. You may have already done this for other Zabbix plugins. Default: /usr/lib/zabbix/externalscripts
2. Copy aerospike\_discovery.py to the external scripts directory and make it executable
  * ie: chmod +x aerospike\_discovery.py
3. Copy ssl folder to same external scripts directory.
4. Restart/Reload Zabbix.
5. In Configuration -> Templates section of Zabbix, click `Import` and choose aerospike\_templates.xml.
6. Add the newly imported `Template App Aerospike Service` to your Aerospike Hosts.

### Default Checks

The default template contains checks for testing and requires modification to monitor your aerospike configuration. 
To modify the default template goto Configuration -> Templates, and click on the Discovery section of
Template App Aerospike Service. Click on any of the Discovery Rules and change the key so that the arguments to
`aerospike_discovery.py` match your current namespaces, sets, datacenters, etc.  For instance to monitor all metrics
for the namespace `fizzbuzz` change the Aerospike Namespace discovery rule key to:

    aerospike_discovery[-h,{HOST.IP},-n,fizzbuzz]

### Aerospike Zabbix Plugin

See *aerospike\_discovery.py*, this is the executable that Zabbix will schedule to perform
queries against Aerospike. Other than copying it to the appropriate location,
you are not required to interact with it.

### Alert Triggers

The default template has 5 example triggers: free memory/disk, stop_writes, cluster_size, dc_state (pre 5.0)
and latency_ms (5.0+). The free memory/disk trigger uses a template macro `{$ASD_FREE_PCT_LIMIT}` to determine 
when to trigger while the others use static values. Each trigger should be modified to fit your particular 
aerospike configuration.

To add more alerts via the LLD discovery mechanism, you will need to define a new Discovery Rule. This
discovery rule will need to duplicate the existing discovery key, with the added exception of a unique 
dummy variable. This is used since the same key cannot be used for multiple discovery rules or item prototype. You will also
need to add a macro filter to this discovery rule to filter down the results to your interested metrics.

Next create a new item prototype which is a duplicate of the existing item prototype, with the added exception
of a different key.  You can change the name as well if your prefer.

Next you will need to create a new trigger prototype using the item prototype that was just created.

You can still define individual alert triggers outside of the LLD mechanism.

###  Usage
```bash
./aerospike_discovery.py --help
usage: aerospike_discovery.py [-u] [-U USER] [-P [PASSWORD]]
                              [--credentials-file CREDENTIALS]
                              [--auth-mode AUTH_MODE] [-v]
                              [-n NAMESPACE | -l | -x DC]
                              [-t SET | -b | -i SINDEX] [-s STAT] [-p PORT]
                              [-h HOST] [-d DUMMY] [--timeout TIMEOUT]
                              [--tls-enable] [--tls-name TLS_NAME]
                              [--tls-keyfile TLS_KEYFILE]
                              [--tls-keyfile-pw TLS_KEYFILE_PW]
                              [--tls-certfile TLS_CERTFILE]
                              [--tls-cafile TLS_CAFILE]
                              [--tls-capath TLS_CAPATH]
                              [--tls-ciphers TLS_CIPHERS]
                              [--tls-protocols TLS_PROTOCOLS]
                              [--tls-cert-blacklist TLS_CERT_BLACKLIST]
                              [--tls-crl-check] [--tls-crl-check-all]

optional arguments:
  -u, --usage, --help   Show this help message and exit
  -U USER, --user USER  user name
  -P [PASSWORD], --password [PASSWORD]
                        password
  --credentials-file CREDENTIALS
                        Path to the credentials file. Use this in place of
                        --user and --password.
  --auth-mode AUTH_MODE
                        Authentication mode. Values: ['EXTERNAL_INSECURE',
                        'INTERNAL', 'EXTERNAL'] (default: INTERNAL)
  -v, --verbose         Enable verbose logging
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace name. eg: bar
  -l, --latency         Options: see output of asinfo -v 'latency:hist' -l
  -x DC, --xdr DC       Datacenter name. eg: myDC1
  -t SET, --set SET     Set name. eg: testSet. Statistic for a particular set
                        in a particular namespace.
  -b, --bin             Bin usage information for a particular namspace.
  -i SINDEX, --sindex SINDEX
                        Secondary Index name. eg: age. Statistic for a
                        particular secondary index in a particular namespace.
  -s STAT, --stat STAT  Statistic name. eg: cluster_size
  -p PORT, ---port PORT
                        PORT for Aerospike server (default: 3000)
  -h HOST, --host HOST  HOST for Aerospike server (default: 127.0.0.1)
  -d DUMMY              Dummy variable for templating
  --timeout TIMEOUT     Set timeout value in seconds to node level operations.
                        TLS connection does not support timeout. (default: 5)
  --tls-enable          Enable TLS
  --tls-name TLS_NAME   The expected name on the server side certificate
  --tls-keyfile TLS_KEYFILE
                        The private keyfile for your client TLS Cert
  --tls-keyfile-pw TLS_KEYFILE_PW
                        Password to load protected tls-keyfile
  --tls-certfile TLS_CERTFILE
                        The client TLS cert
  --tls-cafile TLS_CAFILE
                        The CA for the server's certificate
  --tls-capath TLS_CAPATH
                        The path to a directory containing CA certs and/or
                        CRLs
  --tls-ciphers TLS_CIPHERS
                        Ciphers to include. See https://www.openssl.org/docs/m
                        an1.1.0/man1/ciphers.html for cipher list format
  --tls-protocols TLS_PROTOCOLS
                        The TLS protocol to use. Available choices: TLSv1,
                        TLSv1.1, TLSv1.2, all. An optional + or - can be
                        appended before the protocol to indicate specific
                        inclusion or exclusion.
  --tls-cert-blacklist TLS_CERT_BLACKLIST
                        Blacklist including serial number of certs to revoke
  --tls-crl-check       Checks SSL/TLS certs against vendor's Certificate
                        Revocation Lists for revoked certificates. CRLs are
                        found in path specified by --tls-capath. Checks the
                        leaf certificates only
  --tls-crl-check-all   Check on all entries within the CRL chain


```
The `dummy` variable is just there so Alert Triggers can be set in batches based on item prototypes. 
However the item prototype needs to have unique keys (read: unique external script calls) so the
dummy variable is there to satisfy this uniqueness.

### Examples
To monitor all general metrics:
```
aerospike_discovery.py -h YOUR_ASD_HOST
```

To monitor a specific general metric:
```
aerospike_discovery.py -h YOUR_ASD_HOST -s YOUR_METRIC_NAME 
```

To monitor all latency metrics:
```
aerospike_discovery.py -h YOUR_ASD_HOST -l
```

To monitor a specific latency metric:
```
aerospike_discovery.py -h YOUR_ASD_HOST -l -s YOUR_HISTOGRAM
```
  - For instance, to monitor latencies greater than 8ms for histogram {test}-write:
  ```
  aerospike_discovery.py -h 127.0.0.1 -l -s {test}-write-8ms
  ```

To monitor all metrics in a namespace:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE
```

To monitor a specific metric in a namespace:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -s YOUR_METRIC_NAME 
```

To monitor all metrics in a set:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -t YOUR_SET_NAME
```

To monitor a specific metric in a set:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -t YOUR_SET_NAME -s YOUR_METRIC_NAME
```

To monitor all bin metrics in a namespace:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -b
```

To monitor a specific bin metrics in a namespace:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -b -s YOUR_METRIC_NAME
```

To monitor all sIndex metrics for a sIndex in a namespace:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -i YOUR_SINDEX
```

To monitor a specific sIndex metric for a sIndex in a namespace:
```
aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE -i YOUR_SINDEX -s YOUR_METRIC_NAME
```

To monitor all XDR metrics for a datacenter:
```
aerospike_discovery.py -h YOUR_ASD_HOST -x YOUR_DATACENTER
```

To monitor a specific XDR metric for a datacenter:
```
aerospike_discovery.py -h YOUR_ASD_HOST -x YOUR_DATACENTER -s METRIC_NAME 
```

### Authentication

You can specify User and Password for authentication via the -U/--user and -P/--password parameters.
The Password is also an interactive prompt if you leave it empty.
                        
If this is not preferable, you can also specify a credentials file with -c/--credentials-file. 
It is a simple 2 line file, with the username and password on each line, in that order. 
With this method, the credentials file can be secured via other means (eg: chmod 600) and prevent snooping.

`AuthMode` is optional parameter to specify authentication mode. It's default value is INTERNAL.
