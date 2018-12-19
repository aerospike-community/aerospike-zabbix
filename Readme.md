# Introduction

aerospike\_discovery.py simplifies Zabbix configurations for Aerospike clusters.
The goal is to reduce the complexity to 3 simple steps.

1. Drop aerospike\_discovery.py and ssl\_context.py into the external scripts directory of Zabbix.
2. Import the configuration template into Zabbix.
3. Add the new Aerospike Serivce Template to Aerospike Hosts in Zabbix.

This project is currently in beta. Any suggestions or improvements are welcome through
Git comments/issues and/or pull requests.

Features
---

- Can monitor any stat returned by
  - `$ asinfo -v 'statistics' [-h <HOST>]`
  - `$ asinfo -v 'namespace/<NAMESPACE NAME>' [-h host]`
  - `$ asinfo -v 'dc/<DATACENTER NAME>' [-h host]`

### Known Issues

- Not all non-numeric metrics have been converted to numeric
- SELinux (CentOS) interferes with simple net checks built into Zabbix.
  * Get around this by setting SELinux to disabled or permissive in `/etc/selinux.config`

### Requirements

See requirements.txt

> sudo pip install -r requirements.txt

### Installing Zabbix

Many popular distributions have Zabbix packages provided. You can follow along with their [official install documentation](https://www.zabbix.com/documentation/2.4/manual/installation/install_from_packages) or use a third party guide like the one [written by Digital Ocean](https://www.digitalocean.com/community/tutorials/how-to-install-zabbix-on-ubuntu-configure-it-to-monitor-multiple-vps-servers).


### Getting Started

1. Enable [external scripts](https://www.zabbix.com/documentation/2.4/manual/config/items/itemtypes/external)
for Zabbix Server. You may have already done this for other Zabbix plugins 
2. Copy aerospike\_discovery.py to the extenal scripts directory and make it executable
  * ie: chmod +x aerospike\_discovery.py
3. Restart/Reload Zabbix 
4. In Configuration -> Templates section of Zabbix, click `Import` and choose aerospike\_templates.xml. 
5. Add the newly imported `Template App Aerospike Service` to your Aerospike Hosts 

### Namespace Checks

The default template contains namespace checks for the namespace `test`. To change
this to another namespace, go to Configuration -> Templates, and click on the Discovery section of
Template App Aerospike Service. Click on Aerospike Test Namespace Metric, and change `test` to the name of your namespace. For example, if your namespace was `fizzbuzz`:

    aerospike_discovery[-h,{HOST.IP},-n,fizzbuzz]

### Aerospike Zabbix Plugin

See *aerospike\_discovery.py*, this is the executable that Zabbix will schedule to perform
queries against Aerospike. Other than copying it to the appropriate location,
you are not required to interact with it.

### Alert Triggers

The main alert trigger is free memory/disk and if the namespace is in stop_writes. The free memory/disk 
trigger is set as a template macro `{$ASD_FREE_PCT_LIMIT}`.

To add more alerts via the LLD discovery mechanism, you will need to define a new Item prototype. This
item protoytype will need to duplicate the existing discovery key, with the added exception of a unique 
dummy variable. This is used since the same key cannot be used for multiple item prototype. You will also
need to add a macro filter to this item prototype to filter down the results to your interested metrics.

Next you will need to create a new trigger prototype using the item prototype that was just created.

You can still define individual alert triggers outside of the LLD mechanism.

###  Usage
```bash
usage: aerospike_discovery.py [-u] [-U USER] [-P [PASSWORD]] [-v]
                              [-n NAMESPACE | -l LATENCY | -x DC] [-s STAT]
                              [-p PORT] [-h HOST] [-d DUMMY] [--tls_enable]
                              [--tls_encrypt_only] [--tls_keyfile TLS_KEYFILE]
                              [--tls_certfile TLS_CERTFILE]
                              [--tls_cafile TLS_CAFILE]
                              [--tls_capath TLS_CAPATH]
                              [--tls_protocols TLS_PROTOCOLS]
                              [--tls_blacklist TLS_BLACKLIST]
                              [--tls_ciphers TLS_CIPHERS] [--tls_crl]
                              [--tls_crlall] [--tls_name TLS_NAME]

optional arguments:
  -u, --usage, --help   Show this help message and exit
  -U USER, --user USER  user name
  -P [PASSWORD], --password [PASSWORD]
                        password
  -v, --verbose         Enable verbose logging
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace name. eg: bar
  -l LATENCY, --latency LATENCY
                        Options: see output of asinfo -v 'latency:hist' -l
  -x DC, --xdr DC       Datacenter name. eg: myDC1
  -s STAT, --stat STAT  Statistic name. eg: cluster_size
  -p PORT, ---port PORT
                        PORT for Aerospike server (default: 3000)
  -h HOST, --host HOST  HOST for Aerospike server (default: 127.0.0.1)
  -d DUMMY              Dummy variable for templating
  --tls_enable          Enable TLS
  --tls_encrypt_only    TLS Encrypt Only
  --tls_keyfile TLS_KEYFILE
                        The private keyfile for your client TLS Cert
  --tls_certfile TLS_CERTFILE
                        The client TLS cert
  --tls_cafile TLS_CAFILE
                        The CA for the server's certificate
  --tls_capath TLS_CAPATH
                        The path to a directory containing CA certs and/or
                        CRLs
  --tls_protocols TLS_PROTOCOLS
                        The TLS protocol to use. Available choices: SSLv2,
                        SSLv3, TLSv1, TLSv1.1, TLSv1.2, all. An optional + or
                        - can be appended before the protocol to indicate
                        specific inclusion or exclusion.
  --tls_blacklist TLS_BLACKLIST
                        Blacklist including serial number of certs to revoke
  --tls_ciphers TLS_CIPHERS
                        Ciphers to include. See https://www.openssl.org/docs/m
                        an1.0.1/apps/ciphers.html for cipher list format
  --tls_crl             Checks SSL/TLS certs against vendor's Certificate
                        Revocation Lists for revoked certificates. CRLs are
                        found in path specified by --tls_capath. Checks the
                        leaf certificates only
  --tls_crlall          Check on all entries within the CRL chain
  --tls_name TLS_NAME   The expected name on the server side certificate

```
The `dummy` variable is just there so Alert Triggers can be set in batches based on item prototypes. 
However the item prototype needs to have unique keys (read: unique external script calls) so the
dummy variable is there to satisfy this uniqueness.

To monitor all general statistics:
`aerospike_discovery.py -h YOUR_ASD_HOST`

To monitor all statistics in a namespace:
`aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE`

To monitor a specific general statistic:
`aerospike_discovery.py -h YOUR_ASD_HOST -s SERVICE_NAME`

To monitor a specific statistic in a namespace:
`aerospike_discovery.py -h YOUR_ASD_HOST -s SERVICE_NAME -n YOUR_NAMESPACE`

To monitor all XDR statistics for a datacenter:
`aerospike_discvoery.py -h YOUR_ASD_HOST -x DATACENTER`

