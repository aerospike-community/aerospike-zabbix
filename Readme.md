#Introduction

aerospike\_discovery.py simplifies Zabbix configurations for Aerospike clusters.
The goal is to reduce the complexity to 3 simple steps.

1. Drop aerospike\_discovery.py into the external scripts directory of Zabbix.
2. Import the configuration template into Zabbix.
3. Add the new Aerospike Serivce Template to Aerospike Hosts in Zabbix.

The project is not there yet, there are extra steps not yet automated.

Features
---

- Can monitor any stat returned by
  - `$ asinfo -v 'statistics' [-h <HOST>]`
  - `$ asinfo -v 'namespace/<NAMESPACE NAME>' [-h host]`
  - `$ asinfo -v 'dc/<DATACENTER NAME>' [-h host]`

### Known Issues

- Alerting is not part of the template
- Host based monitoring instead of cluster based monitoring
- Not all non-numeric metrics have been converted to numeric

### Getting Started

1. Enable [external scripts](https://www.zabbix.com/documentation/2.4/manual/config/items/itemtypes/external)
for Zabbix Server. You may have already done this for other Zabbix plugins 
2. Copy aerospike\_discovery.py to the extenal scripts directory. 
3. Restart/Reload Zabbix 
4. In Configuration -> Templates section of Zabbix, click `Import` and choose aerospike\_templates.xml. 
5. Add the newly imported `Template App Aerospike Service` to your Aerospike Hosts 

### Namespace Checks

The default template contains namespace checks for the namespace `test`. To change
this to another namespace, go to Configuration -> Templates, and click on the Discovery section of
Template App Aerospike Service. Click on Aerospike Test Namespace Metric, and change the key to

    aerospike_discovery[-h,{HOST.IP},-n,YOUR\_NAMESPACE]

You may also want to rename this Discovery Rule.

### XDR Checks

XDR datacenter metrics are avaialble by changing the Template App key to:

    aerospike_discovery[-h,{HOST.IP},-x,YOUR_DATACENTER_NAME]

The process is the same as namespace checks above.

### Aerospike Zabbix Plugin

See *aerospike\_discovery.py*, this is the file that Zabbix will schedule to perform
queries against Aerospike. Other than copying it to the appropriate location,
you are not required to interact with it.

###  Usage

    Usage:
     -h host (default 127.0.0.1)
     -p port (default 3000)
     -U user (Enterprise only)
     -P password (Enterprise only)
     -x xdr datacenter (Enterprise 3.7.4+)
     -s "statistic" (Eg: "free-pct-memory")
     -n "namespace" (Eg: "namespace/test")

To monitor all general statistics:
`aerospike_discovery.py -h YOUR_ASD_HOST`

To monitor all statistics in a namespace:
`aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE`

To monitor a specific general statistic:
`aerospike_discovery.py -h YOUR_ASD_HOST -s SERVICE_NAME`

To monitor a specific statistic in a namespace:
`aerospike_discovery.py -h YOUR_ASD_HOST -s SERVICE_NAME -n YOUR_NAMESPACE`

