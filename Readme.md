#Introduction

aerospike_discovery.py simplifies Zabbix configurations for Aerospike clusters.
The goal is to reduce the complexity to 4 simple steps.

1. Install Zabbix
2. Configure Zabbix external scripts and drop aeorspike_discovery.py into
the external scripts directory
3. Import the configuration template into Zabbix
4. Add the new Aerospike Serivce Template to Aerospike Hosts in Zabbix.

The project is not there yet, there are extra steps not yet automated.

Features
---

- Can monitor any stat returned by
  - `$ asinfo -v 'statistics' [-h <HOST>]`
  - `$ asinfo -v 'namespace/<NAMESPACE NAME>' [-h host]`

### Known Issues

- Alerting is not part of the template
- Cluster based monitoring instead of host-based monitoring

### Getting Started

1. Enable [external scripts](https://www.zabbix.com/documentation/2.4/manual/config/items/itemtypes/external)
for Zabbix Server. You may have already done this for other Zabbix plugins 
2. Copy aerospike_discovery.py to the extenal scripts directory. 
3. Restart/Reload Zabbix 
4. In Configuration -> Templates section of Zabbix, click `Import` and choose aerospike_templates.xml. 
5. Add the newly imported `Template App Aerospike Service` to your Aerospike Hosts 


### Aerospike Zabbix Plugin

See *aerospike_discovery.py*, this is the file that Zabbix will schedule to perform
queries against Aerospike. Other than copying it to the appropriate location,
you are not required to interact with it.

###  Usage

    Usage:
     -h host (default 127.0.0.1)
     -p port (default 3000)
     -s "statistic" (Eg: "free-pct-memory")
     -n "namespace" (Eg: "namespace/test")

To monitor all general statistics:
`aerospike_discovery.py -h YOUR_ASD_HOST`

To monitor all statistics in a namespace:
`aerospike_discovery.py -h YOUR_ASD_HOST -n YOUR_NAMESPACE`

To monitor a specific general statistic:
`aerospike_discovery.py -h YOUR_ASD_HOST -s SERVICE_NAME`

To monitor a specific statistic in a namepsace:
`aerospike_discovery.py -h YOUR_ASD_HOST -s SERVICE_NAME -n YOUR_NAMESPACE`

