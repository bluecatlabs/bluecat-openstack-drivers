# BlueCat OpenStack Integration
The BlueCat OpenStack example integration consists of three Python-based components: 

- The BlueCat OpenStack Neutron driver patch, which documents OpenStack subnets,ports and compute instances as they are provisioned within BlueCat Address Manager™ (BAM)
- The BlueCat OpenStack Nova monitor, which sends OpenStack instance FQDNs (A,AAAA and PTRs) to a Bluecat DNS server (BDDS) dynamically, which then updates the DNS records within Bluecat Address Manager™ (BAM) added by the neutron driver
- The Bluecat Neutron monitor, which sends floating IP assignment updates (A,AAAA and PTRs) to Bluecat DNS server dynamically, which then updates the DNS records within Bluecat Address Manager™ (BAM) added by the OpenStack Nova Monitor



## Installation
All development has taken place against DevStack (upon Ubuntu 16.10), installation directly onto production OpenStack Neutron and Nova nodes should be tested and validated independently


#### On BlueCat Address Manager™ (BAM)

- Create a new Configuration for OpenStack updates, for example `OpenStack`.

- Create an API User, for example openstack in BlueCat and assign it full access rights to the new configuration.

- Ensure that the DNS domain used by OpenStack is defined within the BAM, for example `bluecat.lab`.

- Ensure there is a primary DNS server deployed for `bluecat.lab`.

- Create new UDFs for the OpenStack UUIDs:

		`Administration > Object Types > IPv4 Address  > New > User Defined Field`

		Display Name `UUID`, Field Name `UUID`, Type `Text`

		`Administration > Object Types > IPv4 Network  > New > User Defined Field`

		Display Name `UUID`, Field Name `UUID`, Type `Text`

		`Administration > Object Types > IPv6 Address  > New > User Defined Field`

		Display Name `UUID`, Field Name `UUID`, Type `Text`

		`Administration > Object Types > IPv6 Network  > New > User Defined Field` 

		Display Name `UUID`, Field Name `UUID`, Type `Text`

- Create IPv4 public and private blocks, for example `10.0.0.0/8 [OpenStack Public]` and `192.168.0.0/16 [OpenStack Private]`

Note :- OpenStack Subnets (Networks in BlueCat terminology) are dynamically created if not already present


#### Install the BlueCat Neutron Driver patch on DevStack

- Backup the existing requests.py file on the Neutron node in the /opt/neutron/neutron/ipam/ directory.

- Backup the existing driver.py file on the Neutron node in the /opt/neutron/neutron/ipam/drivers/neutrondb_ipam directory.

- Copy the new requests.py to the /opt/neutron/neutron/ipam/ directory.

- Copy the new driver.py to the /opt/neutron/neutron/ipam/drivers/neutrondb_ipam directory, taking care not to  overwrite /opt/stack/neuron/neutron/driver/driver.py. 


The `driver.py` has the following variables which must be set during installation within the python source:

	BAM_ADDRESS="192.168.1.100"

	BAM_API_USER="openstack"

	BAM_API_PASS="openstack"

	BAM_CONFIG_NAME="OpenStack"

	BAM_IPV4_PUBLIC_BLOCK="10.0.0.0/8"

	BAM_IPV4_PRIVATE_BLOCK="192.168.1.0/24"

	BAM_IPV4_PRIVATE_NETWORK="192.168.1.0/26"

	BAM_IPV4_PRIVATE_IPRANGE_STARTIP="192.168.1.2"

	BAM_IPV4_PRIVATE_IPRANGE_ENDIP="192.168.1.62"

	BAM_IPV4_PRIVATE_IPRANGE_GW="192.168.1.254"

	BAM_IPV6_PUBLIC_BLOCK="2000::/3"

	BAM_IPV6_PRIVATE_BLOCK="FC00::/6"

	BAM_DNS_ZONE="bluecat.lab"


#### Configuring the DevStack local.conf

Nova and Neutron must be configured to state changes and notifications, the transport_url should be configured to the local rabbitmq instance, if using devstack add the following additions to the local.conf

	[[post-config|$NOVA_CONF]]
	[DEFAULT]
	use_syslog = True
	notify_on_state_change=vm_state

	[[post-config|$NEUTRON_CONF]]
	[DEFAULT]
	notify_nova_on_port_status_changes = true
	notify_nova_on_port_data_changes = true
	control_exchange = neutron
	notification_topics = notifications
	transport_url = rabbit://stackrabbit:stackqueue@192.168.1.70:5672/
	notification_driver = messagingv2


#### Installing the Bluecat Nova Monitor

Copy the `bluecat_nova_monitor.py` to a suitable location (such as `/opt/stack/devstack/bluecat`)

	chmod +x bluecat_nova_monitor.py

	mv bluecat_nova_monitor.py bluecat_nova_monitor

Copy the `bluecat_nova_monitor.sh` to `/etc/init.d`

	mv bluecat_nova_monitor.sh bluecat_nova_monitor

	chmod +x /etc/init.d/bluecat_nova_monitor

	sudo vi /etc/init.d/bluecat_nova_monitor

Update the script parameters (APPDIR/APPARGS/USER/GROUP) to install locations and requirements, for example:

	APPDIR="/opt/stack/devstack/bluecat"
	APPARGS="--name 192.168.1.102 --ttl 999" 
	USER="stack"
	GROUP="stack"

Start the Bluecat Nova Monitor service

	sudo update-rc.d bluecat_nova_monitor defaults

	sudo service bluecat_nova_monitor start 



#### Installing the Bluecat Neutron Monitor

Copy the `bluecat_neutron_monitor.py` to a suitable location (such as `/opt/stack/devstack/bluecat`)

	chmod +x bluecat_neutron_monitor.py
	
	mv bluecat_neutron_monitor.py bluecat_neutron_monitor

Copy the `bluecat_neutron_monitor.sh` to `/etc/init.d`

	mv bluecat_neutron_monitor.sh bluecat_neutron_monitor

	chmod +x /etc/init.d/bluecat_neutron_monitor

	sudo vi /etc/init.d/bluecat_neutron_monitor

update the script parameters (APPDIR/APPARGS/USER/GROUP) to install locations and requirements, for example:

	APPDIR="/opt/stack/devstack/bluecat"
	APPARGS="--name 192.168.1.102 --ttl 999" 
	USER="stack"
	GROUP="stack"

Start the Bluecat Neutron Monitor service

	sudo update-rc.d bluecat_neutron_monitor defaults
	
	sudo service bluecat_neutron_monitor start 



## Usage

#### Bluecat Neutron Driver

Delivered as a patch to the native Neutron plugin IPAM driver, parameters are configured during installation

#### Bluecat Neutron Monitor

Listens to AMPQ message from Neutron to ascertain the correct DNS name for a Nova instance as a Floating IP is associated.

The service will then send an RFC2136 DDNS update to a target BlueCat DNS server

##### Service Control

`service bluecat_neutron_monitor start [stop|restart|status]`

##### Parameters

`-n | --nameserver` 

Set the target DNS server to be updated by DDNS (Defaults to 0.0.0.0)

`-l | --logfile`

Sets the logfile location and name (Default `/opt/stack/devstack/bluecat/bluecat_neutron.log`)

`-t | --ttl`

Sets the TTL of the records added to DNS (Default 1)

`-d | --domain`

Sets a domain name to append to the Nova instance name, if this parameter isn't passed the driver uses the instance as a FQDN

`-r | --replace` 
At default the neutron monitor will add floating IP records to the target DNS and not replace the private IP DNS records created 
by the Bluecat Nova Monitor, setting this option will replace the private IP DNS records replacing with the floating IP record


#### Bluecat Nova Monitor

Listens to AMPQ message from NOVA to ascertain the correct DNS name for a Nova instance as it starts

The service will then send an RFC2136 update to a target bluecat DNS server

##### Service Control

`service bluecat_nova_monitor start [stop|restart|status]`

##### Parameters

`-n | --nameserver`

Set the target DNS server to be updated by DDNS (Defaults to 0.0.0.0)

`-l | --logfile`

Sets the logfile location and name (Default `/opt/stack/devstack/bluecat/bluecat_nova.log`)

`-t | --ttl`

Sets the TTL of the records added to DNS (Default 1)

`-d | --domain`

Sets a domain name to append to the Nova instance name, if this parameter isn't passed the driver uses the instance as a FQDN

## Contributions
Contributing follows a review process: before a update is accepted it will be reviewed and then merged into the master branch.

1. Fork it!
2. Create your feature branch: git checkout -b my-new-feature
3. Commit your changes: git commit -am 'Add some feature'
4. Push to the branch: git push origin my-new-feature
5. Submit a pull request 

## Credits
The OpenStack example integration would not have been possible without the work of the following people. 
Thank you for contributing your time to making this project a success.

- David Horne
- Dmitri Dehterov
- Brian Shorland

## License

Copyright 2017 BlueCat Networks (USA) Inc. and its affiliates

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
