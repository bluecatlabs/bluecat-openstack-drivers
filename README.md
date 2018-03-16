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

- Backup the existing requests.py file on the Neutron node in the /opt/stack/neutron/neutron/ipam/ directory.

- Backup the existing driver.py file on the Neutron node in the /opt/stack/neutron/neutron/ipam/drivers/neutrondb_ipam directory.

- Copy the new requests.py to the /opt/stack/neutron/neutron/ipam/ directory.

- Copy the new driver.py to the /opt/stack/neutron/neutron/ipam/drivers/neutrondb_ipam directory, taking care not to  overwrite /opt/stack/neutron/neutron/driver/driver.py.

- Copy the new driver.ini to the /opt/neutron/neutron/ipam/drivers/neutrondb_ipam directory.


#### Configure The BlueCat OpenStack driver

##### For version V0.13 and above

Edit 'driver.ini' as required for your environment:

	[BAM]
	bam_address=192.168.1.100
	bam_api_user=openstack
	bam_api_pass=openstack
	bam_config_name=OpenStack
	bam_ipv4_public_block=10.0.0.0/8
	bam_ipv4_private_block=192.168.1.0/24
	bam_ipv4_private_network=192.168.1.0/26
	bam_ipv4_private_iprange_startip=192.168.1.2
	bam_ipv4_private_iprange_endip=192.168.1.62
	bam_ipv4_private_iprange_gw=192.168.1.254
	bam_ipv6_public_block=2000::/3
	bam_ipv6_private_block=FC00::/6
	bam_dns_zone=bluecat.lab
	bam_updatemodify_networks=True



##### For versions up to V0.12

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
	transport_url = rabbit://stackrabbit:bluecat@192.168.1.70:5672/
	notification_driver = messagingv2


#### Installing the Bluecat Nova Monitor

Copy the `bluecat_nova_monitor.py` to a suitable location (such as `/opt/bluecat`)

#### Configure the bluecat.conf in the local directory for your environment:

	[bluecat_nova_monitor]
	broker_uri=amqp://stackrabbit:bluecat@localhost:5672//
	nameserver=192.168.1.102
	logfile=/opt/bluecat/Bluecat Nova Monitor/bluecat_nova.log
	ttl=666
	domain_override=False
	debuglevel=DEBUG

#### Installing the Bluecat Neutron Monitor

Copy the `bluecat_neutron_monitor.py` to a suitable location (such as `/opt/bluecat`)

#### Configure the bluecat.conf in the local directory for your environment:

	[bluecat_neutron_monitor]
	broker_uri=amqp://stackrabbit:bluecat@localhost:5672//
	nameserver=192.168.1.102
	logfile=/opt/bluecat/Bluecat Neutron Monitor/bluecat_neutron.log
	ttl=666
	domain_override=False
	replace=False
	debuglevel=DEBUG

#### Usage

#### Bluecat Neutron Monitor

Listens to AMPQ message from Neutron to ascertain the correct DNS name for a Nova instance as a Floating IP is associated.
The service will then send an RFC2136 DDNS update to a target BlueCat DNS server

#### bluecat.conf [bluecat_neutron_monitor] section settings

Set parameters for the BlueCat Neutron Monitor
	
	`broker_uri=amqp://stackrabbit:bluecat@localhost:5672//`

Sets the AMQ broker URI, used to read rabbitMQ messages

	`nameserver=192.168.1.102`

Sets the target DNS server to be updated by DDNS

	`logfile=/opt/bluecat/Bluecat Neutron Monitor/bluecat_neutron.log`

Sets the logfile location and name 

	`ttl=666`

Sets the TTL of the records added to DNS 

	`domain_override=False`

Sets a domain name to append to the instance name, if this parameter is set to False the monitor will utilise the whole instances name as a fully qualified domain name

	`replace=False`

At default the neutron monitor will add floating IP records to the target DNS and not replace the private IP DNS records created by the Bluecat Nova Monitor. Setting this option to True will replace the private IP DNS records replacing with the floating IP record.


#### Bluecat Nova Monitor

Listens to AMPQ message from NOVA to ascertain the correct DNS name for a Nova instance as it starts

The service will then send an RFC2136 update to a target bluecat DNS server

#### bluecat.conf [bluecat_nova_monitor] section settings

Set parameters for the BlueCat Neutron Monitor

	`broker_uri=amqp://stackrabbit:bluecat@localhost:5672//`

Sets the AMQ broker URI, used to read rabbitMQ messages

	`nameserver=192.168.1.102`

Sets the target DNS server to be updated by DDNS

	`logfile=/opt/bluecat/Bluecat Nova Monitor/bluecat_nova.log`

Sets the logfile location and name 

	`ttl=666`

Sets the TTL of the records added to DNS 

	`domain_override=False`

Sets a domain name to append to the instance name, if this parameter is set to False the monitor will utilise the whole instances name as a fully qualified domain name

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

Copyright 2018 BlueCat Networks (USA) Inc. and its affiliates

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
