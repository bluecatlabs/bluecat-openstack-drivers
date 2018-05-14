# BlueCat OpenStack Driver
The BlueCat OpenStack integration consists of three Python-based components:

- The BlueCat OpenStack Neutron IPAM Driver, which documents OpenStack subnets,ports and compute instances as they are provisioned in Openstack within the BlueCat Address Manager™ (BAM)
- The BlueCat OpenStack Nova monitor, which sends OpenStack instance FQDNs (A,AAAA and PTRs) to a Bluecat DNS server (BDDS) dynamically, which then forwards updates to Bluecat Address Manager™ (BAM) 
- The Bluecat Neutron monitor, which sends floating IP assignment updates (A,AAAA and PTRs) to Bluecat DNS server dynamically, which then updates the DNS records within Bluecat Address Manager™ (BAM) 

## Installation
All development has taken place against DevStack, installation directly onto production OpenStack Neutron and Nova nodes should be tested and validated independently.

#### Prepare BlueCat Address Manager™ (BAM)

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
		
- Create new UDFs for the IPv4 Networks:

		`Administration > Object Types > IPv4 Network  > New > User Defined Field`

		Display Name `OpenStack Network ID`, Field Name `OS_NETWORK_ID`, Type `Text`

		`Administration > Object Types > IPv4 Network  > New > User Defined Field`

		Display Name `OpenStack Project ID`, Field Name `OS_PROJECT_ID`, Type `Text`

		`Administration > Object Types > IPv4 Network  > New > User Defined Field`

		Display Name `OpenStack Subnet ID`, Field Name `OS_SUBNET_ID`, Type `Text`

		`Administration > Object Types > IPv4 Network  > New > User Defined Field`

		Display Name `OpenStack Subnet Pool ID`, Field Name `OS_SUBNET_POOL_ID`, Type `Text`
		
		`Administration > Object Types > IPv4 Network  > New > User Defined Field`

		Display Name `OpenStack Tenant ID`, Field Name `OS_TENANT_ID`, Type `Text`
		
- Create new UDFs for the IPv6 Networks:

		`Administration > Object Types > IPv6 Network  > New > User Defined Field`

		Display Name `OpenStack Network ID`, Field Name `OS_NETWORK_ID`, Type `Text`

		`Administration > Object Types > IPv6 Network  > New > User Defined Field`

		Display Name `OpenStack Project ID`, Field Name `OS_PROJECT_ID`, Type `Text`

		`Administration > Object Types > IPv6 Network  > New > User Defined Field`

		Display Name `OpenStack Subnet ID`, Field Name `OS_SUBNET_ID`, Type `Text`

		`Administration > Object Types > IPv6 Network  > New > User Defined Field`

		Display Name `OpenStack Subnet Pool ID`, Field Name `OS_SUBNET_POOL_ID`, Type `Text`
		
		`Administration > Object Types > IPv6 Network  > New > User Defined Field`

		Display Name `OpenStack Tenant ID`, Field Name `OS_TENANT_ID`, Type `Text`

- Create IPv4 public and private blocks, for example `10.0.0.0/8 [OpenStack Public]` and `192.168.0.0/16 [OpenStack Private]`

Note :- OpenStack Subnets (Networks in BlueCat terminology) are dynamically created if not already present. However parent blocks must already exist in the Bluecat Address Manager

#### Install the BlueCat Neutron Driver on DevStack

- Edit the local.conf for Devstack to pull the BlueCat OpenStack Neutron IPAM Driver from GitHUB and set driver parameters

		enable_plugin bluecatopenstack https://github.com/bluecatlabs/bluecat-openstack-drivers.git 0.3
		enable_service bluecatopenstack

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
		
		bcn_nova_transport_url=amqp://stackrabbit:nintendo@localhost:5672//
		bcn_nova_nameserver=192.168.1.102
		bcn_nova_logfile=/home/brian/devstack/bluecat_nova.log
		bcn_nova_ttl=666
		bcn_nova_domain_override=False 
		bcn_nova_debuglevel=DEBUG
		bcn_nova_TSIG = bluecat.lab:trgMrgF/Kf1Bn67tNbWWhA==,openstack.bluecat.lab:c26dRiyCqnKfgVUGWlp5Tg==

		bcn_neutron_transport_url=amqp://stackrabbit:nintendo@localhost:5672//
		bcn_neutron_nameserver=192.168.1.102
		bcn_neutron_logfile=/home/brian/devstack/bluecat_neutron.log
		bcn_neutron_ttl=666
		bcn_neutron_domain_override=False
		bcn_neutron_debuglevel=DEBUG 
		bcn_neutron_replace=False
		bcn_neutron_TSIG = bluecat.lab:trgMrgF/Kf1Bn67tNbWWhA==,openstack.bluecat.lab:c26dRiyCqnKfgVUGWlp5Tg==

- Run stack.sh to stack Devstack, during stacking Devstack will correctly assigned the parameters defined in the local.conf into the nova/neutron.conf files automatically

- Post installation check the driver is installed by running `pip show bluecatopenstack`.

		Name: bluecatopenstack
		Version: 0.2.2
		Summary: Bluecat Networks Openstack Drivers
		Home-page: https://github.com/bluecatlabs/bluecat-openstack-drivers.git
		Author: B.Shorland
		Author-email: bshorland@bluecatnetworks.com
		License: Apache-2
		Location: /usr/lib/python2.7/site-packages
		Requires: dnspython, configparser, ipaddress, suds, pprint

#### Install the BlueCat Neutron Driver on Openstack

- Clone the git repo  

- Build the driver with `python setup.py install`

- Post installation check the driver is installed by running `pip show bluecatopenstack`

		Name: bluecatopenstack
		Version: 0.3
		Summary: Bluecat Networks Openstack Drivers
		Home-page: https://github.com/bluecatlabs/bluecat-openstack-drivers.git
		Author: B.Shorland
		Author-email: bshorland@bluecatnetworks.com
		License: Apache-2
		Location: /usr/lib/python2.7/site-packages
		Requires: dnspython, configparser, ipaddress, suds, pprint

- Adjust Neutron.conf to call the bluecatopenstack drivers

		IPAM_Driver = bluecatopenstack
		
- Adjust Neutron.conf adding the [Bluecat] section with parameters for the driver defined

		[bluecat]
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
		
#### Installing the Bluecat Nova Monitor

Edit the nova.conf to add the Bluecat parameters

	[bluecat]
	bcn_nova_transport_url=amqp://stackrabbit:nintendo@localhost:5672//
	bcn_nova_nameserver=192.168.1.102
	bcn_nova_logfile=/home/brian/devstack/bluecat_nova.log
	bcn_nova_ttl=666
	bcn_nova_domain_override=False 
	bcn_nova_debuglevel=DEBUG
	bcn_nova_TSIG = bluecat.lab:trgMrgF/Kf1Bn67tNbWWhA==,openstack.bluecat.lab:c26dRiyCqnKfgVUGWlp5Tg==

Copy the `bluecat_nova_monitor.py` from /opt/stack/neutron/bluecatopenstack/bluecatopenstack to a suitable location (such as `/opt/bluecat`)

Run the `bluecat_nova_monitor.py` code

#### Installing the Bluecat Neutron Monitor

Edit the neutron.conf to add the Bluecat parameters

	[bluecat]
	bcn_nova_transport_url=amqp://stackrabbit:nintendo@localhost:5672//
	bcn_nova_nameserver=192.168.1.102
	bcn_nova_logfile=/home/brian/devstack/bluecat_nova.log
	bcn_nova_ttl=666
	bcn_nova_domain_override=False 
	bcn_nova_debuglevel=DEBUG
	bcn_nova_TSIG = bluecat.lab:trgMrgF/Kf1Bn67tNbWWhA==,openstack.bluecat.lab:c26dRiyCqnKfgVUGWlp5Tg==

Copy the `bluecat_neutron_monitor.py` from /opt/stack/neutron/bluecatopenstack/bluecatopenstack to a suitable location (such as `/opt/bluecat`)

Run the `bluecat_neutron_monitor.py` code

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
