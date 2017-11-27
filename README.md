# BlueCat Openstack Integration Example

* Free software: Apache license

Bluecat Neutron Monitor
-----------------------

Contains a monitor service which listens for Openstack Neutron floating-IP event messages and updates Bluecat DNS

* Free software: Apache license

Overview
--------

Listens to AMPQ message from Neutron to ascertain the correct DNS name for a Nova instance as a Floating IP is associated
The service will then send an RFC2136 update to a target bluecat DNS server

Service Parameters
------------------

-n | --nameserver 
Set the target DNS server to be updated by DDNS (Defaults to 0.0.0.0)

-l | --logfile
Sets the logfile location and name (Default /opt/stack/devstack//bluecat/bluecat_neutron.log)

-t | --ttl
Sets the TTL of the records added to DNS (Default 1)

-d | --domain
Sets a domain name to append to the Nova instance name, if this parameter isn't passed the driver uses the instance as a FQDN

-r | --replace
At default the neutron monitor will add floating IP records to the target DNS and not replace the private IP DNS records created 
by the Bluecat Nova Monitor, setting this option will replace the private IP DNS records replacing with the floating IP record


Devstack Installation
---------------------

Ensure the notification.info messages are being sent by Neutron

local.conf

[[post-config|$NEUTRON_CONF]]
[DEFAULT]
notify_nova_on_port_status_changes = true
notify_nova_on_port_data_changes = true
control_exchange = neutron
notification_topics = notifications
notification_driver = messagingv2

Copy the bluecat_neutron_monitor.py to a suitable location (such as /opt/stack/devstack/bluecat)
chmod +x bluecat_neutron_monitor.py
mv bluecat_neutron_monitor.py bluecat_neutron_monitor

Copy the bluecat_neutron_monitor.sh to /etc/init.d
mv bluecat_neutron_monitor.sh bluecat_neutron_monitor
chmod +x /etc/init.d/bluecat_neutron_monitor
sudo vi /etc/init.d/bluecat_neutron_monitor

update the script parameters (APPDIR/APPARGS/USER/GROUP) to install locations and requirements, for example:

APPDIR="/opt/stack/devstack/bluecat"
APPARGS="--name 192.168.1.102 --ttl 999" 
USER="stack"
GROUP="stack"

sudo update-rc.d bluecat_neutron_monitor defaults

sudo service bluecat_neutron_monitor start [stop|restart|status]


Bluecat Nova Monitor
--------------------

Contains a monitor service which listens for Openstack nova event messages and updates Bluecat DNS

* Free software: Apache license

Overview
--------

Listens to AMPQ message from NOVA to ascertain the correct DNS name for a Nova instance as it starts
The service will then send an RFC2136 update to a target bluecat DNS server

Service Parameters
------------------

-n | --nameserver 
Set the target DNS server to be updated by DDNS (Defaults to 0.0.0.0)

-l | --logfile
Sets the logfile location and name (Default /opt/stack/devstack//bluecat/bluecat_nova.log)

-t | --ttl
Sets the TTL of the records added to DNS (Default 1)

-d | --domain
Sets a domain name to append to the Nova instance name, if this parameter isn't passed the driver uses the instance as a FQDN


Devstack Installation
---------------------

Copy the bluecat_nova_monitor.py to a suitable location (such as /opt/stack/devstack/bluecat)
chmod +x bluecat_nova_monitor.py
mv bluecat_nova_monitor.py bluecat_nova_monitor

Copy the bluecat_nova_monitor.sh to /etc/init.d
mv bluecat_nova_monitor.sh bluecat_nova_monitor
chmod +x /etc/init.d/bluecat_nova_monitor
sudo vi /etc/init.d/bluecat_nova_monitor

update the script parameters (APPDIR/APPARGS/USER/GROUP) to install locations and requirements, for example:

APPDIR="/opt/stack/devstack/bluecat"
APPARGS="--name 192.168.1.102 --ttl 999" 
USER="stack"
GROUP="stack"

sudo update-rc.d bluecat_nova_monitor defaults

sudo service bluecat_nova_monitor start [stop|restart|status]
