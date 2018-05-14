#!/usr/bin/env python

# Copyright 2018 Bluecat Networks Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# BlueCat Neutron Monitor listens on the AMQP message bus of Openstack.
# Whenever a Neutron notification message is seen for a port or floating_IP update, does X

# B.Shorland - Bluecat Networks 2018

import dns.name
import dns.message
import dns.query
import dns.flags
import dns.reversename
import dns.rdatatype
import dns.update
import dns.resolver
import dns.exception
import string
import ipaddress
import netaddr
import datetime
import sys
import json
import logging as log

from inspect import getmembers
from pprint import pprint
import httplib
from suds.client import Client
from suds import WebFault
from suds.transport.http import HttpAuthenticated
from pip._vendor.ipaddress import ip_address
from configparser import ConfigParser

from kombu import BrokerConnection
from kombu import Exchange
from kombu import Queue
from kombu.mixins import ConsumerMixin
from oslo_config import cfg
from oslo_service import service
import oslo_messaging

bluecat_neutron_parameters = [
    cfg.StrOpt('bcn_neutron_transport_url', default=None, help=("BlueCat Neutron Monitor Transport URL")),
    cfg.StrOpt('bcn_neutron_nameserver', default=None, help=("BlueCat Neutron Monitor NameServer")),
    cfg.StrOpt('bcn_neutron_logfile', default=None, help=("BlueCat Neutron Monitor LogFile")),
    cfg.StrOpt('bcn_neutron_ttl', default=666, help=("BlueCat Neutron Monitor TTL")),
    cfg.StrOpt('bcn_neutron_domain_override', default=None, help=("BlueCat Neutron Monitor Domain Overide")),
    cfg.StrOpt('bcn_neutron_debuglevel', default="INFO", help=("BlueCat Neutron Monitor Debug Level")),
    cfg.DictOpt('bcn_neutron_TSIG', default=None, help=("BlueCat Neutron TSIG")),
    cfg.StrOpt('bcn_neutron_replace', default="False", help=("BlueCat Neutron Monitor Replace Policy")),
    cfg.StrOpt('bam_address', default=None, help=("BAM IP Address")),
    cfg.StrOpt('bam_api_user', default=None, help=("BAM API User Name")),
    cfg.StrOpt('bam_api_pass', default=None, help=("BAM API User Password")),
    cfg.StrOpt('bam_config_name', default=None, help=("BAM Configuration Name")),
    cfg.StrOpt('bam_updatemodify_networks', default=None, help=("BAM Update Of Modify Networks"))]
    
version = 0.3

EXCHANGE_NAME="neutron"
ROUTING_KEY="notifications.info"
QUEUE_NAME="bluecat_neutron_monitor"
FLOAT_START="floatingip.create.start"
FLOAT_END="floatingip.create.end"
FLOAT_U_START="floatingip.update.start"
FLOAT_U_END="floatingip.update.end"
PORT_START="port.create.start"
PORT_END="port.create.end"
PORT_U_START="port.update.start"
PORT_U_END="port.update.end"
ADDITIONAL_RDCLASS = 65535

SUBNET_CREATE_START="subnet.create.start"
SUBNET_CREATE_END="subnet.create.end"
SUBNET_DELETE_END="subnet.delete.end"
SUBNET_UPDATE_END="subnet.update.end"

NETWORK_CREATE_START="network.create.start"
NETWORK_CREATE_END="network.create.end"
NETWORK_DELETE_END="network.delete.end"
NETWORK_UPDATE_END="network.update.end"

bluecat_group = cfg.OptGroup(name='bluecat',title='Bluecat Group')

def config_parser(conf,list):
	CONF = cfg.CONF
	CONF.register_group(bluecat_group)
	CONF.register_opts(list, "bluecat")
	CONF(default_config_files=conf)
	return CONF

# read in settings from neutron.conf

NEUTRON_CONF=config_parser(['/etc/neutron/neutron.conf'],bluecat_neutron_parameters)

monitor_broker = NEUTRON_CONF.bluecat.bcn_neutron_transport_url
monitor_nameserver = NEUTRON_CONF.bluecat.bcn_neutron_nameserver
monitor_logfile = NEUTRON_CONF.bluecat.bcn_neutron_logfile
monitor_ttl = NEUTRON_CONF.bluecat.bcn_neutron_ttl
monitor_domain_override = NEUTRON_CONF.bluecat.bcn_neutron_domain_override
monitor_debuglevel = NEUTRON_CONF.bluecat.bcn_neutron_debuglevel
monitor_replace = NEUTRON_CONF.bluecat.bcn_neutron_replace
monitor_TSIG = bcn_neutron_TSIG = NEUTRON_CONF.bluecat.bcn_neutron_TSIG

bam_address = NEUTRON_CONF.bluecat.bam_address
bam_api_user = NEUTRON_CONF.bluecat.bam_api_user
bam_api_pass = NEUTRON_CONF.bluecat.bam_api_pass
bam_config_name = NEUTRON_CONF.bluecat.bam_config_name
bam_updatemodify_networks = NEUTRON_CONF.bluecat.bam_updatemodify_networks


print 'BlueCat Neutron Monitor Transport URL = ',monitor_broker
print 'BlueCat Neutron Monitor NameServer =',monitor_nameserver
print 'BlueCat Neutron Monitor Logfile =',monitor_logfile
print 'BlueCat Neutron Monitor Debug Level = ',monitor_debuglevel
print 'BlueCat Nuetron Monitor TTL =',monitor_ttl
print 'BlueCat Nuetron Monitor Domain Override = ',monitor_domain_override
print 'BlueCat Nuetron Monitor Replace = ',monitor_replace


if bcn_neutron_TSIG.keys():
	print "Domains with configured TSIG keys:"
	neutronsecuredomains = bcn_neutron_TSIG.keys()
	for i in range(len(neutronsecuredomains)):
		print "Domain: \033[0;32m %s \033[1;m" %(neutronsecuredomains[i])
		print "TSIG Key: \033[0;32m %s \033[1;m" %(bcn_neutron_TSIG[neutronsecuredomains[i]])

print "BlueCat Address Manager:\033[0;32m  %s \033[1;m" % bam_address
print "BlueCat Address Manager API User:\033[0;32m  %s \033[1;m" % bam_api_user
print "BlueCat Address Manager API Password:\033[0;32m %s \033[1;m" % bam_api_pass
print "BlueCat Configuration Name:\033[0;32m %s \033[1;m" % bam_config_name
print "BlueCat Update/Modify Network Policy:\033[0;32m %s \033[1;m" % bam_updatemodify_networks


# read from Nuetron.conf [bluecat] settings parameters bcn_neutron_debuglevel and bcn_neutron_logfile
#log.basicConfig(filename=monitor_logfile, level=monitor_debuglevel, format='%(asctime)s %(message)s')
log.basicConfig(filename=monitor_logfile, level="INFO", format='%(asctime)s %(message)s')

class TSIGSecured():
        TSIGKey=""
        keyname=""
        domains = bcn_neutron_TSIG.keys()

        def __init__(self, domain):
                self.domain = domain

        def TSIG(self,domain):
                self.domain = domain
                if domain in TSIGSecured.domains:
                        log.debug ("[TSIGSecured.TSIG] \033[0;32m TSIG Key in neutron.conf %s \033[1;m" % bcn_neutron_TSIG[domain])
                        keyname = domain.replace(".","_")
                        log.debug ('[TSIGSecured.TSIG] \033[0;32m expected TSIG key name in BAM %s \033[1;m' % keyname)
                        return bcn_neutron_TSIG[domain]
                else:
                        log.debug ("[TSIGSecured.TSIG] \033[1;31m No TSIG key in neutron.conf for %s \033[1;m" % domain)
                        return

        def isSecure(self,domain):
                self.domain = domain
                if domain in TSIGSecured.domains:
						log.debug ("[TSIGSecured.isSecure] \033[0;32m TSIG key in neutron.conf for %s \033[1;m" % domain)
						keyname = domain.replace(".","_")
						log.debug ('[TSIGSecured.isSecure] \033[0;32m expected TSIG key name in BAM %s \033[1;m' % keyname)
						return True
                else:
                        log.debug ("[TSIGSecured.isSecure] \033[1;31m No TSIG key found in neutron.conf for %s \033[1;m" % domain)
                        return False

def stripptr(substr, str):
        index = 0
        length = len(substr)
        while string.find(str,substr) != -1:
                index = string.find(str,substr)
                str = str[0:index] + str[index+length:]
	str = str.rstrip('.')
        return str

# Check the reverse zone authority upon target DNS server
def getrevzone_auth(domain):
	domain = dns.name.from_text(domain)
	if not domain.is_absolute():
		domain = domain.concatenate(dns.name.root)
	request = dns.message.make_query(domain, dns.rdatatype.ANY)
	request.flags |= dns.flags.AD
	request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS, dns.rdatatype.OPT, create=True, force_unique=True)
	response = dns.query.udp(request, monitor_nameserver)
	if not response.authority:
		log.debug ('[getrevzone_auth] -\033[1;31m DNS not authoritive\033[1;m')
		return
	else:
		auth_reverse = str(response.authority).split(' ')[1]
		log.debug ('[getrezone_auth] - %s' % str(auth_reverse).lower())
		return str(auth_reverse).lower()

# Add PTR record for a given address,ttl and name
def addREV(ipaddress,ttl,name):
	reversedomain = dns.reversename.from_address(str(ipaddress))
	reversedomain = str(reversedomain).rstrip('.')
	log.debug ('[addREV] - reversedomain  %s' % reversedomain)
	authdomain = getrevzone_auth(str(reversedomain)).rstrip('.')
	log.debug ('[addREV] - authdomain %s' % authdomain)
	label = stripptr(authdomain, reversedomain)
	log.debug ('[addREV] - label %s' % label)
	log.debug ('[addREV] - name %s' % name)
	check4TSIG = TSIGSecured(authdomain)
	if check4TSIG.isSecure(authdomain):
		key = str(check4TSIG.TSIG(authdomain))
		keyname = authdomain.replace(".","_")
		keyring = dns.tsigkeyring.from_text({keyname:key})
		update = dns.update.Update(authdomain, keyring=keyring)
	else:
		update = dns.update.Update(authdomain)
	if monitor_replace == False:
		update.add(label,monitor_ttl,dns.rdatatype.PTR, name)
	else:
		update.replace(label,monitor_ttl,dns.rdatatype.PTR, name)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# Delete PTR record for a passed address,name
def delREV(ipaddress,name):
	name = str(name)
	reversedomain = dns.reversename.from_address(str(ipaddress))
	reversedomain = str(reversedomain).rstrip('.')
	log.debug ('[delREV] - reversedomain  %s' % reversedomain)
	authdomain = getrevzone_auth(str(reversedomain)).rstrip('.')
	log.debug ('[delREV] - authdomain  %s' % authdomain)
	check4TSIG = TSIGSecured(authdomain)
	if check4TSIG.isSecure(authdomain):		
		key = str(check4TSIG.TSIG(authdomain))
		keyname = authdomain.replace(".","_")
		keyring = dns.tsigkeyring.from_text({keyname:key})
		update = dns.update.Update(authdomain, keyring=keyring)
	else:
		update = dns.update.Update(authdomain)
	label = stripptr(authdomain, reversedomain)
	log.debug ('[delREV] - label  %s' % label)
	update.delete(label,'PTR',name)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# add A/AAAA record by name, ttl and address
def addFWD(name,ttl,ipaddress):
	ipaddress = str(ipaddress)
	hostname = splitFQDN(name)[0]
	log.debug ('[addFWD] - hostname %s' % hostname)
	log.debug ('[addFWD] - domain %s' % splitFQDN(name)[1])
	domain = splitFQDN(name)[1]
	if domain.endswith("."):
		domain = domain.rstrip('.')
	check4TSIG = TSIGSecured(domain)
	if check4TSIG.isSecure(domain):
		key = str(check4TSIG.TSIG(domain))
		keyname = domain.replace(".","_")
		keyring = dns.tsigkeyring.from_text({keyname:key})
		update = dns.update.Update(splitFQDN(name)[1], keyring=keyring)
	else:
		update = dns.update.Update(splitFQDN(name)[1])
	address_type = enumIPtype(ipaddress)
        if address_type == 4:
		log.debug ('[addFWD] - IPv4')
		if monitor_replace == "False":
			update.add(hostname,monitor_ttl,dns.rdatatype.A, ipaddress)
		else:
			update.replace(hostname,monitor_ttl,dns.rdatatype.A, ipaddress)
	elif address_type == 6:
		log.debug ('[addFWD] - IPv6')

		if monitor_replace == "False":
			update.add(hostname,monitor_ttl,dns.rdatatype.AAAA, ipaddress)
		else:
			update.replace(hostname,monitor_ttl,dns.rdatatype.AAAA, ipaddress)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# Delete record from name, ipadress
def delFWD(name,ipaddress):
	name = str(name)
	ipaddress = str(ipaddress)
	update = dns.update.Update(splitFQDN(name)[1])
	hostname = splitFQDN(name)[0]
	domain = (splitFQDN(name)[1]).rstrip('.')
	log.debug ('[delFWD] - name %s' % name)
	log.debug ('[delFWD] - ipaddress %s' % ipaddress)
	log.debug ('[delFWD] - hostname %s' % hostname)
	log.debug ('[delFWD] - domainname %s' % domain)
	check4TSIG = TSIGSecured(domain)
	if check4TSIG.isSecure(domain):
		key = str(check4TSIG.TSIG(domain))
		keyname = domain.replace(".","_")
		keyring = dns.tsigkeyring.from_text({keyname:key})
		update = dns.update.Update(splitFQDN(name)[1], keyring=keyring)
	else:
		update = dns.update.Update(splitFQDN(name)[1])
	address_type = enumIPtype(ipaddress)
	if address_type == 4:
		update.delete(hostname, 'A', ipaddress)
	if address_type == 6:
		update.delete(hostname, 'AAAA', ipaddress)	
	response = dns.query.udp(update, monitor_nameserver)
	return response

# Resolve PTR record given either IPv4 or IPv6 address
def resolvePTR(address):
	type = enumIPtype(address)
	address = str(address)
	if type == 4:
		req = '.'.join(reversed(address.split('.'))) + ".in-addr.arpa."
		log.debug ('[ResolvePTR] - %s' % req)
	elif type == 6:
		# exploded concatenated V6 address out
		v6address = ipaddress.ip_address(unicode(address))
		v6address = v6address.exploded
		req = '.'.join(reversed(v6address.replace(':',''))) + ".ip6.arpa."
		log.debug ('[ResolvePTR] - %s' % req)
	myResolver = dns.resolver.Resolver()
	myResolver.nameservers = [monitor_nameserver]
	try:
		myAnswers = myResolver.query(req, "PTR")
		for rdata in myAnswers:
			log.debug ('[ResolvePTR] - %s' % rdata)
			return rdata
	except:
		log.debug ('[ResolvePTR] - \033[1;31m PTR query failed \033[1;m')
		return "PTR Query failed"

# Returns address type 4 or 6
def enumIPtype(address):
	address = ipaddress.ip_address(unicode(address))
	return address.version

# Splits FQDN into host and domain portions
def splitFQDN(name):
	hostname = name.split('.')[0]
	domain = name.partition('.')[2]
	return hostname,domain

def getItemsFromResponse(data):
    dataStr = data.decode("utf-8")
    words = dataStr.split(',')
    return words


def getPropsField(properties, keyName):
    propsArr = properties.split('|')
    for prop in propsArr:
        kv = prop.split("=")
        if kv[0] == keyName:
            return kv[1]
            break
    return None

def updatePropsStr(props, fieldName, value):
    params = {}
    keyValPairs = props.split('|')
    for keyValPair in keyValPairs:
        keyVal = keyValPair.split('=')
        if len(keyVal) > 1:
            params[keyVal[0]] = keyVal[1]
    params[fieldName] = value
    newProps = ""
    for key in params:
        newProps += key +"=" +params[key] +'|'
    return newProps

def _bam_login():
   log.debug ('\033[0;32m[BAM] Connecting to BAM at %s ...' % bam_address)
   soap_client = Client('http://%s/Services/API?wsdl' % bam_address)
   soap_client.service.login(bam_api_user, bam_api_pass)
   return soap_client

def _bam_logout(soap_client):
   log.debug ('\033[0;32m[BAM] Disconnecting from BAM at %s ...\033[1;m' % bam_address)
   soap_client.service.logout()


def _get_bam_configid(soap_client):
   config = soap_client.service.getEntityByName(0, bam_config_name, 'Configuration')
   configID = long(config['id'])
   log.debug ('\033[0;32m[BAM] ConfigID %d\033[1;m' % (configID))
   return configID


def config_parser(conf,list):
	CONF = cfg.CONF
	CONF.register_group(bluecat_group)
	CONF.register_opts(list, "bluecat")
	CONF(default_config_files=conf)
	return CONF

def updateBCNetwork(soap_client, configID, netCIDR, newNetName, subnet_id, network_id,tenant_id, project_id,subnet_pool_id ):
    # Get netid
    ipNet = netaddr.IPNetwork(netCIDR)

    log.debug ('\033[0;32m[BAM] Getting NetID Info  ... \033[1;m')
    net = ""
    if ipNet.version == 4:
        net = soap_client.service.getIPRangedByIP(configID, "IP4Network", ipNet[0])
    else:
        net = soap_client.service.getIPRangedByIP(configID, "IP6Network", ipNet[0])

    netid = net['id']

    if not netid:
        log.debug ('\033[0;32m[BAM] [Warning!!!] : Network does not exist - Skipping ....\033[1;m' % netCIDR)
        return

    newSubnetID = updatePropsStr(net['properties'], "OS_SUBNET_ID", subnet_id)
    newNetworkID = updatePropsStr(net['properties'], "OS_NETWORK_ID", network_id)
    newTenantID = updatePropsStr(net['properties'], "OS_TENANT_ID", tenant_id)
    newProjectID = updatePropsStr(net['properties'], "OS_PROJECT_ID", project_id)
    newSubnetPoolID = updatePropsStr(net['properties'], "OS_SUBNET_POOL_ID", subnet_pool_id)
    
    newProps  = newSubnetID + newNetworkID + newTenantID + newProjectID + newSubnetPoolID
    
    # new, subnet_id, "OS_NETWORK_ID", network_id, "OS_TENANT_ID", tenant_id, "OS_PROJECT_ID", project_id, "OS_SUBNET_POOL_ID")
    
    net['name'] = newNetName
    net['properties'] = newProps

    print "[BAM] Updating Network ..."
    soap_client.service.update(net)
	

class BCUpdater(ConsumerMixin):

    def __init__(self, connection):
        self.connection = connection
        return

    def get_consumers(self, consumer, channel):
        exchange = Exchange(EXCHANGE_NAME, type='topic', durable=False)
        queue = Queue(
            QUEUE_NAME,
            exchange,
            routing_key=ROUTING_KEY,
            durable=False,
            auto_delete=True,
            no_ack=True,
            )
        return [consumer(queue, callbacks=[self.on_message])]

    def on_message(self, body, message):
        try:
            self._handle_message(body)
        except Exception, e:
            log.info(repr(e))

# Message handler extracts event_type
    def _handle_message(self, body):
		log.debug('[Event Body] %r' % body)
		jbody = json.loads(body['oslo.message'])
		event_type = jbody['event_type']
		log.info ('\033[0;32m[Event Type] [%s] \033[1;m' % event_type)
 		if event_type == FLOAT_START:
 			# no relevent information in floatingip.create.start
 			log.info ('[floatingip.create.start]')

 		elif event_type == FLOAT_END:
 			# only floating_ip_address in payload as IP is selected from pool
 			fixed = jbody['payload']['floatingip']['fixed_ip_address']
 			log.info ('[floatingip.create.end] -> FIXED_IP_ADDRESS = %s' % fixed)
 			float = jbody['payload']['floatingip']['floating_ip_address']
 			log.info ('[floatingip.create.end] -> FLOATING_IP_ADDRESS = %s' % float)
 			port_id = jbody['payload']['floatingip']['port_id']
 			log.info ('[floatingip.create.end] -> PORT_ID = %s' % port_id)

 		elif event_type == FLOAT_U_START:
 			# fixed IP from instance to which floating IP will be assigned and the port_id (upon associated)
 			# NULL (upon dis-associated)
 			if 'fixed_ip_address' in jbody['payload']['floatingip']:
 				fixed = jbody['payload']['floatingip']['fixed_ip_address']
 				if fixed is not None:
 					log.info ('[floatingip.update.start] -> FIXED_IP_ADDRESS = %s' % fixed)
 					checkit = resolvePTR(fixed)
 					log.info ('[floatingip.update.start] -> FIXED FQDN = %s' % checkit)
 					port_id = jbody['payload']['floatingip']['port_id']
 					log.info ('[floatingip.update.start] -> PORT_ID = %s' % port_id)

 		elif event_type == FLOAT_U_END:
 			# Fixed_IP, Floating_IP and Port_ID seen (upon associate)
 			# Fixed_IP = None, floating_IP, and port_id = None (upon disassociation)
 			if 'fixed_ip_address' in jbody['payload']['floatingip']:
 				fixed = jbody['payload']['floatingip']['fixed_ip_address']
 				log.info ('[floatingip.update.end] -> FixedIP = %s ' % fixed)
 				float = jbody['payload']['floatingip']['floating_ip_address']
 				log.info ('[floatingip.update.end] -> FloatingIP = %s ' % float)
 				port_id = jbody['payload']['floatingip']['port_id']
 				log.info ('[floatingip.update.end] -> PortID = %s' % port_id)
 				if fixed is not None and float is not None and port_id is not None:
 					log.info ('[floatingip.update.end] -> Associating FloatingIP to instance')
 					log.info ('[floatingip.update.end] -> FIXED_IP_ADDRESS = %s' % fixed)
 					checkit = str(resolvePTR(fixed))
 					log.info ('[floatingip.update.end] -> FIXED FQDN = %s' % checkit)
 					log.info ('[floatingip.update.end] -> FLOATING_IP_ADDRESS = %s' % float)
 					log.info ('[floatingip.update.end] -> PORT_ID = %s' % port_id)
 					if monitor_replace == "False":
						log.info ('[floatingip.update.end] - Updating DNS - adding FLOATING_IP records')
					else:
						log.info ('[floatingip.update.end] - Updating DNS - replacing FIXED_IP records with FLOATING_IP')
 					addFWD(checkit,'666',float)
 					addREV(float,'666',checkit)
 				elif fixed is None and float and port_id is None:
 					log.info ('[floatingip.update.end] -> disassociating FloatingIP from instance')
 					checkit = str(resolvePTR(float))
 					log.info ('[floatingip.update.end] -> FLOATING_IP_ADDRESS = %s' % float)
 					log.info ('[floatingip.update.end] -> FLOATING_IP FQDN = %s' % checkit)
 					log.info ('[floatingip.update.end] - removing FLOATING_IP records')
 					delFWD(checkit,float)
 					delREV(float,checkit)

 		elif event_type == PORT_START:
 			if 'id' in jbody['payload']['port']:
 				port_id = jbody['payload']['port']['id']
 				log.info ('[port.create.start] -> PORT_ID = %s' % port_id)

 		elif event_type == PORT_END:
 			port_id = jbody['payload']['port']['id']
 			log.info ('[port.create.end] -> PORT_ID = %s' % port_id)

 		elif event_type == PORT_U_START:
 			if 'id' in jbody['payload']['port']:
 				port_id = jbody['payload']['port']['id']
 				log.info ('[port.update.start] - > PORT_ID = %s' % port_id)

 		elif event_type == PORT_U_END:
 			port_id = jbody['payload']['port']['id']
 			log.info ('[port.update.end] -> PORT_ID = %s' % port_id)
 			for temp in jbody['payload']['port']['fixed_ips']:
 				addr = temp['ip_address']
 				log.info ('[port.update.end] -> IP ADDRESS = %s' % addr)

		elif event_type == SUBNET_CREATE_START:
			log.info ('\033[0;32m[subnet.create.start]\033[1;m')
			subnet_name = jbody['payload']['subnet']['name']
			network_id = jbody['payload']['subnet']['network_id']
			tenant_id = jbody['payload']['subnet']['tenant_id']
			
			log.info ('\033[0;32m[subnet.create.start] Subnet Name [%s] \033[1;m' % subnet_name)
			log.info ('\033[0;32m[subnet.create.start] Network ID: %s \033[1;m' % network_id)
			log.info ('\033[0;32m[subnet.create.start] Tenant ID: %s \033[1;m' % tenant_id)

			
		elif event_type == SUBNET_CREATE_END:
			log.info ('\033[0;32m[subnet.create.end]\033[1;m')
			subnet_name = jbody['payload']['subnet']['name']
			subnet_address = jbody['payload']['subnet']['cidr']	
			network_id = jbody['payload']['subnet']['network_id']
			tenant_id = jbody['payload']['subnet']['tenant_id']
			gateway_ip = jbody['payload']['subnet']['gateway_ip']
			subnet_id = jbody['payload']['subnet']['id']
			
			subnet_pool_id = jbody['payload']['subnet']['subnetpool_id']
			project_id = jbody['payload']['subnet']['project_id']
			
			log.info ('\033[0;32m[subnet.create.end] Subnet Name: %s \033[1;m' % subnet_name)
			log.info ('\033[0;32m[subnet.create.end] Subnet Address: %s \033[1;m' % subnet_address)
			log.info ('\033[0;32m[subnet.create.end] Gateway IP: %s \033[1;m' % gateway_ip)
			log.info ('\033[0;32m[subnet.create.end] Network ID: %s \033[1;m' % network_id)
			log.info ('\033[0;32m[subnet.create.end] Tenant ID: %s \033[1;m' % tenant_id)
			log.info ('\033[0;32m[subnet.create.end] Subnet ID: %s \033[1;m' % subnet_id)
			log.info ('\033[0;32m[subnet.create.end] Subnet Pool ID: %s \033[1;m' % subnet_pool_id)
			log.info ('\033[0;32m[subnet.create.end] Project ID: %s \033[1;m' % project_id)
			soap_client = _bam_login()
			configID = _get_bam_configid(soap_client)

			log.info ('\033[0;32m[subnet.create.end] Updating BAM Network %s with name %s \033[1;m' % (subnet_address, subnet_name))
			updateBCNetwork(soap_client, configID, subnet_address, subnet_name, subnet_id, network_id,tenant_id,project_id,subnet_pool_id)
			_bam_logout(soap_client)
			
				
		elif event_type == SUBNET_DELETE_END:
			log.info ('\033[0;32m[subnet.delete.end]\033[1;m')
			log.info ('\033[0;32m[subnet.delete.end]\033[1;m')
			subnet_name = jbody['payload']['subnet']['name']
			subnet_address = jbody['payload']['subnet']['cidr']
			network_id = jbody['payload']['subnet']['network_id']
			tenant_id = jbody['payload']['subnet']['tenant_id']
			gateway_ip = jbody['payload']['subnet']['gateway_ip']
			subnet_pool_id = jbody['payload']['subnet']['subnetpool_id']
			project_id = jbody['payload']['subnet']['project_id']
			subnet_id = jbody['payload']['subnet']['id']

			log.info ('\033[0;32m[subnet.delete.end] Subnet Name: %s \033[1;m' % subnet_name)
			log.info ('\033[0;32m[subnet.delete.end] Subnet Address: %s \033[1;m' % subnet_address)
			log.info ('\033[0;32m[subnet.delete.end] Gateway IP: %s \033[1;m' % gateway_ip)
			log.info ('\033[0;32m[subnet.delete.end] Network ID: %s \033[1;m' % network_id)
			log.info ('\033[0;32m[subnet.delete.end] Tenant ID: %s \033[1;m' % tenant_id)
			log.info ('\033[0;32m[subnet.delete.end] Subnet ID: %s \033[1;m' % subnet_id)
			log.info ('\033[0;32m[subnet.delete.end] Subnet Pool ID: %s \033[1;m' % subnet_pool_id)
			log.info ('\033[0;32m[subnet.delete.end] Project ID: %s \033[1;m' % project_id)
				
		elif event_type == SUBNET_UPDATE_END:
			log.info ('\033[0;32m[subnet.update.end]\033[1;m')
		elif event_type == NETWORK_CREATE_START:
			log.info ('\033[0;32m[network.create.start]\033[1;m')
		elif event_type == NETWORK_CREATE_END:
			log.info ('\033[0;32m[network.create.end]\033[1;m')
		elif event_type == NETWORK_DELETE_END:
			log.info ('\033[0;32m[network.delete.end]\033[1;m')
		elif event_type == NETWORK_UPDATE_END:
			log.info ('\033[0;32m[network.update.end]\033[1;m')

if __name__ == "__main__":
    log.info("BlueCat Neutron Monitor - %s Bluecat Networks 2018" % version)
    log.info("- AMQ connection URI: %s" % monitor_broker)
    log.info("- Sending RFC2136 Dynamic DNS updates to DNS: %s" % monitor_nameserver)
    log.info("- Debugging Logging to %s" % monitor_logfile)
    log.info("- Debug Log Level: %s" % monitor_debuglevel)
    log.info("- Dynamic TTL for Records: %s" % monitor_ttl)
    log.info("- Override Domain: %s" % monitor_domain_override)
    log.info("- Replace FixedIP with Floating: %s" % monitor_replace)

    with BrokerConnection(monitor_broker) as connection:
		try:
			print(connection)
			BCUpdater(connection).run()
		except KeyboardInterrupt:
			print(' - Exiting Bluecat Neutron Monitor ....')
