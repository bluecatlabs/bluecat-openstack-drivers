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
import datetime
import sys
import json
import logging as log
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
    cfg.StrOpt('bcn_neutron_ttl', default=None, help=("BlueCat Neutron Monitor TTL")),
    cfg.StrOpt('bcn_neutron_domain_override', default=None, help=("BlueCat Neutron Monitor Domain Overide")),
    cfg.StrOpt('bcn_neutron_debuglevel', default=None, help=("BlueCat Neutron Monitor Debug Level")),
    cfg.StrOpt('bcn_neutron_replace', default=None, help=("BlueCat Neutron Monitor Replace Policy"))]

version = 1.0

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

print 'BlueCat Neutron Monitor Transport URL = ',monitor_broker
print 'BlueCat Neutron Monitor NameServer =',monitor_nameserver
print 'BlueCat Neutron Monitor Logfile =',monitor_logfile
print 'BlueCat Neutron Monitor Debug Level = ',monitor_debuglevel
print 'BlueCat Nuetron Monitor TTL =',monitor_ttl
print 'BlueCat Nuetron Monitor Domain Override = ',monitor_domain_override
print 'BlueCat Nuetron Monitor Replace = ',monitor_replace

# read from Nuetron.conf [bluecat] settings parameters bcn_neutron_debuglevel and bcn_neutron_logfile
log.basicConfig(filename=monitor_logfile, level=monitor_debuglevel, format='%(asctime)s %(message)s')

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
		log.debug ('[getrevzone_auth] - DNS not authoritive')
		return
	else:
		auth_reverse = str(response.authority).split(' ')[1]
		log.debug ('[getrezone_auth] - %s' % str(auth_reverse).lower())
		return str(auth_reverse).lower()

# Add PTR record for a given address
def addREV(ipaddress,ttl,name):
	reversedomain = dns.reversename.from_address(str(ipaddress))
	reversedomain = str(reversedomain).rstrip('.')
	log.debug ('[addREV] - reversedomain  %s' % reversedomain)
	authdomain = getrevzone_auth(str(reversedomain)).rstrip('.')
	log.debug ('[addREV] - authdomain %s' % authdomain)
	label = stripptr(authdomain, reversedomain)
	log.debug ('[addREV] - label %s' % label)
	log.debug ('[addREV] - name %s' % name)
	update = dns.update.Update(authdomain)
	if monitor_replace == False:
		update.add(label,monitor_ttl,dns.rdatatype.PTR, name)
	else:
		update.replace(label,monitor_ttl,dns.rdatatype.PTR, name)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# Delete PTR record for a passed address
def delREV(ipaddress,name):
	name = str(name)
	reversedomain = dns.reversename.from_address(str(ipaddress))
	reversedomain = str(reversedomain).rstrip('.')
	log.debug ('[delREV] - reversedomain  %s' % reversedomain)
	authdomain = getrevzone_auth(str(reversedomain)).rstrip('.')
	log.debug ('[delREV] - authdomain  %s' % authdomain)
	update = dns.update.Update(authdomain)
	label = stripptr(authdomain, reversedomain)
	log.debug ('[delREV] - label  %s' % label)
	update.delete(label,'PTR',name)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# Delete A/AAAA record from name
def delFWD(name,ipaddress):
	name = str(name)
	ipaddress = str(ipaddress)
	update = dns.update.Update(splitFQDN(name)[1])
	hostname = splitFQDN(name)[0]
	domain = splitFQDN(name)[1]
	log.debug ('[delFWD] - name %s' % name)
	log.debug ('[delFWD] - ipaddress %s' % ipaddress)
	log.debug ('[delFWD] - hostname %s' % hostname)
	log.debug ('[delFWD] - domainname %s' % domain)
	update.delete(hostname, 'A', ipaddress)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# add A/AAAA record
def addFWD(name,ttl,ipaddress):
	ipaddress = str(ipaddress)
	update = dns.update.Update(splitFQDN(name)[1])
	hostname = splitFQDN(name)[0]
	log.debug ('[addFWD] - hostname %s' % hostname)
	log.debug ('[addFWD] - domain %s' % splitFQDN(name)[1])
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

# Resolve PTR record from either IPv4 or IPv6 address
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
		log.debug ('[ResolvePTR] - PTR query failed')
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
		log.debug('Body: %r' % body)
		jbody = json.loads(body['oslo.message'])
		event_type = jbody['event_type']
		log.info ('EVENT_TYPE = %s' % event_type)
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
