#!/usr/bin/env python

# Copyright 2017 Bluecat Networks Inc.
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

# BlueCat Nova Monitor listens on the AMQP message bus of Openstack. 
# Whenever a nova notification message is seen for a compute instance create or delete
# an RFC2136 DDNS update is sent to the Bluecat DNS defined which updates the A/AAAA and PTR records
# The bluecat DNS server will forward a notify onto the Bluecat address managed to update the Host Record 
# added by the Blue Neutron driver (which updates the BAM using the UUID (not hostname)

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
import sys, optparse
import json
import logging as log
from kombu import BrokerConnection
from kombu import Exchange
from kombu import Queue
from kombu.mixins import ConsumerMixin

version = 0.7
EXCHANGE_NAME="nova"
ROUTING_KEY="notifications.info"
QUEUE_NAME="bluecat_nova_monitor"
BROKER_URI="amqp://guest:guest@localhost:5672//"
EVENT_CREATE="compute.instance.create.end"
EVENT_DELETE="compute.instance.delete.start"
EVENT_UPDATE="compute.instance.update"
ADDITIONAL_RDCLASS = 65535

# Parse command line arguments
parser = optparse.OptionParser()
parser.add_option('-n','--nameserver',dest="nameserver",default="0.0.0.0",)
parser.add_option('-l','--logfile',dest="logfile",default="/opt/stack/devstack/bluecat/bluecat_nova.log",)
parser.add_option('-t','--ttl',dest="ttl",type=int,default=1,)
parser.add_option('-d','--domain',dest="domain",default=False,)
options, remainder = parser.parse_args()
print 'Sending DDNS Updates to BDDS =',options.nameserver
print 'Debug Logging =',options.logfile
print 'DDNS TTL =',options.ttl
print 'Domain =',options.domain


# Set INFO to DEBUG to see the RabbitMQ BODY messages 
log.basicConfig(filename=options.logfile, level=log.INFO, format='%(asctime)s %(message)s')

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
	response = dns.query.udp(request, options.nameserver)
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
	name = name + '.'
	log.debug ('[addREV] - name %s' % name)
	update = dns.update.Update(authdomain)
	update.replace(label,ttl,dns.rdatatype.PTR, name)
	response = dns.query.tcp(update, options.nameserver)
	return response

# Delete PTR record for a passed address
def delREV(ipaddress):
	reversedomain = dns.reversename.from_address(str(ipaddress))
	reversedomain = str(reversedomain).rstrip('.')
	log.debug ('[delREV] - reversedomain  %s' % reversedomain)
	authdomain = getrevzone_auth(str(reversedomain)).rstrip('.')
	log.debug ('[delREV] - authdomain  %s' % authdomain)
	update = dns.update.Update(authdomain)
	label = stripptr(authdomain, reversedomain)
	log.debug ('[delREV] - label  %s' % label)
	update.delete(label,'PTR')
	response = dns.query.tcp(update, options.nameserver)
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
		update.add(hostname,ttl,dns.rdatatype.A, ipaddress)
	elif address_type == 6:
		log.debug ('[addFWD] - IPv6')
		update.add(hostname,ttl,dns.rdatatype.AAAA, ipaddress)	
	response = dns.query.udp(update, options.nameserver)
	return response

# Resolve AAAA record from name, returns address
def delFWD(name):
	name = str(name)
	update = dns.update.Update(splitFQDN(name)[1])
	hostname = splitFQDN(name)[0]
	domain = splitFQDN(name)[1]
	log.debug ('[delFWD] - hostname %s' % hostname)
	log.debug ('[delFWD] - domainname %s' % domain)
	update.delete(hostname, 'A')
	update.delete(hostname, 'AAAA')
	response = dns.query.tcp(update, options.nameserver)
	return response
		
# Resolve A record from name, returns address
def resolveA(name):
	myResolver = dns.resolver.Resolver()
	myResolver.nameservers = [options.nameserver]
	try:
		myAnswers = myResolver.query(name, dns.rdatatype.A)
	except dns.exception.DNSException:
		log.debug ('[resolveA] - Exception %s' % dns.exception.DNSException)
		return 
	alist = []	
	for rr in myAnswers.response.answer:
		for a in rr:
			log.debug ('[resolveA] - %s' % a.address)
			alist.append (a.address)
		return alist
	return 
	

# Resolve AAAA record from name, returns address
def resolveAAAA(name):
	myResolver = dns.resolver.Resolver()
	myResolver.nameservers = [options.nameserver]
	try:
		myAnswers = myResolver.query(name, dns.rdatatype.AAAA)
	except dns.exception.DNSException:
		log.debug ('[resolveAAAA] - Exception %s' % dns.exception.DNSException)
		return 
	alist = []
	for rr in myAnswers.response.answer:
		for aaaa in rr:
			log.debug ('[resolveAAAA] - %s' % aaaa.address)
			alist.append (aaaa.address)
		return alist
	return		


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
	myResolver.nameservers = [options.nameserver]
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

# Message handler extracts event_type, hostname, addresses etc. from payload 
    def _handle_message(self, body):
		log.debug('Body: %r' % body)
		jbody = json.loads(body['oslo.message'])
		event_type = jbody['event_type']
		log.info ('Event Type :- %s' % event_type)
		
		if event_type in [EVENT_CREATE, EVENT_DELETE]:
			hostname = jbody['payload']['hostname']
			
			if options.domain == False:
				log.info ('[Payload] - Using INSTANCE as FQDN')
				log.debug ('[Payload] - INSTANCE %s' % hostname)
				fqdn = hostname
				log.debug ('[Payload] - FQDN %s'  % fqdn)
				hostname = splitFQDN(fqdn)[0]
				log.debug ('[Payload] - HOSTNAME %s' % hostname)
				domain = splitFQDN(fqdn)[1]
				log.debug ('[Payload] - DOMAIN %s' % domain)
				
			else:
			
				log.info ('[Payload] - Using INSTANCE as hostname {} and appending (-d) domain {} '.format(hostname, options.domain))
				log.debug ('[Payload] - HOSTNAME %s' % hostname)
				domain = options.domain
				log.debug ('[Payload] - DOMAIN %s' % options.domain)
				fqdn = hostname + '.' + options.domain
				log.debug ('[Payload] - FQDN %s'  % fqdn)
				
			if event_type == EVENT_CREATE:
			
				for temp in jbody['payload']['fixed_ips']:
					addr = temp['address']
					addr = ipaddress.ip_address(unicode(addr))
					log.info ('[Instance Create] - Adding for Fixed_IP IPv{} Address: {} DNS RRs'.format(addr.version, addr))
					addFWD(fqdn,options.ttl, addr)
					addREV(addr,options.ttl, fqdn)
					log.info('[Instance Create] - Completed Update')
		
			elif event_type == EVENT_DELETE:
				# Remove PTRs first, resolves the FQDN to the IPs to have PTRs removed
				log.info('[Instance Delete] - Deleting A/AAAA RRs for {} '.format(fqdn))
				
				resA = resolveA(fqdn)
				if resA is not None:
					for ip in resA: 
						log.info ('[Instance Delete] - Deleting PTR for {} {}'.format(ip,fqdn))
						delREV(ip)
				elif resA is None:
					log.debug ("Exception removing...")
				log.debug ('[Instance Delete] - Removed PTRs for A')
				
				resAAAA = resolveAAAA(fqdn)
				if resAAAA is not None:
					for ip in resAAAA:
						log.info ('[Instance Delete] - Deleting PTR for {} {}'.format(ip,fqdn))
						delREV(ip)
				elif resAAAA is None:
					log.debug ("Exception removing...")
				log.debug ('[Instance Delete] - Removed PTRs for AAAA')
				
				# Now remove the forward A/AAAA records
				delFWD(fqdn)
				log.info('[Instance Delete] - Completed Update')
		
			elif event_type == EVENT_UPDATE:
				log.debug ('[Instance Update]...')
				
				
if __name__ == "__main__":
	log.info("BlueCat Nova Monitor - %s Bluecat Networks 2017" % version)
	log.info("- Sending RFC2136 Dynamic DNS updates to DNS: %s" % options.nameserver)
	log.info("- Debugging Logging to %s" % options.logfile)
	log.info("- Dynamic TTL for Records: %s" % options.ttl)
	log.info("- Override Domain: %s" % options.domain)
	log.info("Connecting to broker {}".format(BROKER_URI))
	with BrokerConnection(BROKER_URI) as connection:
		try:
			print(connection)
			BCUpdater(connection).run()
		except KeyboardInterrupt:
			print(' - Exiting BlueCat Nova Monitor ....')


