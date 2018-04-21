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

# BlueCat Nova Monitor listens on the AMQP message bus of Openstack.
# Whenever a nova notification message is seen for a compute instance create or delete
# an RFC2136 DDNS update is sent to the Bluecat DNS defined which updates the A/AAAA and PTR records
# The bluecat DNS server will forward a notify onto the Bluecat address managed to update the Host Record
# added by the Blue Neutron driver (which updates the BAM using the UUID (not hostname)

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
import sys, optparse
import json
import logging as log
import sys
from kombu import BrokerConnection
from kombu import Exchange
from kombu import Queue
from kombu.mixins import ConsumerMixin


import sys
from oslo_config import cfg
from oslo_service import service
import oslo_messaging

bluecat_nova_parameters = [
    cfg.StrOpt('bcn_nova_transport_url', default=None, help=("BlueCat Nova Monitor Transport URL")),
    cfg.StrOpt('bcn_nova_nameserver', default=None, help=("BlueCat Nova Monitor NameServer")),
    cfg.StrOpt('bcn_nova_logfile', default=None, help=("BlueCat Nova Monitor Logfile")),
    cfg.StrOpt('bcn_nova_ttl', default=666, help=("BlueCat Nova Monitor TTL")),
    cfg.StrOpt('bcn_nova_domain_override', default=False, help=("BlueCat Nova Monitor Domain Override")),
    cfg.DictOpt('bcn_nova_TSIG', default=None, help=("BlueCat Nova TSIG")),
    cfg.StrOpt('bcn_nova_debuglevel', default="INFO", help=("BlueCat Nova Monitor Debug Level"))]

version = 1.1
EXCHANGE_NAME="nova"
ROUTING_KEY="notifications.info"
QUEUE_NAME="bluecat_nova_monitor"
EVENT_CREATE="compute.instance.create.end"
EVENT_DELETE="compute.instance.delete.start"
EVENT_UPDATE="compute.instance.update"
ADDITIONAL_RDCLASS = 65535

bluecat_group = cfg.OptGroup(name='bluecat',title='Bluecat Group')

def config_parser(conf,list):
	CONF = cfg.CONF
	CONF.register_group(bluecat_group)
	CONF.register_opts(list, "bluecat")
	CONF(default_config_files=conf)
	return CONF

# read in settings from nova.conf

NOVA_CONF=config_parser(['/etc/nova/nova.conf'],bluecat_nova_parameters)

monitor_broker = NOVA_CONF.bluecat.bcn_nova_transport_url
monitor_nameserver = NOVA_CONF.bluecat.bcn_nova_nameserver
monitor_logfile = NOVA_CONF.bluecat.bcn_nova_logfile
monitor_ttl = NOVA_CONF.bluecat.bcn_nova_ttl
monitor_domain_override = NOVA_CONF.bluecat.bcn_nova_domain_override
monitor_debuglevel = NOVA_CONF.bluecat.bcn_nova_debuglevel
monitor_TSIG = bcn_nova_TSIG = NOVA_CONF.bluecat.bcn_nova_TSIG

print 'BlueCat Nova Monitor Transport URL = ',monitor_broker
print 'BlueCat Nova Monitor NameServer =',monitor_nameserver
print 'BlueCat Nova Monitor Logfile =',monitor_logfile
print 'BlueCat Nova Monitor Debug Level = ',monitor_debuglevel
print 'BlueCat Nova Monitor TTL =',monitor_ttl
print 'BlueCat Nova Monitor Domain Override = ',monitor_domain_override
print "BlueCat Secure Domains which have TSIG keys:"
if bcn_nova_TSIG.keys():
	novasecuredomains = bcn_nova_TSIG.keys()
	for i in range(len(novasecuredomains)):
		print "Domain: \033[0;32m %s \033[1;m" %(novasecuredomains[i])
		print "TSIG Key: \033[0;32m %s \033[1;m" %(bcn_nova_TSIG[novasecuredomains[i]])

# # read from nova.conf [bluecat] settings parameters bcn_nova_debuglevel and bcn_nova_logfile
log.basicConfig(filename=monitor_logfile, level=monitor_debuglevel, format='%(asctime)s %(message)s')

class TSIGSecured():
        TSIGKey=""
        domains = bcn_nova_TSIG.keys()

        def __init__(self, domain):
                self.domain = domain

        def TSIG(self,domain):
                self.domain = domain
                if domain in TSIGSecured.domains:
                        # print "TSIG \033[0;32m %s \033[1;m" % bcn_nova_TSIG[domain]
                        return bcn_nova_TSIG[domain]
                else:
                        # print "No TSIG"
                        return

        def isSecure(self,domain):
                self.domain = domain
                if domain in TSIGSecured.domains:
                        #print "Domain \033[0;32m %s \033[1;m has TSIG Key (TRUE)" % self.domain
                        return True
                else:
                        #print "Domain \033[0;32m %s \033[1;m has no TSIG Key (FALSE)" % self.domain
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
	check4TSIG = TSIGSecured(authdomain)
	if check4TSIG.isSecure(authdomain):
		log.debug ('[addREV] - domain has TSIG key defined %s' % check4TSIG.TSIG(authdomain))
		keyring = dns.tsigkeyring.from_text(check4TSIG.TSIG(authdomain))
		update = dns.update.Update(authdomain, keyring=keyring)
	else:
		log.debug ('[addREV] - domain %s has no TSIG key defined ' % authdomain)
		update = dns.update.Update(authdomain)
	update.replace(label,monitor_ttl,dns.rdatatype.PTR, name)
	response = dns.query.tcp(update, monitor_nameserver)
	return response

# Delete PTR record for a passed address
def delREV(ipaddress):
	reversedomain = dns.reversename.from_address(str(ipaddress))
	reversedomain = str(reversedomain).rstrip('.')
	log.debug ('[delREV] - reversedomain  %s' % reversedomain)
	authdomain = getrevzone_auth(str(reversedomain)).rstrip('.')
	log.debug ('[delREV] - authdomain  %s' % authdomain)
	check4TSIG = TSIGSecured(authdomain)
	if check4TSIG.isSecure(authdomain):
		log.debug ('[delREV] - domain has TSIG key defined %s' % check4TSIG.TSIG(authdomain))
		keyring = dns.tsigkeyring.from_text(check4TSIG.TSIG(authdomain))
		update = dns.update.Update(authdomain, keyring=keyring)
	else:
		log.debug ('[delREV] - domain %s has no TSIG key defined ' % authdomain)
		update = dns.update.Update(authdomain)
	label = stripptr(authdomain, reversedomain)
	log.debug ('[delREV] - label  %s' % label)
	update.delete(label,'PTR')
	response = dns.query.tcp(update, monitor_nameserver)
	return response

# add A/AAAA record
def addFWD(name,ttl,ipaddress):
	ipaddress = str(ipaddress)
	hostname = splitFQDN(name)[0]
	log.debug ('[addFWD] - hostname %s' % hostname)
	log.debug ('[addFWD] - domain %s' % splitFQDN(name)[1])
	domain = splitFQDN(name)[1]
	check4TSIG = TSIGSecured(domain)
	if check4TSIG.isSecure(domain):
		log.debug ('[addFWD] - domain has TSIG key defined %s' % check4TSIG.TSIG(domain))
		key = str(check4TSIG.TSIG(domain))
		keyname = domain.replace(".","_")
		log.debug ('[addFWD] - expected TSIG key name in BAM %s' % keyname)
		keyring = dns.tsigkeyring.from_text({keyname:key})
		update = dns.update.Update(splitFQDN(name)[1], keyring=keyring)
	else:
		log.debug ('[addFWD] - domain %s has no TSIG key defined ' % domain)
		update = dns.update.Update(splitFQDN(name)[1])
	address_type = enumIPtype(ipaddress)
        if address_type == 4:
		log.debug ('[addFWD] - IPv4')
		update.add(hostname,monitor_ttl,dns.rdatatype.A, ipaddress)
	elif address_type == 6:
		log.debug ('[addFWD] - IPv6')
		update.add(hostname,monitor_ttl,dns.rdatatype.AAAA, ipaddress)
	response = dns.query.udp(update, monitor_nameserver)
	return response

# Delete record from name
def delFWD(name):
	name = str(name)
	hostname = splitFQDN(name)[0]
	domain = splitFQDN(name)[1]
	log.debug ('[delFWD] - hostname %s' % hostname)
	log.debug ('[delFWD] - domainname %s' % domain)
	check4TSIG = TSIGSecured(domain)
	if check4TSIG.isSecure(domain):
		log.debug ('[delFWD] - domain has TSIG key defined %s' % check4TSIG.TSIG(domain))
		key = str(check4TSIG.TSIG(domain))
		keyname = domain.replace(".","_")
		log.debug ('[delFWD] - expected TSIG key name in BAM %s' % keyname)
		keyring = dns.tsigkeyring.from_text({keyname:key})
		update = dns.update.Update(splitFQDN(name)[1], keyring=keyring)
	else:
		log.debug ('[delFWD] - domain %s has no TSIG key defined ' % domain)
        update = dns.update.Update(splitFQDN(name)[1])
	update.delete(hostname, 'A')
	update.delete(hostname, 'AAAA')
	response = dns.query.tcp(update, monitor_nameserver)
	return response

# Resolve A record from name, returns address
def resolveA(name):
	myResolver = dns.resolver.Resolver()
	myResolver.nameservers = [monitor_nameserver]
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
	myResolver.nameservers = [monitor_nameserver]
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

# Message handler extracts event_type, hostname, addresses etc. from payload
    def _handle_message(self, body):
		log.debug('Body: %r' % body)
		jbody = json.loads(body['oslo.message'])
		event_type = jbody['event_type']
		log.info ('Event Type :- %s' % event_type)

		if event_type in [EVENT_CREATE, EVENT_DELETE]:
			hostname = jbody['payload']['hostname']

			if monitor_domain_override == "False":
				log.info ('[Payload] - Using INSTANCE as FQDN')
				log.debug ('[Payload] - INSTANCE %s' % hostname)
				fqdn = hostname
				log.debug ('[Payload] - FQDN %s'  % fqdn)
				hostname = splitFQDN(fqdn)[0]
				log.debug ('[Payload] - HOSTNAME %s' % hostname)
				domain = splitFQDN(fqdn)[1]
				log.debug ('[Payload] - DOMAIN %s' % domain)

			else:

				log.info ('[Payload] - Using INSTANCE as hostname {} and appending (-d) domain {} '.format(hostname, monitor_domain_override))
				log.debug ('[Payload] - HOSTNAME %s' % hostname)
				domain = monitor_domain_override
				log.debug ('[Payload] - DOMAIN %s' % monitor_domain_override)
				fqdn = hostname + '.' + monitor_domain_override
				log.debug ('[Payload] - FQDN %s'  % fqdn)

			if event_type == EVENT_CREATE:

				for temp in jbody['payload']['fixed_ips']:
					addr = temp['address']
					addr = ipaddress.ip_address(unicode(addr))
					log.info ('[Instance Create] - Adding for Fixed_IP IPv{} Address: {} DNS RRs'.format(addr.version, addr))
					addFWD(fqdn,monitor_ttl, addr)
					addREV(addr,monitor_ttl, fqdn)
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

    log.info("BlueCat Nova Monitor - %s Bluecat Networks 2018" % version)
    log.info("- Transport URL: %s" % monitor_broker)
    log.info("- Sending RFC2136 Dynamic DNS updates to DNS: %s" % monitor_nameserver)
    log.info("- Debugging Logging to %s" % monitor_logfile)
    log.info("- Debug Log Level: %s" % monitor_debuglevel)
    log.info("- Dynamic TTL for Records: %s" % monitor_ttl)
    log.info("- Override Domain: %s" % monitor_domain_override)

    with BrokerConnection(monitor_broker) as connection:
		try:
			print(connection)
			BCUpdater(connection).run()
		except KeyboardInterrupt:
			print(' - Exiting BlueCat Nova Monitor ....')
