#!/usr/bin/env python

import sys
from oslo_config import cfg
from neutron.common import config as common_config
from oslo_service import service
import oslo_messaging as om
from pprint import pprint

bluecat_neutron_parameters = [
    cfg.StrOpt('bam_api_user', default=None, help=("BlueCat Address Manager API User")),
    cfg.StrOpt('bam_api_pass', default=None, help=("BlueCat Address Manager API Password")),
    cfg.StrOpt('bam_config_name', default=None, help=("BlueCat Configuration")),
    cfg.StrOpt('bam_ipv4_public_block', default=None, help=("BlueCat IPv4 Public Block")),
    cfg.StrOpt('bam_ipv4_private_block', default=None, help=("BlueCat IPv4 Private Block")),
    cfg.StrOpt('bam_ipv4_private_network', default=None, help=("BlueCat IPv4 Private Network")),
    cfg.StrOpt('bam_ipv4_private_iprange_startip', default=None, help=("BlueCat IPv4 Private IP Range Start IP")),
    cfg.StrOpt('bam_ipv4_private_iprange_endip', default=None, help=("BlueCat IPv4 Private IP Range End IP")),
    cfg.StrOpt('bam_ipv4_private_iprange_gw', default=None, help=("BlueCat IPv4 Private IP Range Gateway")),
    cfg.StrOpt('bam_ipv6_public_block', default=None, help=("BlueCat IPv6 Public Block")),
    cfg.StrOpt('bam_ipv6_private_block', default=None, help=("BlueCat IPv6 Private Block")),
    cfg.StrOpt('bam_dns_zone', default=None, help=("BlueCat DNS Zone")),
    cfg.StrOpt('bam_updatemodify_networks', default=True, help=("BlueCat Update/Modify Networks Policy")),
    cfg.StrOpt('bcn_neutron_transport_url', default=None, help=("BlueCat Neutron Monitor Transport URL")),
    cfg.StrOpt('bcn_neutron_nameserver', default=None, help=("BlueCat Neutron Monitor NameServer")),
    cfg.StrOpt('bcn_neutron_logfile', default=None, help=("BlueCat Neutron Monitor LogFile")),
    cfg.StrOpt('bcn_neutron_ttl', default=None, help=("BlueCat Neutron Monitor TTL")),
    cfg.StrOpt('bcn_neutron_domain_override', default=None, help=("BlueCat Neutron Monitor Domain Overide")),
    cfg.StrOpt('bcn_neutron_debuglevel', default="INFO", help=("BlueCat Neutron Monitor Debug Level")),
    cfg.DictOpt('bcn_neutron_TSIG', default=None, help=("BlueCat Neutron TSIG")),
    cfg.StrOpt('bcn_neutron_replace', default=None, help=("BlueCat Neutron Monitor Replace Policy"))]

bluecat_nova_parameters = [
    cfg.StrOpt('bcn_nova_transport_url', default=None, help=("BlueCat Nova Monitor Transport URL")),
    cfg.StrOpt('bcn_nova_nameserver', default=None, help=("BlueCat Nova Monitor NameServer")),
    cfg.StrOpt('bcn_nova_logfile', default=None, help=("BlueCat Nova Monitor Logfile")),
    cfg.StrOpt('bcn_nova_ttl', default=None, help=("BlueCat Nova Monitor TTL")),
    cfg.StrOpt('bcn_nova_domain_override', default=None, help=("BlueCat Nova Monitor Domain Override")),
    cfg.DictOpt('bcn_nova_TSIG', default=None, help=("BlueCat Nova TSIG")),
    cfg.StrOpt('bcn_nova_debuglevel', default="INFO", help=("BlueCat Nova Monitor Debug Level"))]

bluecat_group = cfg.OptGroup(name='bluecat',title='Bluecat Group')

def config_parser(conf,list):
	CONF = cfg.CONF
	CONF.register_group(bluecat_group)
	CONF.register_opts(list, "bluecat")
	CONF(default_config_files=conf)
	return CONF

NEUTRON_CONF=config_parser(['/etc/neutron/neutron.conf'],bluecat_neutron_parameters)

bam_api_user = NEUTRON_CONF.bluecat.bam_api_user
bam_api_pass = NEUTRON_CONF.bluecat.bam_api_pass
bam_config_name = NEUTRON_CONF.bluecat.bam_config_name
bam_ipv4_public_block = NEUTRON_CONF.bluecat.bam_ipv4_public_block
bam_ipv4_private_block = NEUTRON_CONF.bluecat.bam_ipv4_private_block
bam_ipv4_private_network = NEUTRON_CONF.bluecat.bam_ipv4_private_network
bam_ipv4_private_iprange_startip = NEUTRON_CONF.bluecat.bam_ipv4_private_iprange_startip
bam_ipv4_private_iprange_endip = NEUTRON_CONF.bluecat.bam_ipv4_private_iprange_endip
bam_ipv4_private_iprange_gw = NEUTRON_CONF.bluecat.bam_ipv4_private_iprange_gw
bam_ipv6_public_block = NEUTRON_CONF.bluecat.bam_ipv6_public_block
bam_ipv6_private_block = NEUTRON_CONF.bluecat.bam_ipv6_private_block
bam_dns_zone = NEUTRON_CONF.bluecat.bam_dns_zone
bam_updatemodify_networks = NEUTRON_CONF.bluecat.bam_updatemodify_networks

bcn_neutron_transport_url = NEUTRON_CONF.bluecat.bcn_neutron_transport_url
bcn_neutron_nameserver = NEUTRON_CONF.bluecat.bcn_neutron_nameserver
bcn_neutron_logfile = NEUTRON_CONF.bluecat.bcn_neutron_logfile
bcn_neutron_ttl = NEUTRON_CONF.bluecat.bcn_neutron_ttl
bcn_neutron_domain_override = NEUTRON_CONF.bluecat.bcn_neutron_domain_override
bcn_neutron_debuglevel = NEUTRON_CONF.bluecat.bcn_neutron_debuglevel
bcn_neutron_replace = NEUTRON_CONF.bluecat.bcn_neutron_replace
bcn_neutron_TSIG = NEUTRON_CONF.bluecat.bcn_neutron_TSIG


ipam_driver = NEUTRON_CONF.ipam_driver
#transport_url = NEUTRON_CONF.transport_url

NOVA_CONF=config_parser(['/etc/nova/nova.conf'],bluecat_nova_parameters)

bcn_nova_transport_url = NOVA_CONF.bluecat.bcn_nova_transport_url
bcn_nova_nameserver = NOVA_CONF.bluecat.bcn_nova_nameserver
bcn_nova_logfile = NOVA_CONF.bluecat.bcn_nova_logfile
bcn_nova_ttl = NOVA_CONF.bluecat.bcn_nova_ttl
bcn_nova_domain_override = NOVA_CONF.bluecat.bcn_nova_domain_override
bcn_nova_debuglevel = NOVA_CONF.bluecat.bcn_nova_debuglevel
bcn_nova_TSIG = NOVA_CONF.bluecat.bcn_nova_TSIG

#transport_url = NOVA_CONF.transport_url

print "NEUTRON.CONF"
print "[DEFAULT]"
print "Neutron IPAM Driver:\033[0;32m %s \033[1;m" % ipam_driver
print ""

print "[BLUECAT]"
print "BlueCat Address Manager API User:\033[0;32m  %s \033[1;m" % bam_api_user
print "BlueCat Address Manager API Password:\033[0;32m %s \033[1;m" % bam_api_pass
print "BlueCat Configuration Name:\033[0;32m %s \033[1;m" % bam_config_name
print "BlueCat IPv4 Public Block:\033[0;32m %s \033[1;m" % bam_ipv4_public_block
print "BlueCat IPv4 Private Block:\033[0;32m %s \033[1;m" % bam_ipv4_private_block
print "BlueCat IPv4 Private Network:\033[0;32m %s \033[1;m" % bam_ipv4_private_network
print "BlueCat IPv4 Private Range Start IP:\033[0;32m %s \033[1;m" % bam_ipv4_private_iprange_startip
print "BlueCat IPv4 Private Range End IP:\033[0;32m %s \033[1;m" % bam_ipv4_private_iprange_endip
print "BlueCat IPv4 Private Range Gateway:\033[0;32m %s \033[1;m" % bam_ipv4_private_iprange_gw
print "BlueCat IPv6 Public Block:\033[0;32m %s \033[1;m" % bam_ipv6_public_block
print "BlueCat IPv6 Private Block:\033[0;32m %s \033[1;m" % bam_ipv6_private_block
print "BlueCat DNS Zone:\033[0;32m %s \033[1;m" % bam_dns_zone
print "BlueCat Update/Modify Network Policy:\033[0;32m %s \033[1;m" % bam_updatemodify_networks
print "BlueCat Neutron Monitor Transport URL:\033[0;32m %s \033[1;m" % bcn_neutron_transport_url
print "BlueCat Neutron Monitor Name ServerL:\033[0;32m %s \033[1;m" % bcn_neutron_nameserver
print "BlueCat Neutron Monitor Logfile:\033[0;32m %s \033[1;m" % bcn_neutron_logfile
print "BlueCat Neutron Monitor TTL:\033[0;32m %s \033[1;m" % bcn_neutron_ttl
print "BlueCat Neutron Monitor Domain Override:\033[0;32m %s \033[1;m" % bcn_neutron_domain_override
print "BlueCat Neutron Monitor Debug Level:\033[0;32m %s \033[1;m" % bcn_neutron_debuglevel
print "BlueCat Neutron Monitor Replace Policy:\033[0;32m %s \033[1;m" % bcn_neutron_replace
print "BlueCat Neutron TSIG Keys: Policy:\033[0;32m %s \033[1;m" %bcn_neutron_TSIG
print ""
print "NOVA.CONF"
print "[BLUECAT]"
print "BlueCat Nova Monitor Transport URL:\033[0;32m %s \033[1;m" % bcn_nova_transport_url
print "BlueCat Nova Monitor Name ServerL:\033[0;32m %s \033[1;m" % bcn_nova_nameserver
print "BlueCat Nova Logfile:\033[0;32m %s \033[1;m" % bcn_nova_logfile
print "BlueCat Nova Monitor TTL:\033[0;32m %s \033[1;m" % bcn_nova_ttl
print "BlueCat Nova Monitor Domain Override:\033[0;32m %s \033[1;m" % bcn_nova_domain_override
print "BlueCat Nova Monitor Debug Level:\033[0;32m %s \033[1;m" % bcn_nova_debuglevel
print "BlueCat Nova TSIG Keys: \033[0;32m %s \033[1;m" %bcn_nova_TSIG
print ""

print "Domains which have TSIG keys:"
if bcn_nova_TSIG.keys():
	securedomains = bcn_nova_TSIG.keys()
	for i in range(len(securedomains)):
		print "Domain: \033[0;32m %s \033[1;m" %(securedomains[i])
		print "Key: \033[0;32m %s \033[1;m" %(bcn_nova_TSIG[securedomains[i]])


