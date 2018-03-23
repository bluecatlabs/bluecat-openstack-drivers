# Copyright 2015 OpenStack LLC.
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

# DH
# V0.11  20171127
# V0.12  20180307	- Removed hardcoded configuration reference.
#					- Added flag to toggle updates/deletion of networks in BAM
# Pike_V0.13  20180314	- Moved BlueCat config options to a config file.
# Pike_V0.14  20180323	-Resolved issue with undefined variable 'bam_updatemodify_networks' in update subnet().

import itertools
import random

import netaddr
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils

from neutron._i18n import _, _LE
from neutron.ipam import driver as ipam_base
from neutron.ipam.drivers.neutrondb_ipam import db_api as ipam_db_api
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron.ipam import utils as ipam_utils

# DMH
from inspect import getmembers
from pprint import pprint
import httplib
from suds.client import Client
from suds import WebFault
from suds.transport.http import HttpAuthenticated
from pip._vendor.ipaddress import ip_address
from configparser import ConfigParser

LOG = log.getLogger(__name__)


BC_configFileName="/opt/stack/neutron/neutron/ipam/drivers/neutrondb_ipam/driver.ini"


   
    
class NeutronDbSubnet(ipam_base.Subnet):
    """Manage IP addresses for Neutron DB IPAM driver.

    This class implements the strategy for IP address allocation and
    deallocation for the Neutron DB IPAM driver.
    """

    @classmethod
    def create_allocation_pools(cls, subnet_manager, context, pools, cidr):
        for pool in pools:
            # IPv6 addresses that start '::1', '::2', etc cause IP version
            # ambiguity when converted to integers by pool.first and pool.last.
            # Infer the IP version from the subnet cidr.
            ip_version = cidr.version
            subnet_manager.create_pool(
                context,
                netaddr.IPAddress(pool.first, ip_version).format(),
                netaddr.IPAddress(pool.last, ip_version).format())

    @classmethod
    def create_from_subnet_request(cls, subnet_request, ctx):
        ipam_subnet_id = uuidutils.generate_uuid()
        subnet_manager = ipam_db_api.IpamSubnetManager(
            ipam_subnet_id,
            subnet_request.subnet_id)
        # Create subnet resource
        subnet_manager.create(ctx)
        # If allocation pools are not specified, define them around
        # the subnet's gateway IP
        if not subnet_request.allocation_pools:
            pools = ipam_utils.generate_pools(subnet_request.subnet_cidr,
                                              subnet_request.gateway_ip)
        else:
            pools = subnet_request.allocation_pools
        # Create IPAM allocation pools
        cls.create_allocation_pools(subnet_manager, ctx, pools,
                                    subnet_request.subnet_cidr)

        return cls(ipam_subnet_id,
                   ctx,
                   cidr=subnet_request.subnet_cidr,
                   allocation_pools=pools,
                   gateway_ip=subnet_request.gateway_ip,
                   tenant_id=subnet_request.tenant_id,
                   subnet_id=subnet_request.subnet_id)

    @classmethod
    def load(cls, neutron_subnet_id, ctx):
        """Load an IPAM subnet from the database given its neutron ID.

        :param neutron_subnet_id: neutron subnet identifier.
        """
        ipam_subnet = ipam_db_api.IpamSubnetManager.load_by_neutron_subnet_id(
            ctx, neutron_subnet_id)
        if not ipam_subnet:
            LOG.error(_LE("BCN: IPAM subnet referenced to "
                          "Neutron subnet %s does not exist"),
                      neutron_subnet_id)
            raise n_exc.SubnetNotFound(subnet_id=neutron_subnet_id)
        pools = []
        for pool in ipam_subnet.allocation_pools:
            pools.append(netaddr.IPRange(pool['first_ip'], pool['last_ip']))

        neutron_subnet = cls._fetch_subnet(ctx, neutron_subnet_id)

        return cls(ipam_subnet['id'],
                   ctx,
                   cidr=neutron_subnet['cidr'],
                   allocation_pools=pools,
                   gateway_ip=neutron_subnet['gateway_ip'],
                   tenant_id=neutron_subnet['tenant_id'],
                   subnet_id=neutron_subnet_id)

    @classmethod
    def _fetch_subnet(cls, context, id):
        plugin = directory.get_plugin()
        return plugin._get_subnet(context, id)

    def __init__(self, internal_id, ctx, cidr=None,
                 allocation_pools=None, gateway_ip=None, tenant_id=None,
                 subnet_id=None):
        # NOTE: In theory it could have been possible to grant the IPAM
        # driver direct access to the database. While this is possible,
        # it would have led to duplicate code and/or non-trivial
        # refactorings in neutron.db.db_base_plugin_v2.
        # This is because in the Neutron V2 plugin logic DB management is
        # encapsulated within the plugin.
        self._cidr = cidr
        self._pools = allocation_pools
        self._gateway_ip = gateway_ip
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self.subnet_manager = ipam_db_api.IpamSubnetManager(internal_id,
                                                            self._subnet_id)
        self._context = ctx
        
        

    def _verify_ip(self, context, ip_address):
        """Verify whether IP address can be allocated on subnet.

        :param context: neutron api request context
        :param ip_address: String representing the IP address to verify
        :raises: InvalidInput, IpAddressAlreadyAllocated
        """
        # Ensure that the IP's are unique
        if not self.subnet_manager.check_unique_allocation(context,
                                                           ip_address):
            raise ipam_exc.IpAddressAlreadyAllocated(
                subnet_id=self.subnet_manager.neutron_id,
                ip=ip_address)

        # Ensure that the IP is valid on the subnet
        if not ipam_utils.check_subnet_ip(self._cidr, ip_address):
            raise ipam_exc.InvalidIpForSubnet(
                subnet_id=self.subnet_manager.neutron_id,
                ip=ip_address)


    def _generate_ip(self, context, prefer_next=False):
        """Generate an IP address from the set of available addresses."""
        ip_allocations = netaddr.IPSet()
        for ipallocation in self.subnet_manager.list_allocations(context):
            ip_allocations.add(ipallocation.ip_address)

        for ip_pool in self.subnet_manager.list_pools(context):
            ip_set = netaddr.IPSet()
            ip_set.add(netaddr.IPRange(ip_pool.first_ip, ip_pool.last_ip))
            av_set = ip_set.difference(ip_allocations)
            if av_set.size == 0:
                continue

            if prefer_next:
                window = 1
            else:
                # Compute a value for the selection window
                window = min(av_set.size, 10)
            ip_index = random.randint(1, window)
            candidate_ips = list(itertools.islice(av_set, ip_index))
            allocated_ip = candidate_ips[-1]
            return str(allocated_ip), ip_pool.id

        raise ipam_exc.IpAddressGenerationFailure(
                  subnet_id=self.subnet_manager.neutron_id)


    def allocate(self, address_request):
        # NOTE(pbondar): Ipam driver is always called in context of already
        # running transaction, which is started on create_port or upper level.
        # To be able to do rollback/retry actions correctly ipam driver
        # should not create new nested transaction blocks.
        all_pool_id = None
        # NOTE(salv-orlando): It would probably better to have a simpler
        # model for address requests and just check whether there is a
        # specific IP address specified in address_request
        if isinstance(address_request, ipam_req.SpecificAddressRequest):
            # This handles both specific and automatic address requests
            # Check availability of requested IP
            ip_address = str(address_request.address)
 
            self._verify_ip(self._context, ip_address)
        else:
            prefer_next = isinstance(address_request,
                                     ipam_req.PreferNextAddressRequest)
            ip_address, all_pool_id = self._generate_ip(self._context,
                                                        prefer_next)

        # Create IP allocation request object
        # The only defined status at this stage is 'ALLOCATED'.
        # More states will be available in the future - e.g.: RECYCLABLE
        try:
            with self._context.session.begin(subtransactions=True):
                # NOTE(kevinbenton): we use a subtransaction to force
                # a flush here so we can capture DBReferenceErrors due
                # to concurrent subnet deletions. (galera would deadlock
                # later on final commit)
                self.subnet_manager.create_allocation(self._context,
                                                      ip_address)
        except db_exc.DBReferenceError:
            raise n_exc.SubnetNotFound(
                subnet_id=self.subnet_manager.neutron_id)

        ipObj = netaddr.IPAddress(ip_address)
        
        # BlueCat additions
        paramsBAM = getBCNConfig(BC_configFileName, "BAM")
        
        soap_client = _bam_login(paramsBAM)
        configID = _get_bam_configid(paramsBAM, soap_client)

        LOG.info("BCN: Creating host %s in BAM  ..." % (ip_address))

        if hasattr(address_request, 'port_name') :
            hostName = address_request.port_name
            LOG.info("BCN: Hostname is %s" % (hostName))
        else:
            LOG.info("BCN: port_name not set in request...")
            if ipObj.version == 4:
                hostName = "ip-"
                hostName += ip_address.replace('.', "-")
            else:
                hostName = "ip-"
                hostName += ip_address.replace(':', "-")

        id = ""
        if hasattr(address_request, "id"):
                id = address_request.id

        mac = ""
        if hasattr(address_request, "mac_address"):
                mac = address_request.mac_address

        if ipObj.version == 4:
            createBCIP4Obj(ip_address, hostName, id, mac, configID, soap_client)
        else:
            createBCPI6Obj(ip_address, hostName, id, mac, configID, soap_client)        

        _bam_logout(paramsBAM, soap_client)
        return ip_address


    def deallocate(self, address):
        # This is almost a no-op because the Neutron DB IPAM driver does not
        # delete IPAllocation objects at every deallocation. The only
        # operation it performs is to delete an IPRequest entry.
        count = self.subnet_manager.delete_allocation(
            self._context, address)
        # count can hardly be greater than 1, but it can be 0...
        if not count:
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self.subnet_manager.neutron_id,
                ip_address=address)

        ipObj = netaddr.IPAddress(address)
        
        # BlueCat additions
        LOG.info("BCN: Deallocating IP address %s" % (address))
        
        paramsBAM = getBCNConfig(BC_configFileName, "BAM")
        soap_client = _bam_login(paramsBAM)
        configID = _get_bam_configid(paramsBAM, soap_client)
    
        LOG.info("BCN: Deleting host %s from BAM ..." % (address))
        if ipObj.version == 4:
                delBCIP4Obj(address, configID, soap_client)
        else:
                delBCIP6Obj(address, configID, soap_client)
    
        _bam_logout(paramsBAM, soap_client)


    def _no_pool_changes(self, context, pools):
        """Check if pool updates in db are required."""
        db_pools = self.subnet_manager.list_pools(context)
        iprange_pools = [netaddr.IPRange(pool.first_ip, pool.last_ip)
                         for pool in db_pools]
        return pools == iprange_pools

    def update_allocation_pools(self, pools, cidr):
        # Pools have already been validated in the subnet request object which
        # was sent to the subnet pool driver. Further validation should not be
        # required.
        if self._no_pool_changes(self._context, pools):
            return
        self.subnet_manager.delete_allocation_pools(self._context)
        self.create_allocation_pools(self.subnet_manager, self._context, pools,
                                     cidr)
        self._pools = pools

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self.subnet_manager.neutron_id,
            self._cidr, self._gateway_ip, self._pools)

    

class NeutronDbPool(subnet_alloc.SubnetAllocator):
    """Subnet pools backed by Neutron Database.

    As this driver does not implement yet the subnet pool concept, most
    operations are either trivial or no-ops.
    """

    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet.

        :param subnet_id: Neutron subnet identifier
        :returns: a NeutronDbSubnet instance
        """
        return NeutronDbSubnet.load(subnet_id, self._context)

    def allocate_subnet(self, subnet_request):
        """Create an IPAMSubnet object for the provided cidr.

        This method does not actually do any operation in the driver, given
        its simplified nature.

        :param cidr: subnet's CIDR
        :returns: a NeutronDbSubnet instance
        """

        paramsBAM = getBCNConfig(BC_configFileName, "BAM")

        if self._subnetpool:
            tmpName = subnet_request.name

            subnet = super(NeutronDbPool, self).allocate_subnet(subnet_request)
            subnet_request = subnet.get_details()

            subnet_request.name = tmpName

        # SubnetRequest must be an instance of SpecificSubnet
        if not isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))

        if not hasattr(subnet_request, '_subnet_cidr') :
            subnet_request = ipam_req.SpecificSubnetRequest(
                            subnet_request._tenant_id,
                            subnet_request._subnet_id,
                            paramsBAM['bam_ipv4_private_network'],
                            allocation_pools=[netaddr.IPRange(paramsBAM['bam_ipv4_private_iprange_startip'], paramsBAM['bam_ipv4_private_iprange_endip'])],
                            gateway_ip=paramsBAM['bam_ipv4_private_iprange_gw']
                            )
                            
        #  BlueCat additions
        soap_client = _bam_login(paramsBAM)

        config = soap_client.service.getEntityByName(0, paramsBAM['bam_config_name'], 'Configuration')
        configID = config['id']
        LOG.info("BCN: Got configID %s" % (configID))

        LOG.info("BCN: Getting ParentBlockID Info ...")

        blockType = ""
        if subnet_request._subnet_cidr.version == 4:
            blockType = "IP4Block"
        else:
            blockType = "IP6Block"

        LOG.info("BCN: blockType : %s" % (blockType))

        # This needs polishing ...
        parentBlockId = ""        
        tenNet= netaddr.IPNetwork(paramsBAM['bam_ipv4_private_block'])

        if str(subnet_request._subnet_cidr.ip) in tenNet:
            parentBlockId = apiGetBlockID( configID, paramsBAM['bam_ipv4_private_block'], blockType)
        elif str(subnet_request._subnet_cidr.version) == "6":
            IP6GlobalUni = netaddr.IPNetwork(paramsBAM['bam_ipv6_public_block'])
            IP6UniqLocal = netaddr.IPNetwork(paramsBAM['bam_ipv6_private_block'])

            if subnet_request._subnet_cidr.ip in IP6UniqLocal:
                LOG.info("BCN: Getting "+paramsBAM['bam_ipv6_private_block'] +" blockID ...")
                parentBlockId = apiGetBlockID(configID, paramsBAM['bam_ipv6_private_block'], blockType)
            elif subnet_request._subnet_cidr.ip in IP6GlobalUni:
                    LOG.info("BCN: Getting " +paramsBAM['bam_ipv6_public_block'] +"blockID ...")
                    parentBlockId = apiGetBlockID(configID, paramsBAM['bam_ipv6_public_block'], blockType)
            else:
                    LOG.error("BCN: [Error] : Unsupported IPv6 Address Range: %s"  % (subnet_request._subnet_cidr.ip))
        else:
            LOG.info("BCN: IP4Block : " +paramsBAM['bam_ipv4_public_block'])
            parentBlockId = apiGetBlockID(configID, paramsBAM['bam_ipv4_public_block'], blockType)

        LOG.info("BCN: parentBlockId = %s"  % (parentBlockId))

        cidr = str(subnet_request._subnet_cidr.ip) +"/" +str(subnet_request._subnet_cidr.prefixlen)
        LOG.info("BCN: Creating Network %s in BAM  ..." % (cidr))

        bcNetID = addBCNetwork(parentBlockId, cidr, subnet_request.name, subnet_request._subnet_id, str(subnet_request._subnet_cidr.version))

        LOG.info("BCN: Network Added, NetworkId = %s, Name = %s UUID = %s\n" % (bcNetID, subnet_request.name, subnet_request._subnet_id))
        
        _bam_logout(paramsBAM, soap_client)

        return NeutronDbSubnet.create_from_subnet_request(subnet_request,
                                                          self._context)


    def update_subnet(self, subnet_request):
        """Update subnet info the in the IPAM driver.

        The only update subnet information the driver needs to be aware of
        are allocation pools.
        """
        if not subnet_request.subnet_id:
            raise ipam_exc.InvalidSubnetRequest(
                reason=_("An identifier must be specified when updating "
                         "a subnet"))
        if subnet_request.allocation_pools is None:
            LOG.debug("Update subnet request for subnet %s did not specify "
                      "new allocation pools, there is nothing to do",
                      subnet_request.subnet_id)
            return

        subnet = NeutronDbSubnet.load(subnet_request.subnet_id, self._context)
        cidr = netaddr.IPNetwork(subnet._cidr)
        subnet.update_allocation_pools(subnet_request.allocation_pools, cidr)
        
        # BlueCat additions
        paramsBAM = getBCNConfig(BC_configFileName, "BAM")
        
        if (paramsBAM['bam_updatemodify_networks'] == "True"):        
			soap_client = _bam_login(paramsBAM)
			configID = _get_bam_configid(paramsBAM, soap_client)
			LOG.info("BCN: Got configID %s" % (configID))

			cidr = str(subnet_request._subnet_cidr.ip) +"/" +str(subnet_request._subnet_cidr.prefixlen)

			LOG.info("BCN: Updating Network %s %s in BAM  ...\n" % (cidr, subnet_request.name))

			updateBCNetwork(soap_client, configID, cidr, subnet_request.name, subnet_request.subnet_id)
			_bam_logout(paramsBAM, soap_client)
        
        return subnet


    def remove_subnet(self, subnet_id):
        """Remove data structures for a given subnet.

        IPAM-related data has no foreign key relationships to neutron subnet,
        so removing ipam subnet manually
        """

        count = ipam_db_api.IpamSubnetManager.delete(self._context,
                                                     subnet_id)
        if count < 1:
            LOG.error(_LE("BCN: IPAM subnet referenced to "
                          "Neutron subnet %s does not exist"),
                      subnet_id)
            raise n_exc.SubnetNotFound(subnet_id=subnet_id)
            
        # BlueCat additions
        paramsBAM = getBCNConfig(BC_configFileName, "BAM")
            
        if (paramsBAM['bam_updatemodify_networks'] == "True"):    
			soap_client = _bam_login(paramsBAM)
			configID = _get_bam_configid(paramsBAM, soap_client)
			LOG.info("BCN: Got configID %s" % (configID))

			LOG.info("BCN: Removing Network %s from BAM  ...\n" % (subnet_id))

			delBCNetwork(configID, subnet_id)
			_bam_logout(paramsBAM, soap_client)


    def needs_rollback(self):
        return False


# ----------------------- Bluecat API Routines ------------------

    
    
    #----------- getItemsFromResponse
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


#----------- getValueFromDataStr
def getValueFromDataStr(dataStr, counter):

    data = dataStr[0]
    fields = data.split(':')
    value = fields[1]
    return(value)
    

def _bam_login(paramsBAM):
   LOG.info("BCN: Connecting to BAM at %s ..." % paramsBAM['bam_address'] )
   soap_client = Client('http://%s/Services/API?wsdl' % paramsBAM['bam_address'])
   soap_client.service.login(paramsBAM['bam_api_user'], paramsBAM['bam_api_pass'])
   return soap_client


def _bam_logout(paramsBAM, soap_client):
   LOG.info("BCN: Disconnecting from BAM at %s ..." % paramsBAM['bam_address'] )
   soap_client.service.logout()


def _get_bam_configid(paramsBAM, soap_client):
   config = soap_client.service.getEntityByName(0, paramsBAM['bam_config_name'], 'Configuration')
   configID = long(config['id'])
   LOG.info("BCN: Got configID %d" % (configID))
   return configID


def getBCNConfig(configFileName, section):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(configFileName)
 
    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, configFileName))
 
    return db
    
    
#----------- apiGetBlockID
def apiGetBlockID(parentID, cidr, blockType):

    fields = cidr.split('/')
    addr = fields[0]
    mask = fields[1]    
    
    paramsBAM = getBCNConfig(BC_configFileName, "BAM")
    soap_client = _bam_login(paramsBAM)
    configID = _get_bam_configid(paramsBAM, soap_client)

    parent = soap_client.service.getIPRangedByIP ( configID, blockType, addr)
    id = parent['id']  
    _bam_logout(paramsBAM, soap_client)

    return(id)



def addBCNetwork(parentID, cidr, subnet_name, subnet_id, version):

    # set wsdl location    
    paramsBAM = getBCNConfig(BC_configFileName, "BAM")
    soap_client = _bam_login(paramsBAM)
    
    properties=""
    if subnet_name == None:
        properties += "UUID="
    else:
        if str(version) == "4":
            properties = "name="+ subnet_name+ "|UUID="
        else:
            properties += "UUID="
               
    properties += subnet_id
    netid = ""
    
    LOG.info("BCN: properties  = %s" % (properties) )

    if str(version) == "4":
        
        # Check if net already exists
        # - do same for ipv4&6 objects if they already exist         
        testNet = soap_client.service.getEntityByCIDR(parentID, cidr, "IP4Network")
        if int(testNet['id']) > 0:
            LOG.info("BCN: Warning: network = %s already exists !" % (cidr) )
            newProps = updatePropsStr(testNet['properties'], "UUID", subnet_id)
            
            testNet['name'] = subnet_name
            testNet['properties'] = newProps
                
            LOG.info( "BCN: Updating Network %s ..." % (cidr))
            soap_client.service.update(testNet)
            soap_client.service.logout()
            return(testNet['id'])
             
        LOG.info("BCN: Creating IPv4 Net: %s, properties: %s, parentID: %s ..." % (cidr, properties, parentID))
        netid = soap_client.service.addIP4Network(parentID,  cidr, properties)
    
    else:
        
        fields = cidr.split('/')
        prefix = fields[0]
        testNet = soap_client.service.getIPRangedByIP(parentID, "IP6Network", prefix)
        if int(testNet['id']) > 0:
 
            LOG.info("BCN: Warning: network = %s already exists !" % (cidr) )
            newProps = updatePropsStr(testNet['properties'], "UUID", subnet_id)
            
            testNet['name'] = subnet_name
            testNet['properties'] = newProps
                
            LOG.info( "BCN: Updating Network ...")
            soap_client.service.update(testNet)
            soap_client.service.logout()
            return(testNet['id'])            


        LOG.info("BCN: Creating IPv6 Net: %s, subnet_name: %s, properties: %s, parentID: %s ..." % (cidr, subnet_name, properties, parentID))
        #LOG.info("pass addIP6NetworkByPrefix: pID: %s cidr: %s sName: %s props :%s" %(parentID,  cidr, subnet_name, properties))
        netid = soap_client.service.addIP6NetworkByPrefix(parentID,  cidr, subnet_name, properties)
        
        _bam_logout(paramsBAM, soap_client)

    return(netid)


def delBCNetwork(configID, subnet_id):
    # Currently only does IPv4 User networks

     # Really this needs to search each IPv4 and IPv6 TL block and only then report an error if the 
    # subnet_id (name) is still not found     
    paramsBAM = getBCNConfig(BC_configFileName, "BAM")
    soap_client = _bam_login(paramsBAM)
    
    # This needs expanding to search each IP4 and IP6 block to find the relevant network to delete.
    LOG.info("BCN: Getting ParentBlockID Info  ...")
    parentBlockId = apiGetBlockID(configID, paramsBAM['bam_ipv4_private_block'], "IP4Block")
    value = ""
    # get child nets
    # Needs expanding to search all Ipv4 and IPv6 TL blocks, but currently I am only working in one. 
    nets = soap_client.service.getEntities(parentBlockId, "IP4Network", 0, 1000000)
    netid = ""
    name=""

    if dict(nets).get('item'):
        for net in dict(nets).get('item'):
                id = net['id']
                name = net['name']
                properties = net['properties']
                value = getPropsField(properties, "UUID")
    
                if value == subnet_id:
                    netid = net['id']
                    name=net['name']
                    break
                              
    if netid:
        LOG.info("BCN: Deleting network %s ..." % (netid))
        soap_client.service.delete(netid)
        LOG.info("BCN: Network Removed : Name = %s, UUID = %s"  % (name, subnet_id))
    else:
        LOG.warning("BCN: NetworkID not found for network %s - Skipping ..." % (subnet_id))
        
    _bam_logout(paramsBAM, soap_client)


def updateBCNetwork(soap_client, configID, netCIDR, newNetName, newUUID):
    
    # Get netid
    ipNet = netaddr.IPNetwork(netCIDR)
    
    LOG.info("BCN: Getting NetID Info  ...")
    net = ""
    if ipNet.version == 4:
        net = soap_client.service.getIPRangedByIP(configID, "IP4Network", ipNet[0])
    else:
        net = soap_client.service.getIPRangedByIP(configID, "IP6Network", ipNet[0])
        

    netid = net['id']
    
    if not netid:
        LOG.info("BCN: [Warning] : Network does not exist -Skipping ...." % (netCIDR))
        return               

    newProps = updatePropsStr(net['properties'], "UUID", newUUID)
    
    net['name'] = newNetName
    net['properties'] = newProps
    
    LOG.info ("BCN: Updating Network ...")
    soap_client.service.update(net)




def createBCIP4Obj(ipAddr, hostName, uuid, mac, configID, soap_client):
    # Get netid
    LOG.info("BCN: Getting ViewID Info  ...")
    viewID = _get_bam_viewid(soap_client, configID, "default")
   
    LOG.info("BCN: Getting ParentNetID Info  ...")
    net = soap_client.service.getIPRangedByIP(configID, "IP4Network", ipAddr)
    netid = net['id']
    
    if not netid:
        LOG.warning("BCN: Network for IP %s does not exist -Skipping ...." % (ipAddr))
        return
    
    # Check if IP already exists - id = '0' if obj does not exist.
    ipObj = soap_client.service.getIP4Address(netid, ipAddr)
    ipID = ipObj['id']
    if ipID:
        LOG.warning("BCN: IP %s already defined : objId = %s - Updating ..." % (ipAddr, ipID))
        updateIP4Obj(ipAddr, hostName, uuid, configID, soap_client)
        return

    LOG.info("BCN: Creating host %s in BAM  ..." % (ipAddr))
    paramsBAM = getBCNConfig(BC_configFileName, "BAM")
    properties = "name=" +hostName +"|UUID=" +uuid  
    hostInfo = hostName +"." +paramsBAM['bam_dns_zone'] +"," +str(viewID) +",false,false" 
    hostID = soap_client.service.assignIP4Address(long(configID), ipAddr, mac, hostInfo, 'MAKE_STATIC', properties)
    LOG.info("BCN: Host Added : hostID = %s, IP = %s"  % (hostID, ipAddr))


def createBCPI6Obj(ipAddr, hostName, uuid, mac, configID, soap_client):

    LOG.info("BCN: Getting ViewID Info  ...")
    viewID = _get_bam_viewid(soap_client, configID, "default")
    
    properties = "name=" +hostName +"|UUID=" +uuid
     
    # Note - this is in a different order to v4.
    paramsBAM = getBCNConfig(BC_configFileName, "BAM")
    hostInfo = str(viewID) +"," +hostName +"." +paramsBAM['bam_dns_zone'] +",false,false" 
    LOG.info("BCN: IP6Obj hostInfo = %s" % (hostInfo))

    hostID = soap_client.service.assignIP6Address(long(configID), ipAddr, 'MAKE_STATIC', mac, hostInfo, properties)
    LOG.info("BCN: Host Added : hostID = %s, IP = %s" % (hostID, ipAddr))


# Currently this is only used to update existing objects when the stack starts (ie called from update_subnet),
# at the time of writing there is no 'update_port' type call in the reference driver (See portUpdateMonitor.py)
def updateIP4Obj(ipAddr, newName, uuid, configID, soap_client):

    LOG.info("BCN: Getting ViewID Info  ...")
    viewID = _get_bam_viewid(soap_client, configID, "default")
    
    # Get netid
    LOG.info("BCN: Getting ParentNetID Info  ...")
    net = soap_client.service.getIPRangedByIP(configID, "IP4Network", ipAddr)
    netid = net['id']
    
    if not netid:
        LOG.warning("BCN: [Warning] : Network for IP %s does not exist -Skipping ...." % (ipAddr))
        return
    
    # Get objID
    ipObj = soap_client.service.getIP4Address(netid, ipAddr)
    ipID = ipObj['id']   
    
    if not ipID:
        LOG.warning("BCN: [Warning] : IP %s is not defined in BAM -Skipping ...." % (ipAddr))
        return        
    
    newProps = updatePropsStr(ipObj['properties'], "UUID", uuid)

    ipObj['name'] = newName
    ipObj['properties'] = newProps
   
    LOG.info ("BCN: Updating Object ...")
    soap_client.service.update(ipObj)
    paramsBAM = getBCNConfig(BC_configFileName, "BAM")
    rrID = ""
    newNameFQDN = newName +"." +paramsBAM['bam_dns_zone']

    linkedEntities = soap_client.service.getLinkedEntities(ipID, "HostRecord", 0, 1000)
    for linkedEntity in linkedEntities:
       
        rr = linkedEntity[1][0]
      
        if "id" in rr:
                
                rrID = rr['id']
                if rrID:
                    LOG.info ("BCN: \tRemoving HostRecord ...")
                    soap_client.service.delete(rrID)
                
                    # Only adding new records if we have removed one - this covers router objects which have no name defined.
                    LOG.info ("BCN: \tAdding New HostRecord ...")
                    LOG.info ("BCN: \trrDetails: ipAddr : %s viewID: %s fqdn: %s ..." % (ipAddr, viewID, newNameFQDN))

                    newRRID = soap_client.service.addHostRecord(viewID, newNameFQDN, ipAddr, -1, "" )
    


def delBCIP4Obj(ipAddr, configID, soap_client):
    # Get netid
    LOG.info("BCN: Getting ParentNetID Info ...")
    net = soap_client.service.getIPRangedByIP(configID, "IP4Network", ipAddr)
    netid = net['id']
    
    if not netid:
        LOG.warning("BCN: Network for IP %s does not exist -Skipping ...." % (ipAddr))
        return
    
    LOG.info("BCN: netid= %s, " % (netid))

    
    # Get objID
    ipObj = soap_client.service.getIP4Address(netid, ipAddr)
    ipID = ipObj['id']
    # Delete IP Object
    LOG.info("BCN: Deleting Host : hostID = %s, IP = %s" % (ipID, ipAddr))
    if int(ipID) > 0:
        soap_client.service.delete(ipID)
        LOG.info("BCN: Host Deleted, hostID = %s, IP = %s" % (ipID, ipAddr))
    else:
        LOG.info("BCN: Warning Host : IP = %s does not exit" % (ipAddr))


def delBCIP6Obj(ipAddr, configID, soap_client):

    # Get netid
    LOG.info("BCN: Getting ParentNetID Info ...")
    net = soap_client.service.getIPRangedByIP(configID, "IP6Network", ipAddr)
    netid = net['id']
    
    if not netid:
        LOG.warning("BCN: Network for IP %s does not exist -Skipping ...." % (ipAddr))
        return
    
    # Get objID
    ipObj = soap_client.service.getIP6Address(netid, ipAddr)
    ipID = ipObj['id']
    
    # Delete IP Object
    soap_client.service.delete(ipID)
    LOG.info("BCN: Host Deleted, hostID = %s, IP = %s" % (ipID, ipAddr))
    
 
def _get_bam_viewid(soap_client, configId, viewName):
   view = soap_client.service.getEntityByName(configId, viewName, 'View')
   viewId = long(view['id'])
   #LOG.info("BCN: Got View ID %d" % (viewId))
   return viewId 