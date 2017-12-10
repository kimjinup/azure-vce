#!/usr/bin/env python3
# pip install azure

from azure.common import credentials
from azure.mgmt import resource, network, storage, compute
from azure.mgmt.network import models as network_models
from azure.mgmt.compute import models as compute_models
from azure.mgmt.compute import ComputeManagementClient
import sys
import azure
from azure.mgmt.compute.compute.v2015_06_15.models import hardware_profile

def prepare_network(username, password, subscription_id, location, resource_group_name, 
                    virtual_network_name, virtual_network_prefix,
                    mgmt_subnet_prefix, public_subnet_prefix, private_subnet_prefix):

        # create the credential with username and password
        credential = credentials.UserPassCredentials(username, password)

        # create resource group
        resource_client = resource.ResourceManagementClient(credential, subscription_id)
        resource_client.resource_groups.create_or_update(resource_group_name, {'location': location })
        
        network_client = network.NetworkManagementClient(credential, subscription_id)

        
        rule_vcmp = network_models.SecurityRule(
            priority = 100,
            protocol = "Udp", 
            source_port_range = "*",
            destination_port_range= "2426-2426",
            source_address_prefix = "0.0.0.0/0",
            destination_address_prefix = "0.0.0.0/0",
            access = "Allow",
            direction = "Inbound",
            name = "vcmp")

        rule_snmp = network_models.SecurityRule(
            priority = 110,
            protocol = "Udp", 
            source_port_range = "*",
            destination_port_range= "161-161",
            source_address_prefix = "0.0.0.0/0",
            destination_address_prefix = "0.0.0.0/0",
            access = "Allow",
            direction = "Inbound",
            name = "snmp")

        rule_ssh = network_models.SecurityRule(
            priority = 120,
            protocol = "Tcp", 
            source_port_range = "*",
            destination_port_range= "22-22",
            source_address_prefix = "0.0.0.0/0",
            destination_address_prefix = "0.0.0.0/0",
            access = "Allow",
            direction = "Inbound",
            name = "ssh")

        velocloud_nsg_parameters = network_models.NetworkSecurityGroup(location = location,
            security_rules = [rule_vcmp, rule_snmp, rule_ssh ])
        network_client.network_security_groups.create_or_update(
            resource_group_name = resource_group_name,
            network_security_group_name = "velocloud_nsg",
            parameters = velocloud_nsg_parameters )
        velocloud_nsg = network_client.network_security_groups.get(resource_group_name, "velocloud_nsg")

        public_subnet = network_models.Subnet(
            address_prefix = public_subnet_prefix,
            network_security_group=velocloud_nsg,
            route_table = None,
            name = virtual_network_name + "_public_subnet")
        public_subnet_route = network_models.Route(
            address_prefix = public_subnet_prefix,
            next_hop_type = "VnetLocal",
            name = "public_subnet_route")

        mgmt_subnet = network_models.Subnet(
            address_prefix = mgmt_subnet_prefix,
            network_security_group=velocloud_nsg,
            route_table = None,
            name = virtual_network_name + "_mgmt_subnet")
        mgmt_subnet_route = network_models.Route(
            address_prefix = mgmt_subnet_prefix,
            next_hop_type = "VnetLocal",
            name = "mgmt_subnet_route")

        private_subnet = network_models.Subnet(
            address_prefix = private_subnet_prefix,
            network_security_group=velocloud_nsg,
            route_table = None,
            name = virtual_network_name + "_private_subnet")
        private_subnet_route = network_models.Route(
            address_prefix = private_subnet_prefix,
            next_hop_type = "VnetLocal",
            name = "private_subnet_route")
        
        default_route = network_models.Route(
            address_prefix = "0.0.0.0/0",
            next_hop_type = "Internet",
            name = "default_route")

        vn_parameters = network_models.VirtualNetwork(
            location = location,
            address_space = network_models.AddressSpace([virtual_network_prefix]),
            dhcp_options = None,
            subnets = [mgmt_subnet, public_subnet, private_subnet] )

        network_client.virtual_networks.create_or_update(resource_group_name, virtual_network_name, vn_parameters)
        
        public_route_table = network_models.RouteTable(
            location = location,
            routes = [default_route, public_subnet_route, mgmt_subnet_route, private_subnet_route]
            )
        
        network_client.route_tables.create_or_update(resource_group_name, "public_route_table", public_route_table)
       
def create_virtual_vce(username, password, subscription_id, edge_name, storage_account_name, resource_group_name, 
                       location, virtual_network_name,
                       mgmt_subnet_name, public_subnet_name, private_subnet_name, 
                       mgmt_subnet_nsg_name, public_subnet_nsg_name, private_subnet_nsg_name,
                       ssh_public_key):
    credential = credentials.UserPassCredentials(username, password)

    # create resource group
    resource_client = resource.ResourceManagementClient(credential, subscription_id)
    storage_client = storage.StorageManagementClient(credentials, subscription_id)
    network_client = network.NetworkManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)

    mgmt_subnet = network_client.subnets.get(resource_group_name, virtual_network_name, mgmt_subnet_name)
    public_subnet = network_client.subnets.get(resource_group_name, virtual_network_name, public_subnet_name)
    private_subnet = network_client.subnets.get(resource_group_name, virtual_network_name, private_subnet_name)

    mgmt_subnet_nsg = network_client.network_security_groups.get(resource_group_name, mgmt_subnet_nsg_name )
    public_subnet_nsg = network_client.network_security_groups.get(resource_group_name, public_subnet_nsg_name )
    private_subnet_nsg = network_client.network_security_groups.get(resource_group_name, private_subnet_nsg_name )
    
    nic_eth0_ip_configuration = network_models.IPConfiguration(
        subnet = mgmt_subnet,
        name = edge_name + "_eth0-ip-configuration",
        private_ip_allocation_method=network_models.IPAllocationMethod.dynamic
        )
    nic_eth0_parameters = network_models.NetworkInterface(
        location = location,
        network_security_group= mgmt_subnet_nsg,
        ip_configurations = [nic_eth0_ip_configuration],
        enable_ip_forwarding= False )
    async_nic_eth0_creation = network_client.network_interfaces.create_or_update(
        resource_group_name, edge_name + "_eth0", nic_eth0_parameters)
    async_nic_eth0_creation.wait()
    nic_eth0 = network_client.network_interfaces.get(resource_group_name, edge_name + "_eth0")

    public_ip_address_parameters = network_models.PublicIPAddress(
        location = location,
        public_ip_allocation_method=network_models.IPAllocationMethod.dynamic,
        idle_timeout_in_minutes=4)
    async_public_ip_creation = network_client.public_ip_addresses.create_or_update(
        resource_group_name, edge_name + "_eth1-public-ip-address", public_ip_address_parameters)
    async_public_ip_creation.wait()
    eth1_public_ip_address = network_client.public_ip_addresses.get(resource_group_name, edge_name + "_eth1-public-ip-address")

    nic_eth1_ip_configuration = network_models.IPConfiguration(
        subnet = public_subnet,
        name = edge_name + "_eth1-ip-configuration",
        private_ip_allocation_method=network_models.IPAllocationMethod.dynamic,
        public_ip_address = eth1_public_ip_address
        )
    nic_eth1_parameters = network_models.NetworkInterface(
        location = location,
        network_security_group= public_subnet_nsg,
        ip_configurations = [nic_eth1_ip_configuration],
        enable_ip_forwarding= True)
    async_nic_eth1_creation = network_client.network_interfaces.create_or_update( 
        resource_group_name, edge_name + "_eth1", nic_eth1_parameters)
    nic_eth1 = network_client.network_interfaces.get(resource_group_name, edge_name + "_eth1")

    nic_eth2_ip_configuration = network_models.IPConfiguration(
        subnet = private_subnet,
        name = edge_name + "_eth2-ip-configuration",
        private_ip_allocation_method=network_models.IPAllocationMethod.dynamic
        )
    nic_eth1_parameter = network_models.NetworkInterface(
        location = location,
        network_security_group= private_subnet_nsg,
        ip_configurations = [nic_eth2_ip_configuration],
        enable_ip_forwarding= True)
    async_nic_eth2_creation = network_client.network_interfaces.create_or_update( resource_group_name, edge_name + "_eth2", nic_eth1_parameter)
    nic_eth2 = network_client.network_interfaces.get(resource_group_name, edge_name + "_eth2")
    
    os_profile = compute_models.OSProfile(
        computer_name = edge_name,
        admin_username = 'vcadmin',
        #admin_password = 'Velocloud123'
#        linux_configuration = compute_models.LinuxConfiguration(
#            disable_password_authentication= True,
#            ssh = compute_models.SshConfiguration(
#                public_keys = [ssh_public_key]
#            )
#        )
    )
    
    vm = compute_client.virtual_machines.get(resource_group_name, "vVCE1")
    
    hardware_profile = compute_models.HardwareProfile(
        vm_size = 'Standard_DS2'
    )

#    storage_profile = compute_models.StorageProfile(
#        image_reference= compute_models.ImageReference(
#            publisher= 'velocloud',
#            offer = 'velocloud-virtual-edge-3x',
#            sku = 'velocloud-virtual-edge-3x'
#        )
#    )
    storage_profile = compute_models.StorageProfile(
        image_reference = compute_models.ImageReference(
            publisher = 'Canonical',
            offer = 'UbuntuServer',
            sku = '16.04.0-LTS',
            version = 'latest')
    )
    
    network_profile = compute_models.NetworkProfile(
        network_interfaces = [ nic_eth0.id, nic_eth1.id, nic_eth2.id]
    )
   
    vm_profile = compute_models.VirtualMachine(
        location = location,
        os_profile = os_profile,
        hardware_profile = hardware_profile,
        storage_profile = storage_profile,
        network_profile = network_profile
    )
    
    async_vm_creation = compute_client.virtual_machines.create_or_update(resource_group_name, edge_name, vm_profile)
    async_vm_creation.wait()
    
    

def main():
    subscription_id = "26c6bd98-ba08-4a26-bed8-dd2b3b1df2b7"
    username = "Jinup@azuremarketplacevelocloud.onmicrosoft.com"
    password = "585#Akma"
    resource_group_name = "test"
    location = "eastus"
    security_group_name = "vVCE_inbound_nsg"
    #ssh_public_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgxv32+sKkMioHAnTR1+xflPVzaBt1xysScotO2sx7SCVH5hCd9/Xw8ZzF1Rk3yuVAcZTsL31pj0m84eXI0dZbgJ8C1KD8K80R6dDXTh6roB72Wua/HFYtRVhKriLtZoBbUaXzA9N9X9+hpvtW7MPL0SiuU2X5GCEDiA1OrOBhn1jtLrJM446dG2KpWYdUYieibZV8ViA1BD6Sue86QfFnHKGNmXA6+pdwRt3J8zxMJOKXq84hQ4lUM9GFQ3B5q/qv6adTLpqe4oG9P5TxMcN3ZHIFNkxxVp6wJpMrSY2rWUMx7qcXg7l3fTzbLKbiFmPZVz+dYMwTOw3iN+vA7m0N kimjinup@Kims-MacBook-Pro.local'
    
    prepare_network(username, password, subscription_id, location, resource_group_name, "veloCloud1", 
                    "172.16.0.0/16", "172.16.0.0/24", "172.16.1.0/24", "172.16.2.0/24")
    
    create_virtual_vce(username, password, subscription_id, "vVCE1", "velocloudvirtualvce", resource_group_name, location, "veloCloud1",
                       "veloCloud1_mgmt_subnet", "veloCloud1_public_subnet", "veloCloud1_private_subnet", "velocloud_nsg", "velocloud_nsg", "velocloud_nsg",
                       None)
    
    
if __name__ == "__main__":
    main()