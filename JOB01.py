#! /usr/bin/env python
#
#
from dataclasses import dataclass
from typing import Optional
from netmiko import ConnectHandler
from ntc_templates.parse import parse_output
from ipaddress import ip_address
#
#
import asyncio
import yaml
from scrapli.driver.core import AsyncIOSXEDriver
from inv import DEVICES
#
#
#
#
#
@dataclass
class NetworkAudit:
    """
    XXXX
    """

    MgmtIP: str
    port: int
    username: str
    password: str
    FileExport: str
    hostname: str
    # access_list_name: Optional[str] = "CISCO-CWA-URL-REDIRECT-ACL"
    # telnet_vty_line: Optional[int] = 15

    def connect(self) -> ConnectHandler:
        """
        Create and return a ConnectHandler for the device
        """
        net_connect = ConnectHandler(
            host= self.MgmtIP,
            username= self.username,
            password= self.password,
            port= self.port,
            device_type= "cisco_xe",
            session_log= self.FileExport
        )
        return net_connect

    def CiscoDeviceConfigs(self) -> list[dict[str, str]]:
        """
        Lookup and return the current hosts allowed
        telnet access to device.
        """
        Commands = ['show ip route', 'show ip int br', 'show run all']
        net_connect = self.connect()   # Connect to the device
        for CommandsList in Commands:
            mgmt_acl_raw = net_connect.send_command(CommandsList, delay_factor=5)
        net_connect.disconnect()       # Disconnect from the device
        print(f" Export-Job Successful for device  {self.hostname}")

        # TODO: Use TextFSM and the already installed nic_templates to parse the raw
        #       output from the show command and return the result
        # mgmt_acl = None
        mgmt_acl = parse_output(platform="cisco_ios", 
                                command=f"show ip interface brief", 
                                data=mgmt_acl_raw)
        # print(mgmt_acl)
        # print(type(mgmt_acl))
        return mgmt_acl

    def upinterfaceslist(self, mgmt_acl: Optional[list[dict[str, str]]] = None):
        """
        Print out the current status of interfaces
        """

        # If the mgmt_acl isn't provided as input, look it up
        # print(mgmt_acl)
        # print(type(mgmt_acl))

        if mgmt_acl is None:
            mgmt_acl = self.CiscoDeviceConfigs()
        
        #print(f"The following host permissions defined on ACL {self.access_list_name}:")
        # for i, entry in enumerate(mgmt_acl):
        #     if entry["src_host"] != "":
        #         print(f'{i+1:>3}: {entry["action"]} host {entry["src_host"]}')
        NEWUPLIST = []
        for each_element in (mgmt_acl):
            #print(each_element)
            #print(type(each_element))
            # print(each_element['intf'])
            if each_element['proto'] == 'up':
                if each_element['status'] == 'up' :
                    NEWUPLIST.append(each_element['intf'])
                    # print(each_element['intf'])
        # print(f"This is the new list  " + str(NEWUPLIST))



    # def update_mgmt_list(self, action: str, address: ip_address) -> bool:
    #     """
    #     Update the telnet access by adding/removing an address
    #     from the access list
    #     """
    #     # Validate data
    #     if action not in ["add", "remove"]:
    #         return False

    #     # Change action to "no_state"
    #     no_state = "no" if action == "remove" else ""

    #     # The configuration to add/remove a host entry from the ACL
    #     config_cmds = [
    #         f"ip access-list standard {self.access_list_name}",
    #         f"{no_state} permit host {address}",
    #     ]

    #     # Send the configuration to the device
    #     try:
    #         # Connect to the device
    #         net_connect = self.connect()

    #         output = net_connect.send_config_set(config_cmds)
    #         output += net_connect.save_config()

    #         # Disconnect from the device
    #         net_connect.disconnect()

    #     except Exception as e:
    #         print("❌ There was an error sending configuration to device.")
    #         print(e)
    #         return False

    #     # Verify there was no invalid input during configuration
    #     if "% Invalid input detected" in output:
    #         print("❌ There was an error with the configuration commands sent.")
    #         print("Configuration Set: ")
    #         for command in config_cmds:
    #             print(f"    {command}")
    #         print()
    #         print("Output from device: ")
    #         print(output)
    #         return False

    #     # If not error found, return True for success
    #     return True






