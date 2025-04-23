#! /usr/bin/env python

import os
from dotenv import load_dotenv
load_dotenv()
from ipaddress import ip_address
from JOB01 import NetworkAudit
from inv import DEVICES
from ciscoconfparse2 import CiscoConfParse


if __name__ == "__main__":

    # Lookup network credentials from environment
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    if not username or not password:
        print("Credentials for network access must be set as ENVs 'XE_VAR_USER' and 'XE_VAR_PASS' to use this utility.")
    
    """
    
    ● Feature for categorizing the device types and to which DC-GROUP it belongs to is still not developed
    ● The for-loop function need to be changes maybe to a function then loop via multiproccessing/Threading
    ● Develop the feature for examining the checkpoints then reflect on dataframe then export to excel file 

    """
    MLQDC-DeviceList = ['THM-ACI-MOB-INT', 'MLQ-INT-SW' ]

    for device in DEVICES:
        hostname = device['hostname']
        FileExport = (f"./ConfigExport/%s.txt" %hostname)
        try:
            # MgmtIP01 = device['ipadd']
            MgmtIP = ip_address(device['ipadd'])
        except ValueError:
            print(f"❌ The entry {device['ipadd']} is not a valid IP address. Exiting")
        port = 22


        RunFn = NetworkAudit(MgmtIP, port, username, password, FileExport, hostname)    # Create a CiscoDeviceConfig Fn
        print(f"Exporting ConfigurationFiles from device {RunFn.hostname}. to Directory ./ConfigsExport ")
        # print("-" * os.get_terminal_size().columns)
        RunFn.CiscoDeviceConfigs()
        print("-" * os.get_terminal_size().columns)

        # print(hostname)
        # print(MgmtIP)
        # print(FileExport)
        # print(type(FileExport))





"""
    # Ask user if they'd like to add or remove an entry from the list
    action = input(
        f"Would you like to add to or remove from the telnet access list '{device.access_list_name}'? (add/remove): "
    )
    if action not in ["add", "remove"]:
        print("❌ Only 'add' or 'remove' are allowed responses. Exiting")
        exit()

    # Ask user for the address to manage
    host_address = input(
        f"What address would you like to {action}? (provide IP address): "
    )
    print("-" * os.get_terminal_size().columns)

    # Verify the address provided is a valid IP
    try:
        host_address = ip_address(host_address)
    except ValueError:
        print(f"❌ The entry {host_address} is not a valid IP address. Exiting")

    # Update the management access
    print(
        f"Updating configuration of device {device.address} to {action} host {host_address}."
    )
    if device.update_mgmt_list(action, host_address):
        print("🟢 Update successful.")
    else:
        print("🔴 Update unsuccessful.")

"""