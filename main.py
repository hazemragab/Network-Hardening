#! /usr/bin/env python

import os
from ipaddress import ip_address
from JOB01 import NetworkAudit


if __name__ == "__main__":

    # Lookup network credentials from environment
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    # print(username)
    # print(password)
    """
    username = os.environ['XE_VAR_USER']
    password = os.environ['XE_VAR_PASS']
    """

    if not username or not password:
        print("Credentials for network access must be set as ENVs 'XE_VAR_USER' and 'XE_VAR_PASS' to use this utility.")

    # Address and Port for Network Router to manage ACL
    # Default to 'rtr-edge-03' but allow overriding with ENV
    # address = os.getenv("ROUTER_ADDRESS", "10.250.50.201")
    # port = int(os.getenv("ROUTER_PORT", 22))
    address = ('10.250.50.201')
    port = 22

    # Create a Telnet_Mgmt Object for the device
    device = NetworkAudit(address, port, username, password)

    # Display the current list of hosts with defined telnet access
    print(f"Looking up current status of Interfaces from device {device.address}.")
    print("-" * os.get_terminal_size().columns)
    device.upinterfaceslist()
    print("-" * os.get_terminal_size().columns)












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