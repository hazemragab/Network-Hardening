#! /usr/bin/env python

import os
from dotenv import load_dotenv
load_dotenv()
from ipaddress import ip_address
from JOB01 import NetworkAudit
from inv import DEVICES
from ciscoconfparse2 import CiscoConfParse
import yaml, argparse, csv, subprocess


if __name__ == "__main__":

    # Lookup network credentials from environment
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    if not username or not password:
        print("Credentials for network access must be set as ENVs 'XE_VAR_USER' and 'XE_VAR_PASS' to use this utility.")
    

    def parse_arguments():                                     # to parse command-line arguments
        parser = argparse.ArgumentParser(description = ' Netmiko Script to Connect to Routers and Run Commands ')
        parser.add_argument('--hosts_file', required=True, help = ' Path to the Ansible hosts file ')
        parser.add_argument('--group', required=True, help = ' Group of routers to connect to from Ansible hosts file ')
        return parser.parse_args()


    def ping_ip(ip_address):                                   # Use ping command to check if switch alive
        param = '-c'                                           # for linux os
        command = ['ping', param, '2', ip_address]             # Build the ping command
        try:
            subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)    # Execute the ping command
            return "yes"
        except subprocess.CalledProcessError:
            return "no"




def main():
    args = parse_arguments()                               # Parse command-line arguments
    with open(args.hosts_file, 'r') as file:               # Load ansible hosts file in yaml format
        hosts_data = yaml.safe_load(file)
    # global_vars = hosts_data['all']['vars']                # Extract global variables
    if args.group not in hosts_data:
        print(f"Group {args.group} not found in hosts file.")
        return
    # routers = hosts_data[args.group]['hosts']           # Extract group of devices
    routers = hosts_data[args.group]           # Extract group of devices


    MLQDC_DeviceList = ['THM-ACI-MOB-INT', 'MLQ-INT-SW' ]

    for device in DEVICES:
        hostname = device['hostname']
        FileExport = (f"./ConfigExport/%s.txt" %hostname)
        MgmtIP = device['ipadd']
        # try:
        #     MgmtIP = ip_address(MgmtIP)
        # except ValueError:
        #     print(f"❌ The entry {MgmtIP} is not a valid IP address. Exiting")
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