#! /usr/bin/env python

"""
usage : python mainv2.py --hosts_file testbed.yml --group MLQDC

"""

import os
import click
from dotenv import load_dotenv
load_dotenv()
from JOB01 import NetworkAudit
import yaml, argparse, csv, subprocess
from netmiko.utilities import obtain_all_devices
from inv import DEVICES
from ipaddress import ip_address
from ciscoconfparse2 import CiscoConfParse


# if __name__ == "__main__":
    # Lookup network credentials from environment

def parse_arguments():                                     # to parse command-line arguments
    parser = argparse.ArgumentParser(description = ' Netmiko Script to Connect to Routers and Run Commands ')
    parser.add_argument('--hosts_file', required=True, help = ' Path to the Ansible hosts file ')
    parser.add_argument('--group', required=True, help = ' Group of routers to connect to from Ansible hosts file ')
    return parser.parse_args()


def ping_ip(ips):                                   # Use ping command to check if switch alive
    param = '-c'                                           # for linux os
    command = ['ping', param, '2', ips]             # Build the ping command
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)    # Execute the ping command
        return "yes"
    except subprocess.CalledProcessError:
        return "no"

def main():
    
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    if not username or not password:
        print("Credentials for network access must be set as ENVs 'XE_VAR_USER' and 'XE_VAR_PASS' to use this utility.")
    
    args = parse_arguments()                               # Parse command-line arguments
    with open(args.hosts_file, 'r') as file:               # Load ansible hosts file in yaml format
        hosts_data = yaml.safe_load(file)
    if args.group not in hosts_data:
        print(f"Group {args.group} not found in hosts file.")
        return
    GroupDevicesDictionary = hosts_data[args.group]          # Extract group of devices


    for key,value in GroupDevicesDictionary.items():
        if ping_ip(value['host']) == "no":
            print(f' ❌ Device %s MgmtIP:%s is not reachable' %(key,value['host']))
            continue
        else:
            print (f'🟢 Device %s MgmtIP:%s is reachable'  %(key,value['host']))
            hostname = key
            MgmtIP = value['host']
            FileExport = (f"./ConfigExport/%s.txt" %hostname)
            port = 22
            RunFn = NetworkAudit(MgmtIP, port, username, password, FileExport, hostname)    # Create a CiscoDeviceConfig Fn
            print(f"Exporting ConfigurationFiles from device {RunFn.hostname}. to Directory ./ConfigsExport ")
            # print("-" * os.get_terminal_size().columns)
            RunFn.CiscoDeviceConfigs()
            print("-" * os.get_terminal_size().columns)


@click.commad()
@click.option(
    "--all/--node",
    default=True,
    show_default=False,
    required=False,
    help="audit on all files in the directory or just one node",
)
def auditfn():
    print("hello")


main.add_command(auditfn)

# Entry point of the main   ###  
if __name__ == '__main__':
    main()



