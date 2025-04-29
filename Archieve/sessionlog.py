#!/usr/bin/env python
from netmiko import ConnectHandler
from getpass import getpass

cisco1 = {
    "device_type": "cisco_xe",
    "host": "10.250.50.201",
    "username": "T!ger0ne",
    "password":"QYz)xbJWV9#",
    # File name to save the 'session_log' to
    "session_log": "output06.txt"
}

# Show command that we execute
# command = "show ip int brief"



command = ['show ip route', 'show ip int br', 'show run all' ]
with ConnectHandler(**cisco1) as net_connect:
    for commands in command:
        output = net_connect.send_command(commands, delay_factor=5)
net_connect.disconnect()




