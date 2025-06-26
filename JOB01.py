#! /usr/bin/env python
#
#
from dataclasses import dataclass
from typing import Optional
from netmiko import ConnectHandler
from ciscoconfparse2 import CiscoConfParse
import re
import pandas as pd
#
#
import csv
from ipaddress import ip_address
from pathlib import Path
import asyncio
import yaml
from scrapli.driver.core import AsyncIOSXEDriver
from ntc_templates.parse import parse_output
# from inv import DEVICES
#
#
""""
        ● [1] Encrypt configuration passwords 
        ● [2] Encrypt configuration passwords 
"""
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
    Region: str


    def connect(self) -> ConnectHandler:
        """
        Create and return a ConnectHandler for the device and log the session
        """
        device = {
            'host': self.MgmtIP,
            'username': self.username,
            'password': self.password,
            'port': self.port,
            'device_type': "cisco_xe",
            # 'use_keys': 'True',
            # 'auth_timeout': 60,
            # 'session_log': self.FileExport,
        }
        # net_connect = ConnectHandler(**device, disabled_algorithms = {'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
        # net_connect = ConnectHandler(**device, disabled_algorithms = {'keys': ['rsa-sha2-256', 'rsa-sha2-512']})
        net_connect = ConnectHandler(**device)
        
        return net_connect

    # def CiscoDeviceConfigs(self, hostname) -> list[dict[str, str]]:
    def CiscoDeviceConfigsExport(self, hostname, FileExport, NewFilePathName):   
        """
        Lookup and return the current hosts allowed
        telnet access to device.
        """
        global newfile, newfile2

        net_connect = self.connect()
        output = net_connect.send_command('show run all')
        output += net_connect.send_command('\n')
        output += net_connect.send_command('\n')
        newfile=open(FileExport, "a")
        newfile.write(output )
        newfile.close
        
        """
        showrunall = ['show run all']
        for ShowRunAllCommand in showrunall:
            mgmt_acl_raw = net_connect.send_command(ShowRunAllCommand)
            newfile=open(FileExport, "a")
            newfile.write(mgmt_acl_raw )
            newfile.close
        """
        #
        #
        #
        Commands = [ 'show version | inc Cisco IOS XE Software, Version|uptime|Last' , 'show ip route', 'show ip int br','show ntp status', 'show ip ssh', 'show snmp user', 'show platform | inc Chassis type:', 'show version | inc Model Number']
        #### CommandsListOutput = ""
        for CommandsList in Commands:
        #    CommandsListOutput = net_connect.send_command_timing(CommandsList, delay_factor=5)

           CommandsListOutput = net_connect.send_command(CommandsList, delay_factor=2)
           CommandsListOutput += net_connect.send_command('\n')
           newfile2=open(NewFilePathName, "a")
           newfile2.write(CommandsListOutput)
           newfile2.close()

        #
        net_connect.disconnect()       # Disconnect from the device
        print(f"🟢 Export-Job Successful for device  {self.hostname}")
        return newfile, newfile2

        #    CommandsListOutput = net_connect.send_command(CommandsList, use_textfsm=True)
        #    CommandsListOutput = net_connect.send_multiline(CommandsList)
        #    CommandsListOutput = net_connect.send_command_timing(CommandsList, delay_factor=5)

        """
        https://github.com/ktbyers/netmiko/blob/develop/EXAMPLES.md
        command = "show ip int brief"
        with ConnectHandler(**cisco1) as net_connect:
            # Use TextFSM to retrieve structured data
            output = net_connect.send_command(command, use_textfsm=True)
        
        """



    def CiscoCheckList(self, hostname, FileExport, MgmtIP, NewFileName, DeviceRole) :
        
        ShowRunAllParse=CiscoConfParse(FileExport)
        ShowStatusParse = CiscoConfParse(NewFileName, syntax='ios')
        
        ##Encrypt configuration passwords                   --- EncryptConfigurationPasswords
        """
        username nameee privilege 15 password 0
        username aaa password 0 as
        """
        global Check01
        Check01=""
        Encrypt_conf_pwds_pattern1 = re.compile(r'^username\s(.+?)\sprivilege\s([0-9]{1,2})\spassword\s0\s')
        Encrypt_conf_pwds_pattern2 = re.compile(r'^username\s(.+?)\spassword\s0\s') #Hint this Rule also catches the above regex
        clearpwdslist = []
        for obj1 in ShowRunAllParse.find_objects(Encrypt_conf_pwds_pattern1):
            clearpwdslist.append(obj1.text)    
        
        for obj2 in ShowRunAllParse.find_objects(Encrypt_conf_pwds_pattern2):  
            clearpwdslist.append(obj2.text) 

        if not clearpwdslist:
        # if usrslist != []:
            print(f'🟢 Node %s passed for parameter  "EncryptConfigurationPasswords"  ' %hostname )
            Check01 = 'PASS'
        else:
            print(f'❌ Node %s failed for parameter "EncryptConfigurationPasswords" ' %hostname )
            Check01 = 'FAIL'
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        # 
        #
        ##Create a Fallback Account   --- Create Fallback Accoun
        """
            username T!ger0ne privilege 15 secret 9
        """
        global Check02
        Check02=""
        Tiger0neAccount = re.compile(r'^username\sT!ger0ne\sprivilege\s([0-9]{1,2})\ssecret\s[0-9]\s')
        if ShowRunAllParse.find_objects(Tiger0neAccount):
            Check02 = 'PASS'
        else:
            Check02 = 'FAIL'
        
        if Check02 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "Create Fallback Account "  ' %hostname )
        elif Check02 == 'PASS': 
            print(f'🟢 Node %s passed for parameter "Create Fallback Account " ' %hostname )
        else:
            print("No Check02 Value")
        
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        # 
        #
        #Configure the password retry lockout       --- PasswordRetryLockout
        """"
        aaa local authentication attempts max-fail 3
        """
        global Check03
        Check03=""
        # PasswordRetryLockout = re.compile(r'^aaa\slocal\sauthentication\sattempts\smax-fail\s([0-9]{1,2})')
        PasswordRetryLockout = re.compile(r'^aaa\slocal\sauthentication\sattempts\s')
        if ShowRunAllParse.find_objects(PasswordRetryLockout):
            Check03 = 'PASS'
        else:
            Check03 = 'FAIL'
        #
        if Check03 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "Configure the password retry lockout"  ' %hostname )
        elif Check03 == 'PASS': 
            print(f'🟢 Node %s passed for parameter "Configure the password retry lockout " ' %hostname )
        else:
            print("No Check03 Value")
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        # 
        #
        #Configure inactivity time-out for the sessions 
        """"
                line vty 0 4
                    exec-timeout 5 0
        """
        global Check04
        find_lines_pattern = re.compile(r'^line\s(con|vty|aux)\s')
        for eachline in ShowRunAllParse.find_objects(find_lines_pattern):
            if ShowRunAllParse.find_child_objects(eachline, 'exec-timeout'):
                Check04 = 'PASS'
            else:
                Check04 = 'FAIL'
                break
        #
        #
        if Check04 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "Configure inactivity time-out for the sessions "  ' %hostname )
        elif Check04 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "Configure inactivity time-out for the sessions  " ' %hostname )
        else:
            print("No Check04 Value")
        #
        #
        #
        #
        #
        #
        #
        #
        # 
        #
        #
        #**************************************************************************************************#
        # 
        # Disable DHCP services                         --- DisableDHCPServices
        """
        PASSED if a line matching re.compile('no service dhcp') is found.
        otherwise, FAILED
        """ 
        global Check05
        Check05=""
        
        DisableDHCPServices = re.compile(r'^no service dhcp')
        if ShowRunAllParse.find_objects(DisableDHCPServices):
            Check05 = 'PASS'
        else:
            Check05 = 'FAIL'
        
        if Check05 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "Disable DHCP services "  ' %hostname )
        elif Check05 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "Disable DHCP services " ' %hostname )
        else:
            print("No Check05 Value")
        #
        #**************************************************************************************************#
        #
        # DisableHTTPService                            --- DisableHTTPService
        """
            PASSED if a line matching re.compile('no ip http server') is found.
            otherwise, FAILED
        ---
            NOT:
                PASSED if a line matching re.compile('ip http server') is found.
                otherwise,FAILED
        """ 
        global Check06
        DisableHTTPService = re.compile(r'^no ip http server')
        if ShowRunAllParse.find_objects(DisableHTTPService):
            Check06 = 'PASS'
        else:
            Check06 = 'FAIL'
        
        if Check06 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "DisableHTTPService "  ' %hostname )
        elif Check06 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "DisableHTTPService" ' %hostname )
        else:
            print("No Check06 Value")
        #
        #**************************************************************************************************#
        #
        # DisableHTTPSService                           ---   DisableHTTPSService
        """
        MR17:: Disable HTTPS service 
            OR:
            PASSED if a line matching re.compile('no ip http secure-server') is found.
            otherwise, FAILED
        ---
            NOT:
                PASSED if a line matching re.compile('ip http secure-server') is found.
                otherwise, FAILED
        ---
        """ 
        global Check07        
        DisableHTTPSService = re.compile(r'^no ip http secure-server')
        if ShowRunAllParse.find_objects(DisableHTTPSService):
            Check07 = 'PASS'
        else:
            Check07 = 'FAIL'
        #
        if Check07 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "DisableHTTPSService"  ' %hostname )
        elif Check07 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "DisableHTTPSService" ' %hostname )
        else:
            print("No Check07 Value")
        #
        #**************************************************************************************************#
        #
        # DisableTFTPService                    --- DisableTFTPService
        """
        MR19:: Disable TFTP service 
        NOT:
        PASSED if a line matching re.compile('^tftp-server') is found.
        otherwise, FAILED
        ---
        """ 
        global Check08
        
        DisableTFTPService = re.compile(r'^tftp-server')
        if ShowRunAllParse.find_objects(DisableTFTPService):
            Check08 = 'FAIL'
        else:
            Check08 = 'PASS'
        
        if Check08 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "DisableTFTPService"' %hostname )
        elif Check08 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "DisableTFTPService"' %hostname )
        else:
            print("No Check08 Value")

        #
        #**************************************************************************************************#
        #
        # ProhibitTelnetConnections                 --- ProhibitTelnetConnections
        """
        MR25:: Prohibit telnet connections 
            NOT:
                OR:
                    PASSED if a line matching re.compile('\\s+transport input telnet') is found.
                    otherwise, FAILED
                ---
                    PASSED if a line matching re.compile('\\s+transport input telnet ssh|\\s+transport input ssh telnet') is found.
                    otherwise, FAILED
                ---
                    PASSED if a line matching re.compile('\\s+transport input all') is found.
                    otherwise
        """ 
        global Check09
        find_lines_pattern = re.compile(r'^line\s(con|vty|aux)\s')
        for eachline in ShowRunAllParse.find_objects(find_lines_pattern):
            if ShowRunAllParse.find_child_objects(eachline, 'transport input telnet') or ShowRunAllParse.find_child_objects(eachline, 'transport input telnet ssh') or ShowRunAllParse.find_child_objects(eachline, 'transport input ssh telnet') or ShowRunAllParse.find_child_objects(eachline, 'transport input all'):
                Check09 = 'FAIL'
                break
            else:
                Check09 = 'PASS'
        
        if Check09 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "ProhibitTelnetConnections"' %hostname )
        elif Check09 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "ProhibitTelnetConnections"' %hostname )
        else:
            print("No Check09 Value")
        #
        #**************************************************************************************************#
        #
        # CdpDisableExternalIfaces                  --- CdpDisableExternalIfaces
        """
            MR14:: Disable neighbour discovery for external facing interfaces 
                Consider each of the following conditions in order:
                    Evaluate the following condition:
                        PASSED if a line matching re.compile('no cdp run') is found.
                        otherwise, FAILED
                    If it is PASSED, perform the following:
                        Always PASSED
                    If the condition was not met, continue
                    ---
                    Evaluate the following condition:
                        For every section starting with a line matching re.compile('interface (?!Async|Tunnel|(Embedded-)?Service-Engine|Bundle-Ether)(.+)')
                        and ending with a line matching re.compile('!')
                            OR:
                                    Find all lines matching re.compile('\\s+ip address ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})'), then look in the first capture group.
                                    If the capture group does not contain a valid IPv4 address, then fail to check config.
                                        Valid Subnet 0: 10.0.0.0/8
                                        Valid Subnet 1: 192.168.0.0/16
                                        Valid Subnet 2: 172.16.0.0/12
                                    If IP address is in the valid subnets, then PASSED, otherwise FAILED.
                                ---
                                    PASSED if a line matching re.compile('\\s+no cdp enable') is found.
                                    otherwise, FAILED
                                ---
                                    PASSED if a line matching re.compile('\\s+shutdown') is found.
                                    otherwise, FAILED
                                ---
                        PASSED if every section is PASSED, otherwise FAILED
                    If it is PASSED, perform the following:
                        Always PASSED
                    If the condition was not met, continue
                    ---
                    If none of the above conditions were met:
                    Always ADVISORY
        """ 
        global Check10
        #
        find_Ifaces_pattern = re.compile(r'^interface\s(.+?)')
        CdpGlobalEnablePattern = re.compile(r'^cdp run')
        ValidSubnetPattern01=re.compile(r'^\sip address\s10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        ValidSubnetPattern02=re.compile(r'^\sip address\s192\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        ValidSubnetPattern03=re.compile(r'^\sip address\s172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        #
        IfacesList = []
        SubnetsList = []
        ValidPrivateSubnetsList = []
        PublicSubnetsList = []
        ExternalIfacesList = []
        #
        for eachline in ShowRunAllParse.find_objects(find_Ifaces_pattern):
            IfacesList.append(eachline.text)
            if ShowRunAllParse.find_child_objects(eachline, r'\sip\saddress\s(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))'):
                IpAddressListIOS= ShowRunAllParse.find_child_objects(eachline, r'\sip\saddress\s(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))')
                for eachitem in IpAddressListIOS:
                    SubnetsList.append(eachitem.text)
                    if re.findall(ValidSubnetPattern01, eachitem.text) or re.findall(ValidSubnetPattern02, eachitem.text) or re.findall(ValidSubnetPattern03, eachitem.text):
                        ValidPrivateSubnetsList.append(eachitem.text)
                    else:
                        PublicSubnetsList.append(eachitem.text)
        #                
        for eachline in ShowRunAllParse.find_objects(find_Ifaces_pattern):
            for PubSubnet in PublicSubnetsList:
                if ShowRunAllParse.find_child_objects(eachline, PubSubnet):
                    ExternalIfacesList.append(eachline.text)
        # print(ExternalIfacesList)
        #
        if ShowRunAllParse.find_objects(CdpGlobalEnablePattern):
            if ExternalIfacesList:
                for eachitem in ExternalIfacesList:
                    if ShowRunAllParse.find_child_objects(eachitem, ' cdp enable'):
                        Check10 = 'FAIL'
                        break
                    else:
                        Check10 = 'PASS'
            else:
                Check10 = 'PASS'
        else:
            Check10 = 'PASS'

        if Check10 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "CdpDisableExternalIfaces"' %hostname )
        elif Check10 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "CdpDisableExternalIfaces"' %hostname )
        else:
            print("No Check10 Value")          
                
        #
        #**************************************************************************************************#
        #
        # LldpDisableExternalIfaces             ---  LldpDisableExternalIfaces
        """
         no lldp transmit no lldp receive
        """ 
        global Check11
        #
        LldpGlobalEnablePattern = re.compile(r'^lldp run')
        #
        if ShowRunAllParse.find_objects(LldpGlobalEnablePattern):
            if ExternalIfacesList:
                for eachitem in ExternalIfacesList:
                    if ShowRunAllParse.find_child_objects(eachitem, ' no lldp transmit'):
                        Check11 = 'PASS'
                    else:
                        Check11 = 'FAIL'
                        break
            else:
                Check11 = 'PASS'
        else:
            Check11 = 'PASS'
        #
        if Check11 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "LldpDisableExternalIfaces"' %hostname )
        elif Check11 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "LldpDisableExternalIfaces"' %hostname )
        else:
            print("No Check11 Value")             
        #
        #**************************************************************************************************#
        #
        # MR66:: Disable IP ICMP redirect messages IpIcmpRedirectMsgs  --- IpIcmpRedirectMsgsDisabled
        """
         Disable IP ICMP redirect messages on external facing interfaces 
        """ 
        global Check12
        #
        #
        LoadExportedStatusFiles=open(f"./ConfigExportStatus/%s_Status.txt" %hostname,"r")
        LoadExportedStatusFiles.seek(0)
        ReadExportedStatusFiles=LoadExportedStatusFiles.read()
        UpIfacesList = parse_output(platform="cisco_ios",
                                    command=f"show ip int br",
                                    data=ReadExportedStatusFiles)
        #
        NEWUPLIST = []
        if UpIfacesList:
            for each_element in (UpIfacesList):
                if each_element['proto'] == 'up' and each_element['status'] == 'up':
                    NEWUPLIST.append(each_element['interface'])
        else:
            print("emptylist - NOuPIfacesList")
        #
        regex = re.compile(r"^Te([0-9]/[0-9]/[0-9])")
        TeList= []
        for nnn in NEWUPLIST:
            if 'Te' in nnn:
                TeList.append(nnn)
        for eachelement in TeList:
            ff = re.findall(regex, eachelement)
            NEWIfaceName= 'TenGigabitEthernet'+str(ff[0])
            NEWUPLIST.append(NEWIfaceName)
            NEWUPLIST.remove(eachelement)
        #
        UpIfaceListWIface = []
        for ii in NEWUPLIST:
            aaaa= 'interface '+ ii
            UpIfaceListWIface.append(aaaa)
        #
        if ExternalIfacesList:
            for eachitem in ExternalIfacesList:
                if ShowRunAllParse.find_child_objects(eachitem, ' no ip redirects') and eachitem in UpIfaceListWIface:
                    Check12 = 'PASS'
                else:
                    Check12 = 'FAIL'
                    break
        else:
            Check12 = 'PASS'
        #
        if Check12 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "IpIcmpRedirectMsgsDisabled"' %hostname )
        elif Check12 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "IpIcmpRedirectMsgsDisabled"' %hostname )
        else:
            print("No Check12 Value")                    
        #
        #**************************************************************************************************#
        #
        # MR67:: Disable IP ICMP unreachable messages IpIcmpUnreachablesMsgs  --- IpIcmpUnreachablesMsgsDisabled
        """
         Disable IP ICMP unreachable messages on external facing interfaces 
        """ 
        global Check13
        #
        if ExternalIfacesList:
            for eachitem in ExternalIfacesList:
                if ShowRunAllParse.find_child_objects(eachitem, ' no ip unreachables') and eachitem in UpIfaceListWIface:
                    Check13 = 'PASS'
                else:
                    Check13 = 'FAIL'
                    break
        else:
            Check13 = 'PASS'

        #
        if Check13 == 'FAIL':
            print(f'❌ Node %s Failed for parameter  "IpIcmpUnreachablesMsgsDisabled"' %hostname )
        elif Check13 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "IpIcmpUnreachablesMsgsDisabled"' %hostname )
        else:
            print("No Check13 Value")  

        #
        #**************************************************************************************************#
        #
        # MR72:: Configure the source address for NTP  NTPSourceAddressConf  --- NTPConf
        """"
        ● [1] ntp source
        ● [2] ntp server
        ● [3] ntp status >> #Clock is unsynchronized #%NTP is not enabled. #Clock is unsynchronized
        """

        global Check14
        #
        NTPSourceAddressConf01 = re.compile(r'^ntp\ssource\s(Ethernet|GigabitEthernet)')
        NTPSourceAddressConf02 = re.compile(r'^ntp\ssource-interface\s')
        NTPSourceAddressConf03 = re.compile(r'^ntp\ssource\sVlan')
        NTPSRVConf = re.compile(r"^ntp\sserver\s")
        #
        ntpsycline = re.compile(r"Clock\sis\ssynchronized,\sstratum\s[0-9],\sreference\sis\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
        ntpunsycline = re.compile(r"Clock\sis\sunsynchronized")

        # cheching = parse2._find_line_OBJ(ntpsycline)
        # print(cheching[0].text)
        if ShowStatusParse._find_line_OBJ(ntpsycline):
            ntpsyncstatus = 'Synchronized'
        elif ShowStatusParse._find_line_OBJ(ntpunsycline):
            ntpsyncstatus = 'UnSynchronized'
        else:
            ntpsyncstatus = 'NtpNotEnabled'
        #
        if ShowRunAllParse.find_objects(NTPSourceAddressConf01) or ShowRunAllParse.find_objects(NTPSourceAddressConf02) or ShowRunAllParse.find_objects(NTPSourceAddressConf03) and ShowRunAllParse.find_objects(NTPSRVConf) and ntpsyncstatus == 'Synchronized':
            Check14 = 'PASS'
        else:
            Check14 = 'FAIL'
        
        if Check14 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "NTPConf"' %hostname )
        elif Check14 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "NTPConf"' %hostname )
        else:
            print("No Check14 Value")
        #
        #
        #**************************************************************************************************#
        #
        # MR58:: Set the SSH version SHHv2                      --- NtpSRVsCount
        """"
        ● [1] SSHv2 Enabled "show ip ssh" "SSH Enabled - version 2.0"
        ● [2] ip ssh version 2 "Command Existing"
        """

        global Check15
        #
        SSHv2Enabled = re.compile(r"SSH Enabled - version 2.0", re.IGNORECASE)
        SSHv2EnableCommand = re.compile(r'^ip ssh version 2')
        # print(ShowStatusParse._find_line_OBJ(SSHv2Enabled)[0].text)
        #
        if ShowStatusParse._find_line_OBJ(SSHv2Enabled) and ShowRunAllParse.find_objects(SSHv2EnableCommand):
            Check15 = 'PASS'
        else:
            Check15 = 'FAIL'
        #
        #
        if Check15 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "SHHv2"' %hostname )
        elif Check15 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "SHHv2"' %hostname )
        else:
            print("No Check15 Value")
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # MR59:: Set the IP domain name                     --- IpDomainName
        """"
        ● [1] ip domain name tahakom.com
        ● 

        MR59:: Set the IP domain name 
    PASSED if a line matching re.compile('ip domain[ -]name') is found.
    otherwise, FAILED
        """
        global Check16
        #
        IpDomainNameCommand = re.compile(r'^ip\sdomain\sname\stahakom\.com', re.IGNORECASE)
        #
        if ShowRunAllParse.find_objects(IpDomainNameCommand):
            # print(ShowRunAllParse._find_line_OBJ(IpDomainNameCommand)[0].text)
            Check16 = 'PASS'
        else:
            Check16 = 'FAIL'
        #
        #
        if Check16 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "IpDomainName"' %hostname )
        elif Check16 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "IpDomainName"' %hostname )
        else:
            print("No Check16 Value")
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # Define the time zone as UTC                           --- CLockTimeZone
        """"
        ● [1] "clock timezone GMT 3 0" or "clock timezone AST 3 0"
        ●   
        """
        global Check17
        #
        ClockTimeZone = re.compile(r'^clock\stimezone\sGMT\s3\s0', re.IGNORECASE)
        ClockTimeZone02 = re.compile(r'^clock\stimezone\sAST\s3\s0', re.IGNORECASE)
        #
        if ShowRunAllParse.find_objects(ClockTimeZone):
            Check17 = 'PASS'
            # print(ShowRunAllParse._find_line_OBJ(ClockTimeZone)[0].text)
        elif ShowRunAllParse.find_objects(ClockTimeZone02):
            Check17 = 'PASS'
            # print(ShowRunAllParse._find_line_OBJ(ClockTimeZone02)[0].text)
        else:
            Check17 = 'FAIL'
        #
        #
        if Check17 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "ClockTimeZone"' %hostname )
        elif Check17 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "ClockTimeZone"' %hostname )
        else:
            print("No Check17 Value")
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # Configure at least two NTP servers                        --- NtpSRVsCount
        """"
        ● [1] ntp server 10.173.1.13 maxpoll 10 minpoll 6 version 4 burst iburst
        ● [2] ntp server vrf Mgmt-vrf 10.173.1.13  or ntp server vrf TAHAKOM 10.173.1.13 or ntp server 10.30.5.66
        ● [3] This condition can be modified to be more specific about the SRvIPs configured after Infoblox/DDI implementation
        """
        global Check18
        #
        NtpSRVs = re.compile(r'^ntp\sserver\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', re.IGNORECASE)
        NtpSRVs02 = re.compile(r'^ntp\sserver\svrf\s(.+)\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', re.IGNORECASE)
        NtpSrvsList = []
        #
        #
        if ShowRunAllParse._find_line_OBJ(NtpSRVs):
            for ntp in ShowRunAllParse._find_line_OBJ(NtpSRVs):
                NtpSrvsList.append(ntp.text)
        else:
            pass
        #
        if ShowRunAllParse._find_line_OBJ(NtpSRVs02):
            for ntp2 in ShowRunAllParse._find_line_OBJ(NtpSRVs02):
                NtpSrvsList.append(ntp2.text)
        else:
            pass
        #
        #
        if len(NtpSrvsList) >= 2 :
            Check18 = 'PASS'
        else:
            Check18 = 'FAIL'
        #
        #
        if Check18 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "NtpSRVsCount"' %hostname )
        elif Check18 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "NtpSRVsCount"' %hostname )
        else:
            print("No Check18 Value")
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # SNMPv2Disabled                                    --- SNMPv2Disabled
        """"
        ● [1] snmp-server host 10.172.1.100 informs version 2c T@hakom!321#
        ● [2] snmp-server community T@hakom!321# RO
        ● [3] 
    NOT:
        OR:
                PASSED if a line matching re.compile('snmp-server community') is found.
                otherwise, FAILED
            ---
                PASSED if a line matching re.compile('snmp-server host ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) version 2c?') is found.
                otherwise, FAILED
            ---
        MLQ-VPN-Router#show snmp sessions brief
            Destination: 10.172.1.100.162, V2C community: T@hakom!321#

        
        """
        global Check19
        #
        DisableSnmpV2_02 = re.compile(r'^snmp-server\shost\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\sversion\s2c?')
        DisableSnmpV2 = re.compile(r'^snmp-server\shost\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\sinforms\sversion\s2c')
        SNMPv2Community = re.compile(r'^snmp-server\scommunity\s(.+)\s(.+)')
        #
        #
        if ShowRunAllParse._find_line_OBJ(DisableSnmpV2) or ShowRunAllParse._find_line_OBJ(DisableSnmpV2_02) or ShowRunAllParse._find_line_OBJ(SNMPv2Community):
            Check19 = 'FAIL'
        else:
            Check19 = 'PASS'
        #
        #
        #
        if Check19 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "SNMPv2Disabled"' %hostname )
        elif Check19 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "SNMPv2Disabled"' %hostname )
        else:
            print("No Check19 Value")
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # SNMPv3Enabled                                 --- SNMPv3Enabled
        """"
        ● [1] snmp-server host 10.172.1.100 traps version 3 priv nac udp-port 162 #PASSED if a line matching re.compile('snmp-server host (.+) version 3') is found
        ● [2] snmp-server group nac v3 priv                                       #PASSED if a line matching re.compile('snmp-server group (.+) v3') is found.
        ● [3] snmp-server view nac-view iso included                              #PASSED if a line matching re.compile('snmp-server view') is found

        Hint: Multiple groups found but not certain which one to use for which [ Groups: nac, nac-view, nac-group,SDWAN-GROUP]
        Hint: Multiple views found but not certain which one to use for which [ views: nac-view,v1default ...etc ]


        Malqa-RTR01-WAN#show snmp user
            User name: Tahkom-SDWAN
            Engine ID: 800000090300DC774C147900
            storage-type: nonvolatile        active
            Authentication Protocol: SHA
            Privacy Protocol: AES128
            Group-name: SDWAN-GROUP

        Malqa-RTR01-WAN#show snmp sessions brief
            %%SNMP manager not enabled
        """
        global Check20
        #
        SNMPv3Enabled = re.compile(r'^snmp-server\shost\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\straps\sversion\s3\spriv\s(.+)\sudp-port\s162?')
        SNMPv3Enabled01 = re.compile(r'^snmp-server\sgroup(.+)\sv3\spriv(.+)')
        SNMPv3Enabled02 = re.compile(r'^snmp-server\sview\s(.+)\siso\sincluded')
        SNMPv3Enabled03 = re.compile(r'Group-name:\s(.+)', re.IGNORECASE)
        #
        #
        if ShowRunAllParse._find_line_OBJ(SNMPv3Enabled) and ShowRunAllParse._find_line_OBJ(SNMPv3Enabled01) and ShowRunAllParse._find_line_OBJ(SNMPv3Enabled02) and ShowStatusParse._find_line_OBJ(SNMPv3Enabled03) :
            Check20 = 'PASS'
        else:
            Check20 = 'FAIL'
        #
        #
        #
        if Check20 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "SNMPv3Enabled"' %hostname )
        elif Check20 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "SNMPv3Enabled"' %hostname )
        else:
            print("No Check20 Value")
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # Define the AAA login authentication method  - AAALoginAuth  
        """"
        ● [1] aaa authentication login VTYISE group Malqa-PSN-Group local
        ● [2]                                                
        
        MR50:: Define the AAA login authentication method 
            PASSED if a line matching re.compile('aaa authentication login') is found.
            otherwise, FAILED
        
        """
        global Check21
        #
        AAALoginAuth = re.compile(r'^aaa\sauthentication\slogin\sVTYISE\sgroup\sMalqa-PSN-Group\slocal')
        #
        #
        if ShowRunAllParse._find_line_OBJ(AAALoginAuth):
            Check21 = 'PASS'
        else:
            Check21 = 'FAIL'
        #
        #
        #
        if Check21 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "AAALoginAuth"' %hostname )
        elif Check21 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "AAALoginAuth"' %hostname )
        else:
            print("No Check21 Value")
        #
        #
        #
        #**************************************************************************************************#
        #
        # Enable AAA Authorization   - AaaAuthorize
        """"
        ● [1] aaa authorization commands 15 default group Malqa-PSN-Group local
        ● [2]                                                
            PASSED if a line matching re.compile('aaa authorization commands') is found.
            otherwise, FAILED
        """
        global Check22
        #
        # AAA_Authen = re.compile(r'^aaa\sauthorization\scommands\s[0-9]{1,2}\sdefault\sgroup\s')
        AAA_Authen = re.compile(r'^aaa\sauthorization\scommands\s')
        #
        #
        if ShowRunAllParse._find_line_OBJ(AAA_Authen):
            Check22 = 'PASS'
        else:
            Check22 = 'FAIL'
        #
        #
        #
        if Check22 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "AAA Authorization"' %hostname )
        elif Check22 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "AAA Authorization"' %hostname )
        else:
            print("No Check22 Value")
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # Enable AAA accounting    - AAA_Accounting
        """"
        ● [1] aaa accounting commands 15 default start-stop group Malqa-PSN-Group
        ● [2] aaa accounting exec default start-stop group Malqa-PSN-Group                        
        ● [3] #aaa accounting system start-stop group Malqa-PSN-Group     # not included                      
            PASSED if a line matching re.compile('aaa authorization commands') is found.
            otherwise, FAILED
        """
        global Check23
        #
        # AAA_Accounting = re.compile(r'^aaa\saccounting\scommands\s[0-9]{1,2}\sdefault\sstart-stop\sgroup\s')
        AAA_Accounting = re.compile(r'^aaa\saccounting\scommands\s[0-9]{1,2}\sdefault\sstart-stop\sgroup\s')
        AAA_Accounting02 = re.compile(r'^aaa\saccounting\sexec\sdefault\sstart-stop\sgroup\s')
        #
        #
        if ShowRunAllParse._find_line_OBJ(AAA_Accounting) and ShowRunAllParse._find_line_OBJ(AAA_Accounting02):
            Check23 = 'PASS'
        else:
            Check23 = 'FAIL'
        #
        if Check23 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "AAA Accounting"' %hostname )
        elif Check23 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "AAA Accounting"' %hostname )
        else:
            print("No Check23 Value")
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # Define at least two TACACS servers --- TacacsSRVs
        """"
        ● [1]  At least two tacacs servers    ---- tacacs server Malqa-PSN01/Malqa-PSN02
        ● [2]                                   -- address ipv4 10.172.1.108
        ● [3]                                   -- aaa group server tacacs+ Malqa-PSN-Group
        
                    AND:
                    PASSED if a line matching re.compile('tacacs server .+') is found.
                    otherwise, FAILED
                ---
                    Let n be the number of lines that match re.compile(' address ipv4 ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})')
                    PASSED if n >= 2, otherwise FAILED
                ---
        ---
        
         address ipv4 10.172.1.10
        
        """
        global Check24
        #
        TacacsSRVs01 = re.compile(r'^tacacs\sserver\s')
        TacacsSRVs02 = re.compile(r'^\saddress\sipv4\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        TacacsSRVs03 = re.compile(r'^aaa\sgroup\sserver\stacacs\+\s')
        tacacsSrvsList = []
        #
        #
        if ShowRunAllParse._find_line_OBJ(TacacsSRVs01) and ShowRunAllParse._find_line_OBJ(TacacsSRVs02) and ShowRunAllParse._find_line_OBJ(TacacsSRVs03):
            for SRV in ShowRunAllParse._find_line_OBJ(TacacsSRVs01):
                tacacsSrvsList.append(SRV.text)
        else:
            pass
        #
        if len(tacacsSrvsList) >= 2:
            Check24 = 'PASS'
        else:
            Check24 = 'FAIL'
        #
        #
        if Check24 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "TacacsSRVs"' %hostname )
        elif Check24 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "TacacsSRVs"' %hostname )
        else:
            print("No Check24 Value")
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # Authenticate communication with TACACS server  --- TacacsSRVsAuthen
        """"
        ● [1]      ---- tacacs server Malqa-PSN02, key W@Z6$xsM2a0
    
        ---
        
         tacacs server Malqa-PSN02
            address ipv4 10.172.1.108
            key W@Z6$xsM2a0
            port 49
        
        """
        global Check25
        #
        #
        if ShowRunAllParse.find_objects(TacacsSRVs01):
            for eachline in ShowRunAllParse.find_objects(TacacsSRVs01):
                if ShowRunAllParse.find_child_objects(eachline, r' key '):
                    Check25 = 'PASS'
                else:
                    Check25 = 'FAIL'
                    break
        else:
            Check25 = 'FAIL'
        #
        #
        if Check25 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "TacacsSRVsAuthen"' %hostname )
        elif Check25 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "TacacsSRVsAuthen"' %hostname )
        else:
            print("No Check25 Value")
        #
        #
        #
        #
        #**************************************************************************************************#
        """"""
        #
        #
        # Set the source IP address for the TACACS  --- TacacsSrcIface
        """"
        ● [1]      ---- ip tacacs source-interface GigabitEthernet0/0
        ---
            MR57:: Set the source IP address for the TACACS 
                PASSED if a line matching re.compile('(^ip|^\\s+ip) tacacs source-interface (.+)') is found.
                otherwise, FAILED
        """
        
        """
        global Check26
        #
        TacacsSrcIface = re.compile(r'^ip\stacacs\ssource-interface\s(Ethernet|GigabitEthernet)')
        #
        if ShowRunAllParse.find_objects(TacacsSrcIface):
            Check26 = 'PASS'
        else:
            Check26 = 'FAIL'
        #
        #
        if Check26 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "TacacsSrcIface"' %hostname )
        elif Check26 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "TacacsSrcIface"' %hostname )
        else:
            print("No Check26 Value")
        #
        """
         #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        #
        # SwVersion  
        """"
        ● [1]      
        ---
            show version | inc Cisco IOS XE Software, Version|uptime|Last
            #Cisco IOS XE Software, Version 17.12.04
        """
        global Check27
        #
        #### Need Adjustement to accomodate IOS versions >> Ex. Node JED-CoreSW
        SwVersion = re.compile(r'Cisco\sIOS\sXE\sSoftware\,\sVersion\s(.+)', re.IGNORECASE)
        # SwVersion = re.compile(r'Cisco\sIOS\sXE{0,1}\s{0,1}Software\,(.+)\,\sVersion\s(.+)', re.IGNORECASE)
        #
        try:
            SwVersionLine = ShowStatusParse._find_line_OBJ(SwVersion)[0].text
            SwVersionExport =  re.search(SwVersion, SwVersionLine)
            CurrentSwVersion = SwVersionExport.group(1)
        except IndexError:
            CurrentSwVersion = "None"
        # print(Check27)
        #
        # Version = 
        if not CurrentSwVersion:
            Check27 = 'NoVersion'
            print('❌ No SoftWare Version Exported')
        else:
            Check27 = CurrentSwVersion
            print('🟢 Current SoftWare Version is %s' %CurrentSwVersion)
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        #
        # UpTime 
        """"
        ● [1]      
        ---
            show version | inc Cisco IOS XE Software, Version|uptime|Last
            #THM-ACI-MOB-INT uptime is 1 week, 3 days, 19 hours, 30 minutes
            #Last reload reason: PowerOn
        """
        global Check28
        #
        # UpTime = re.compile(r'%s\suptime\sis\s(.+),\s(.+),\s(.+),\s(.+)' %hostname)
        UpTime = re.compile(r'%s\suptime\sis\s(.+),\s(.+){1,4}' %hostname)
        # LastReload = re.compile(r'Last\sreload\sreason:\s(.+)Codes:')
        #
        try:
            ShowStatusParse._find_line_OBJ(UpTime)[0].text
            UpTimeLine = ShowStatusParse._find_line_OBJ(UpTime)[0].text
            UpTimeLineExport =  re.search(UpTime, UpTimeLine)
            CurrentUpTime = UpTimeLineExport.group(1)
        except IndexError:
            CurrentUpTime = "None"
        # print(CurrentUpTime)
        if not CurrentUpTime:
            Check28 = 'NoExportedUpTime'
            print('❌ No Exported UpTime')
        else:
            Check28 = CurrentUpTime
            print('🟢 Current UpTime is %s' %CurrentUpTime)
        #
        #
        #
        #**************************************************************************************************#
        #
        #
        # LastReloadReason
        """"
        ● [1]      
        ---
            show version | inc Cisco IOS XE Software, Version|uptime|Last
            #THM-ACI-MOB-INT uptime is 1 week, 3 days, 19 hours, 30 minutes
            #Last reload reason: PowerOn
        """
        global Check29
        #
        # LastReload = re.compile(r'Last\sreload\sreason:\s(PowerOn|Reload Command|CPUReset|Critical software exception|power-on)')
        LastReload = re.compile(r'Last\sreload\sreason\s{0,}:\s{0,}(PowerOn|Reload Command|CPUReset|Critical software exception|power-on|Power Failure or Unknown|Reload reason not captured|- From Active Switch. reload peer unit|Image Install)')
        #      
        try:
            LastReloadTimeLine = ShowStatusParse._find_line_OBJ(LastReload)[0].text
            LastReloadExport =  re.search(LastReload, LastReloadTimeLine)
            LastReloadReason = LastReloadExport.group(1)
        except IndexError:
            LastReloadReason = "None"
        # print(CurrentUpTime)
        if not LastReloadReason:
            Check29 = 'No LastReloadReason'
            print('❌ No Exported LastReloadReason')
        else:
            Check29 = LastReloadReason
            print('🟢 Last Reload Reason is %s' %LastReloadReason)
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        # print(NEWUPLIST)
                #
        #
        #
        #**************************************************************************************************#
        #
        #
        # For ports that are configured to be trunk ports limit VLANs on trunk ports    ---- TrunkVlansLimit
        """"
        ● [1]      
        ---

        """
        global Check30
        
        '''
        if ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\smode\strunk') and ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\strunk\sallowed\svlan\s[0-9]{1,4}-[0-9]{1,4}'):
            TrunkPortswithVlanSetcfg.append(ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\smode\strunk') and ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\strunk\sallowed\svlan\s[0-9]{1,4}-[0-9]{1,4}')) 
        else:
            pass
        

        if ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\smode\strunk') and ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\strunk\sallowed\svlan\sall'):
            TrunkPortswithNoVlanSetcfg.append(ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\smode\strunk') and ShowRunAllParse.find_parent_objects(r'interface', r'\sswitchport\strunk\sallowed\svlan\sall'))
        else:
            pass

        for each in TrunkPortswithVlanSetcfg[0]:
            TrunkPortswithVlanSet.append(each.text)
        for each333 in TrunkPortswithNoVlanSetcfg[0]:
            TrunkPortswithNoVlanSet.append(each333.text)


        # print(TrunkPortswithVlanSet)
        res = [ele for ele in TrunkPortswithNoVlanSet if ele not in TrunkPortswithVlanSet]
        res2 = [ele for ele in res if ele in UpIfaceListWIface]
        FailTrunkifacelist = []
        for element in res:
            if ShowRunAllParse.find_child_objects(element, r' no shutdown') and ShowRunAllParse.find_child_objects(element, r'\sswitchport\strunk\sallowed\s'):
                FailTrunkifacelist.append(element) 
            else:
                pass
        '''
        #switchport trunk allowed vlan 2250,2251,2310
        # print(DeviceRole)
        TrunkPortsList = []
        TrunkPortswithNoVlanLimitx = []
        TrunkPortswithVlanLimitx = []
        
        if DeviceRole == 'CiscoSwitch':
            for oo in UpIfaceListWIface:
                if ShowRunAllParse.find_parent_objects(oo, r'\sswitchport\smode\strunk') and ShowRunAllParse.find_parent_objects(oo, r'\sswitchport\strunk\sallowed\svlan\s'):
                    TrunkPortsList.append(oo) 
            #
            for oo2 in TrunkPortsList:
                if ShowRunAllParse.find_parent_objects(oo2, r'\sswitchport\strunk\sallowed\svlan\s[0-9]{1,4}-[0-9]{1,4}') or ShowRunAllParse.find_parent_objects(oo2, r'\sswitchport\strunk\sallowed\svlan\s[0-9]{1,4},[0-9]{1,4}'):
                    TrunkPortswithVlanLimitx.append(oo2)
                else:
                    TrunkPortswithNoVlanLimitx.append(oo2)
            #
            TrunkPortswithNoVlanLimit = list(set(TrunkPortswithNoVlanLimitx))
            TrunkPortswithVlanLimit = list(set(TrunkPortswithVlanLimitx))
            if not TrunkPortswithNoVlanLimit:
                Check30 = 'PASS'
                print(f'🟢 Node %s Passed for parameter "TrunkVlansLimit"' %hostname )
            else:
                Check30 = 'FAIL'
                print(f'❌ Node %s Failed for parameter "TrunkVlansLimit "' %hostname)
        else:
            Check30 = 'NA'
            print(f'🟢 Node %s is Router NA for "TrunkVlansLimit"' %hostname )
        #
        # print(TrunkPortswithNoVlanLimit)
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        # ShutDown unused device Physical Interfaces - IfacesNotShut
        #
        """
        can use #show interfaces status for switches with notconnect output also can use same show for Vlan1 checks
        """
        global Check31
        NotShutIfaces = []
        if UpIfacesList:
            for each_element in (UpIfacesList):
                if each_element['proto'] == 'down' and each_element['status'] == 'down':
                    NotShutIfaces.append(each_element['interface'])
                else:
                    continue
        else:
            print("emptylist - ")
        # print(NotShutIfaces)
        NotShutIfacesList = list(set(NotShutIfaces))
        # print(NotShutIfacesList)
        if not NotShutIfacesList:
            Check31 = 'PASS'
            print(f'🟢 Node %s Passed for parameter "IfacesNotShut"' %hostname )
        else:
            Check31 = 'FAIL'
            print(f'❌ Node %s Failed for parameter "IfacesNotShut "' %hostname)
        #
        #
        #
        #
        #
        #
        #
        #
        #
        #**************************************************************************************************#
        # Region
        #
        """
        ###Region
        """
        global Check32
        Check32 = self.Region
               #
        #
        #
        #**************************************************************************************************#
        #
        #
        # Platform
        """"
        ● [1]      
        ---
            show platform | inc Chassis type:
            #Chassis type: C8300-2N2S-4T2X
            #Model Number                       : C9200L-24T-4X
        """
        global Check33
        #
        # LastReload = re.compile(r'Last\sreload\sreason:\s(PowerOn|Reload Command|CPUReset|Critical software exception|power-on)')
        # Platform = re.compile(r'Last\sreload\sreason\s{0,}:\s{0,}(PowerOn|Reload Command|CPUReset|Critical software exception|power-on|Power Failure or Unknown|Reload reason not captured|- From Active Switch. reload peer unit|Image Install)')
        # Platform01 = re.compile(r'Chassis type:\s(.+)')
        # Platform02= re.compile(r'Model Number\s{0,}:\s(.+)')
        #      
        if DeviceRole == 'CiscoSwitch':
            Platform = re.compile(r'Model Number\s{0,}:\s(.+)')
        else:
            Platform = re.compile(r'Chassis type:\s(.+)')
        # print(Platform)
        try:
            PlatformTimeLine = ShowStatusParse._find_line_OBJ(Platform)[0].text
            LastReloadExport =  re.search(Platform, PlatformTimeLine)
            PlatformExport = LastReloadExport.group(1)
        except IndexError:
            PlatformExport = "None"
        # print(CurrentUpTime)
        if not PlatformExport:
            Check29 = 'No LastReloadReason'
            print('❌ No Exported Platform')
        else:
            Check33 = PlatformExport
            print('🟢 Platform is %s' %PlatformExport)
        #
        #
        #
        #
        #**************************************************************************************************#
        #
        
        
        

        
        



















        # return Check01,Check02,Check03,Check04,Check05,Check06,Check07,Check08,Check09,Check10,Check11,Check12,Check13,Check14,Check15,Check16,Check17,Check18,Check19,Check20,Check21,Check22,Check23,Check24,Check25,Check26,Check27,Check28,Check29,Check30,Check31,Check32,Check33
        return Check01,Check02,Check03,Check04,Check05,Check06,Check07,Check08,Check09,Check10,Check11,Check12,Check13,Check14,Check15,Check16,Check17,Check18,Check19,Check20,Check21,Check22,Check23,Check24,Check25,Check27,Check28,Check29,Check30,Check31,Check32,Check33
    
        
    def ExportedData(self, hostname,MgmtIP) -> csv:
        data = {
            'Hostname': [hostname],
            'IPADDRESS': [MgmtIP],
            'Region' : [Check32],
            'EncryptConfigurationPasswords': [Check01],
            'Create Fallback Account': [Check02],
            'PasswordRetryLockout' : [Check03],
            'Configure inactivity time-out for the sessions ' : [Check04],
            'DisableDHCPServices' : [Check05],
            'DisableHTTPService' : [Check06],
            'DisableHTTPSService' : [Check07],
            'DisableTFTPService' : [Check08],
            'ProhibitTelnetConnections' : [Check09],
            'CdpDisableExternalIfaces' : [Check10],
            'LldpDisableExternalIfaces' : [Check11],
            'IpIcmpRedirectMsgsDisabled' : [Check12],
            'IpIcmpUnreachablesMsgsDisabled' : [Check13],
            'NTPConf' : [Check14],
            'NtpSRVsCount' : [Check18],
            'SHHv2' : [Check15],
            'IpDomainName' : [Check16],
            'CLockTimeZone' : [Check17],
            'SNMPv2Disabled' : [Check19],
            'SNMPv3Enabled' : [Check20],
            'AAA_Author' : [Check21],
            'AAA_Authen' : [Check22],
            'AAA_Accounting' : [Check23],
            'TacacsSRVs' : [Check24],
            'TacacsSRVsAuthen' : [Check25],
            # 'TacacsSrcIface' : [Check26],
            'CurrentSwVersion' : [Check27],
            'CurrentUpTime' : [Check28],
            'LastReloadReason' : [Check29],
            'TrunkVlansLimit' : [Check30],
            'IfacesNotShut' : [Check31],
            'Platform' : [Check33]
            }
        #
        df = pd.DataFrame(data)
        df.to_csv('OutputReport.csv', mode='a', index=False, header=False)
        return csv
        #
        #
        #