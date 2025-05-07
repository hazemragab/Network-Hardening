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
            # 'session_log': self.FileExport,
        }
        net_connect = ConnectHandler(**device)
        
        return net_connect

    # def CiscoDeviceConfigs(self, hostname) -> list[dict[str, str]]:
    def CiscoDeviceConfigsExport(self, hostname, FileExport, NewFilePathName):   
        """
        Lookup and return the current hosts allowed
        telnet access to device.
        """
        global newfile, newfile2

        showrunall = ['show run all']
        net_connect = self.connect()   # Connect to the device
        for ShowRunAllCommand in showrunall:
            mgmt_acl_raw = net_connect.send_command(ShowRunAllCommand, delay_factor=5)
            newfile=open(FileExport, "a")
            newfile.write(mgmt_acl_raw )
            newfile.close

        
        #NewFilePathName=(f"./ConfigExportStatus/%s_Status.txt" %hostname)
        # Commands = ['show ip route', 'show ip int br', 'show ntp status']
        Commands = ['show ip route', 'show ip int br','show ntp status', 'show ip ssh']
        # CommandsListOutput = ""
        for CommandsList in Commands:
        #    CommandsListOutput = net_connect.send_command_timing(CommandsList, delay_factor=5)
           CommandsListOutput = net_connect.send_command(CommandsList)
           newfile2=open(NewFilePathName, "a")
           newfile2.write(CommandsListOutput)
           newfile2.close()
        #
        net_connect.disconnect()       # Disconnect from the device
        print(f"🟢 Export-Job Successful for device  {self.hostname}")
        # print(UpIfacesList)
        return newfile, newfile2

        #    CommandsListOutput = net_connect.send_command(CommandsList, use_textfsm=True)
        #    CommandsListOutput = net_connect.send_multiline(CommandsList)   
        #    CommandsListOutputs = str(CommandsListOutput)
        #    CommandsListOutput = net_connect.send_command_timing(CommandsList, delay_factor=5)


    def CiscoCheckList(self, hostname, FileExport, MgmtIP, NewFileName) :
        
        ShowRunAllParse=CiscoConfParse(FileExport)
        ShowStatusParse = CiscoConfParse(NewFileName, syntax='ios')
        
        ##Encrypt configuration passwords 
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
        
        
        
        ##Create a Fallback Account 
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
        

        #Configure the password retry lockout 
        """"
        aaa local authentication attempts max-fail 3
        """
        global Check03
        Check03=""
        PasswordRetryLockout = re.compile(r'^aaa\slocal\sauthentication\sattempts\smax-fail\s([0-9]{1,2})')
        # PasswordRetryLockout = re.compile(r'^aaa\slocal')
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
        
        #Configure inactivity time-out for the sessions 
        """"
        MR47:: Configure inactivity time-out for the sessions 
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
        #**************************************************************************************************#
        # 
        # Disable DHCP services
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
        # DisableHTTPService
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
        # DisableHTTPSService
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
        # DisableTFTPService
        """
        MR19:: Disable TFTP service 
        NOT:
        PASSED if a line matching re.compile('tftp-server') is found.
        otherwise, FAILED
        ---
        """ 
        global Check08
        # Check08=""
        
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
        # ProhibitTelnetConnections
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
        # CdpDisableExternalIfaces
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
        # LldpDisableExternalIfaces
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
        # MR66:: Disable IP ICMP redirect messages IpIcmpRedirectMsgs
        """
         Disable IP ICMP redirect messages on external facing interfaces 
        """ 
        global Check12
        #
        # IpIcmpRedirectMsgs = re.compile(r'^\s no ip redirects')
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
        # MR67:: Disable IP ICMP unreachable messages IpIcmpUnreachablesMsgs
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
        # MR72:: Configure the source address for NTP  NTPSourceAddressConf
        """
        """ 
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
        # MR58:: Set the SSH version SHHv2
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
        # MR59:: Set the IP domain name
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
        # Define the time zone as UTC 
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
        # Configure at least two NTP servers 
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
        

        
        
        
        
        
        
        
        
        
        
        
        



















        return Check01,Check02,Check03,Check04,Check05,Check06,Check07,Check08,Check09,Check10,Check11,Check12,Check13,Check14,Check15,Check16,Check17,Check18
    
        
    def ExportedData(self, hostname,MgmtIP) -> csv:
        data = {
            'Hostname': [hostname],
            'IPADDRESS': [MgmtIP],
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
            'CLockTimeZone' : [Check17]

            }
        #
        df = pd.DataFrame(data)
        df.to_csv('OutputReport.csv', mode='a', index=False, header=False)
        return csv
        #
        #
        #