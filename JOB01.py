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
        Commands = ['show ip route','show ip int br']
        for CommandsList in Commands:
           CommandsListOutput = net_connect.send_command(CommandsList)
           newfile2=open(NewFilePathName, "a")
           newfile2.write(CommandsListOutput)
           newfile2.close()
        

        # UpIfacesList_raw=net_connect.send_command(f"show ip int br")
        # UpIfacesList = parse_output(platform="cisco_ios",
        #                             command=f"show ip int br",
        #                             data=UpIfacesList_raw)
        net_connect.disconnect()       # Disconnect from the device
        print(f"🟢 Export-Job Successful for device  {self.hostname}")
        # print(UpIfacesList)
        return newfile, newfile2

        #    CommandsListOutput = net_connect.send_command(CommandsList, use_textfsm=True)
        #    CommandsListOutput = net_connect.send_multiline(CommandsList)   
        #    CommandsListOutputs = str(CommandsListOutput)


    def CiscoCheckList(self, hostname, FileExport, MgmtIP, NewFileName) :
        
        parse=CiscoConfParse(f"./ConfigExport/%s.txt" %hostname)
        
        ##Encrypt configuration passwords 
        global Check01
        Check01=""
        Encrypt_conf_pwds_pattern1 = re.compile(r'^username\s(.+?)\sprivilege\s([0-9]{1,2})\spassword\s0\s')
        Encrypt_conf_pwds_pattern2 = re.compile(r'^username\s(.+?)\spassword\s0\s') #Hint this Rule also catches the above regex
        clearpwdslist = []
        for obj1 in parse.find_objects(Encrypt_conf_pwds_pattern1):
            clearpwdslist.append(obj1.text)    
        
        for obj2 in parse.find_objects(Encrypt_conf_pwds_pattern2):  
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
        if parse.find_objects(Tiger0neAccount):
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
        if parse.find_objects(PasswordRetryLockout):
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
        for eachline in parse.find_objects(find_lines_pattern):
            if parse.find_child_objects(eachline, 'exec-timeout'):
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
        if parse.find_objects(DisableDHCPServices):
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
        if parse.find_objects(DisableHTTPService):
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
        if parse.find_objects(DisableHTTPSService):
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
        if parse.find_objects(DisableTFTPService):
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
        for eachline in parse.find_objects(find_lines_pattern):
            if parse.find_child_objects(eachline, 'transport input telnet') or parse.find_child_objects(eachline, 'transport input telnet ssh') or parse.find_child_objects(eachline, 'transport input ssh telnet') or parse.find_child_objects(eachline, 'transport input all'):
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
        for eachline in parse.find_objects(find_Ifaces_pattern):
            IfacesList.append(eachline.text)
            if parse.find_child_objects(eachline, r'\sip\saddress\s(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))'):
                IpAddressListIOS= parse.find_child_objects(eachline, r'\sip\saddress\s(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))')
                for eachitem in IpAddressListIOS:
                    SubnetsList.append(eachitem.text)
                    if re.findall(ValidSubnetPattern01, eachitem.text) or re.findall(ValidSubnetPattern02, eachitem.text) or re.findall(ValidSubnetPattern03, eachitem.text):
                        ValidPrivateSubnetsList.append(eachitem.text)
                    else:
                        PublicSubnetsList.append(eachitem.text)
        #                
        for eachline in parse.find_objects(find_Ifaces_pattern):
            for PubSubnet in PublicSubnetsList:
                if parse.find_child_objects(eachline, PubSubnet):
                    ExternalIfacesList.append(eachline.text)
        #
        if parse.find_objects(CdpGlobalEnablePattern):
            if ExternalIfacesList:
                for eachitem in ExternalIfacesList:
                    if parse.find_child_objects(eachitem, ' cdp enable'):
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
        if parse.find_objects(LldpGlobalEnablePattern):
            if ExternalIfacesList:
                for eachitem in ExternalIfacesList:
                    if parse.find_child_objects(eachitem, ' no lldp transmit'):
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
        tt=open(f"./ConfigExportStatus/%s_Status.txt" %hostname,"r")
        tt.seek(0)
        xx=tt.read()
        UpIfacesList = parse_output(platform="cisco_ios",
                                    command=f"show ip int br",
                                    data=xx)
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
                if parse.find_child_objects(eachitem, ' no ip redirects') and eachitem in UpIfaceListWIface:
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
                if parse.find_child_objects(eachitem, ' no ip unreachables') and eachitem in UpIfaceListWIface:
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
        MR72:: Configure the source address for NTP 
            Consider each of the following conditions in order:
            Evaluate the following condition:
                PASSED if a line matching re.compile('\\s?ntp source') is found.
                otherwise, FAILED
            If it is PASSED, perform the following:
                Always PASSED
            If the condition was not met, continue
            ---
            Evaluate the following condition:
                PASSED if a line matching re.compile('\\s?s?ntp source-interface') is found.
                otherwise, FAILED
            If it is PASSED, perform the following:
                Always PASSED
            If the condition was not met, continue
            ---
            Evaluate the following condition:
                PASSED if a line matching re.compile('\\sntp source Vlan') is found.
                otherwise, FAILED
            If it is PASSED, perform the following:
                Always PASSED
            If the condition was not met, continue
            ---
            Evaluate the following condition:
                PASSED if a line matching re.compile('\\s?ntp server') is found.
                otherwise, FAILED
            If it is PASSED, perform the following:
                Find every line matching re.compile('ntp server (?:vrf [^ ]+ )?([^ ]+).*$')
                and use it as the input to:
                    PASSED if a line matching re.compile('.* source') is found.
                    otherwise, FAILED
            If the condition was not met, continue
            ---
        If none of the above conditions were met:
            Always FAILED   
        """ 
        global Check14
        #
        NTPSourceAddressConf01 = re.compile(r'^ntp\ssource\s(Ethernet|GigabitEthernet)')
        NTPSourceAddressConf02 = re.compile(r'^ntp\ssource-interface\s')
        NTPSourceAddressConf03 = re.compile(r'^ntp\ssource\sVlan')
        NTPSRVConf = re.compile(r"^ntp\sserver\s")
        if parse.find_objects(NTPSourceAddressConf01) or parse.find_objects(NTPSourceAddressConf02) or parse.find_objects(NTPSourceAddressConf03) and parse.find_objects(NTPSRVConf):
            Check14 = 'PASS'
        else:
            Check14 = 'FAIL'
        
        if Check14 == 'FAIL':
            print(f'❌ Node %s Failed for parameter "NTPSourceAddressConf"  ' %hostname )
        elif Check14 == 'PASS': 
            print(f'🟢 Node %s Passed for parameter "NTPSourceAddressConf" ' %hostname )
        else:
            print("No Check14 Value")
        
        
        
        
        
        
        
        
        
        
        
        



















        return Check01,Check02,Check03,Check04,Check05,Check06,Check07,Check08,Check09,Check10,Check11,Check12,Check13,Check14
    
        
    def ExportedData(self, hostname,MgmtIP):
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
            'NTPSourceAddressConf' : [Check14]
            }
        
        df = pd.DataFrame(data)
        df.to_csv('OutputReport.csv', mode='a', index=False, header=False)
    
    def upinterfaceslist(self, mgmt_acl: Optional[list[dict[str, str]]] = None):
        """
        Print out the current status of interfaces
        THis function pending on appending CiscoDeviceConfigsExport function to output list
        """

        if mgmt_acl is None:
            mgmt_acl = self.CiscoDeviceConfigs()
        NEWUPLIST = []
        for each_element in (mgmt_acl):
            if each_element['proto'] == 'up':
                if each_element['status'] == 'up' :
                    NEWUPLIST.append(each_element['intf'])
                    # print(each_element['intf'])
        # print(f"This is the new list  " + str(NEWUPLIST))