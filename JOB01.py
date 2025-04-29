#! /usr/bin/env python
#
#
from dataclasses import dataclass
from typing import Optional
from netmiko import ConnectHandler
from ntc_templates.parse import parse_output
from ciscoconfparse2 import CiscoConfParse
import re
from ipaddress import ip_address
from pathlib import Path
import pandas as pd
import csv
#
#
import asyncio
import yaml
from scrapli.driver.core import AsyncIOSXEDriver
# from inv import DEVICES
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
        

        showrunall = ['show run all']
        net_connect = self.connect()   # Connect to the device
        for ShowRunAllCommand in showrunall:
            mgmt_acl_raw = net_connect.send_command(ShowRunAllCommand, delay_factor=5)
            newfile=open(FileExport, "a")
            newfile.write(mgmt_acl_raw )
            newfile.close

        Commands = ['show ip route','show ip int br']
        #NewFilePathName=(f"./ConfigExportStatus/%s_Status.txt" %hostname)
        for CommandsList in Commands:
           CommandsListOutput = net_connect.send_command(CommandsList)
           newfile2=open(NewFilePathName, "a")
           newfile2.write(CommandsListOutput)
           newfile2.close()
        
        net_connect.disconnect()       # Disconnect from the device
        print(f" 🟢🟢 Export-Job Successful for device  {self.hostname}")


                #    CommandsListOutput = net_connect.send_command(CommandsList, use_textfsm=True)
        #    CommandsListOutput = net_connect.send_multiline(CommandsList)   
        #    CommandsListOutputs = str(CommandsListOutput)



    def checking(self, hostname, FileExport, MgmtIP) :
        #print("checking")
        """
        Lookup and return the current hosts allowed
        telnet access to device.
        """
        ##Encrypt configuration passwords 
        tigerone_fallback_account = 'username T!ger0ne privilege 15 secret 9 '
        parse=CiscoConfParse(f"./ConfigExport/%s.txt" %hostname)


        Encrypt_conf_pwds_pattern1 = re.compile(r'^username\s(.+?)\sprivilege\s([0-9]{1,2})\ssecret\s[0-9]\s')
        Encrypt_conf_pwds_pattern2 = re.compile(r'^username\s(.+?)\sssecret\s')
        Encrypt_conf_pwds_pattern3 = re.compile(r'^username\s(.+?)\sprivilege\s([0-9]{1,2})\spassword\s')
        Encrypt_conf_pwds_pattern4 = re.compile(r'^username\s(.+?)\spassword\s')

        Encrypt_conf_pwds_fulllist = []
        for obj1 in parse.find_objects(Encrypt_conf_pwds_pattern1):
                Encrypt_conf_pwds_fulllist.append(obj1.text)

        for obj2 in parse.find_objects(Encrypt_conf_pwds_pattern2):
                Encrypt_conf_pwds_fulllist.append(obj2.text) 

        for obj3 in parse.find_objects(Encrypt_conf_pwds_pattern3):
            Encrypt_conf_pwds_fulllist.append(obj3.text)       
        
        for obj4 in parse.find_objects(Encrypt_conf_pwds_pattern4):
            Encrypt_conf_pwds_fulllist.append(obj4.text) 


        usrslist = []
        for usrs in Encrypt_conf_pwds_fulllist:
            if tigerone_fallback_account not in usrs:
                usrslist.append(usrs)

        # if usrslist != []:
        global Check01
        
        if not usrslist:
            print(f' Node %s passed for parameter  "Encrypt configuration passwords"  ' %hostname )
            Check01 = 'PASS'
        else:
            print(f' ❌ Node %s failed for parameter "Encrypt configuration passwords" ' %hostname )
            Check01 = 'FAIL'
        return Check01
    


        # myfile=Path(f"./wb.xlsx")
        # print(myfile)
        # DF1 = pd.DataFrame({'Hostname': [hostname], 'IPAdress':[MgmtIP]})
        # DF1 = [{'Hostname': hostname, 'IPAdress':MgmtIP, 'Encrypt configuration passwords' : Check01}]
        # writerx=pd.ExcelWriter(myfile, engine='xlsxwriter')
        # # writerx=pd.ExcelWriter(myfile, engine='xlsxwriter', mode='a', if_sheet_exists='overlay')
        # DF1.to_excel(writerx,'Sheet1')

        # if myfile.is_file():
        #     dframe=pd.read_excel(myfile, engine='xlsxwriter', sheet_name='sheet1')
        #     dfx=pd.DataFrame(dframe)
        #     df_appending=dfx.append(pd.DataFrame(DF1), columns=['Hostname','IPAdress'])
        #     writerx=pd.ExcelWriter(myfile, engine='xlsxwriter', mode='a', if_sheet_exists='overlay')
        #     df_appending.to_excel(writerx,'Sheet1')
        #     writerx.save()

            # writer = pd.ExcelWriter(myfile)
            # DF1.to_excel(writer, 'Sheet1', startrow=0, startcol=0)
            # # writer.save()
            # # data.to_csv("output_excel_file.xlsx", sheet_name="Sheet 1", index=False)


        # else:
        #     print('NO Such File Found')

        # for t in usrslist:
        #     print(t)
        
    def ExportedData(self, hostname,MgmtIP):
        
        # data = {'Hostname': [hostname],'IPADDRESS': [MgmtIP],'Encrypt_configuration_passwords': [Check01]}
        data = {'Hostname': [hostname],'IPADDRESS': [MgmtIP],'EncryptConfigurationPasswords': [Check01]}
        df = pd.DataFrame(data)
        df.to_csv('OutputReport.csv', mode='a', index=False, header=False)
        
        
        
        # myfile=Path(f"./wbbbbbb.csv")
        # DF1 = pd.DataFrame({'Hostname': hostname, 'IPAdress':MgmtIP, 'Encrypt configuration passwords' : [Check01]})
        # # DF1 = [{'Hostname': hostname, 'IPAdress':MgmtIP, 'Encrypt configuration passwords' : Check01}]
        # writerx=pd.ExcelWriter(myfile)
        #     # # writerx=pd.ExcelWriter(myfile, engine='xlsxwriter', mode='a', if_sheet_exists='overlay')
        # DF1.to_csv(writerx, encoding='utf-8', index=False, mode='a')

        """
        output_list  = []
        output_list.extend(DF1)                                 # add switch info to total output file

        output_filem = 'hostname' + '_merg.csv'                    #    merge 2 in 1 file
        with open(output_filem, mode='w', newline='') as file:     # Write the updated data to a new CSV file
            fieldnames = output_list[0].keys()
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_list)
        print("New CSV file  has been created as ", '_merg.csv')
        print(f" 🟢🟢 Check-Job Successful for device  {self.hostname}")
    
        """
    
    
    
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