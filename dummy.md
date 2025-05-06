"""

--------------------------------------------------------------------------------------

        # try:
        #     MgmtIP = ip_address(MgmtIP)
        # except ValueError:
        #     print(f"❌ The entry {MgmtIP} is not a valid IP address. Exiting")

--------------------------------------------------------------------------------------


   # for key in hosts_data:l
    #     #print(key)
    #     if key.values['host'] != None:
    #         print(key)
            # dict2.append[key:values]
    # print(dict2)

--------------------------------------------------------------------------------------

    # AllDevicesList = AllDevicesList[:len(AllDevicesList)-4]
    # print(AllDevicesList)
    # print(GroupDevicesDictionary)
    # print(type(GroupDevicesDictionary))
    # print(hosts_data)

--------------------------------------------------------------------------------------

    # print(AllDevicesList)
    # print(len(AllDevicesList))
    # AllDevicesList = AllDevicesList[:len(AllDevicesList)-4]
    # for dictionary in range(len(AllDevicesList)):
    #     MgmtIP_List = (AllDevicesList[dictionary]['host'])
    #     Dictionary_List=(AllDevicesList[dictionary])
        # print(MgmtIP_List)
        # print(Dictionary_List)

--------------------------------------------------------------------------------------

    for device in DEVICES:
        hostname = device['hostname']
        FileExport = (f"./ConfigExport/%s.txt" %hostname)
        MgmtIP = device['ipadd']
        port = 22

        # RunFn = NetworkAudit(MgmtIP, port, username, password, FileExport, hostname)    # Create a CiscoDeviceConfig Fn
        # print(f"Exporting ConfigurationFiles from device {RunFn.hostname}. to Directory ./ConfigsExport ")
        # print("-" * os.get_terminal_size().columns)
        #RunFn.CiscoDeviceConfigs()
        print("-" * os.get_terminal_size().columns)

        # print(hostname)
        # print(MgmtIP)
        # print(FileExport)
        # print(type(FileExport))

-----------------------------------------------------------------------------------------------------------------------

    DevicesListDictionary = hosts_data
    AllDevicesList = list(hosts_data.values()) ##STOPPEDHERE
    AllDevicesListType = type(list(hosts_data.values())[0])

-----------------------------------------------------------------------------------------------------------------------


    # print("-" * os.get_terminal_size().columns)
    # print(f'This is the list of group to be printed {GroupDevicesList}')           # Extract group of devices
    # print(f'This is the list of hosts_data to be printed {AllDevicesList}')           # Extract group of devices
    # print(type(AllDevicesList))
    # print("-" * os.get_terminal_size().columns)


"""

-----------------------------------------------------------------------------------------------------------------------



        """
        #DownInterfaces

        # intf_cmds=parse.find_parent_objects(['interface', 'shutdown'])
        # shut_intf_names=[" ".join(cmd.split()[1:]) for cmd in intf_cmds]
        # print(shut_intf_names)


        ### or
        # for intf_obj in parse.find_parent_objects(['interface', 'no shutdown']):
        #     intf_name = " ".join(intf_obj.split()[1:])
        #     print(f"Shutdown: {intf_name}")
        """
        
        
        """
        # Get all neighbor configuration branches
		branches = parse.find_object_branches(('router bgp',
											'neighbor',
											'remote-as'))
		
		# Get the local BGP ASN
		bgp_cmd = branches[0][0]
		local_asn = bgp_cmd.split()[-1]
		
		# Find EBGP neighbors for any number of peers
		for branch in branches:
			neighbor_addr = branch[1].split()[-1]
			remote_asn = branch[2].split()[-1]
			if local_asn != remote_asn:
				print("EBGP NEIGHBOR", neighbor_addr)
        """


    ------------------------------------------------------------------------------------------------------------------



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


        ----------------------------------------------------------------------------------------------------------------

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


        ----------------------------------------------------------------------------------------------------


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
        Encrypt_conf_pwds_pattern3 = re.compile(r'^username\s(.+?)\sprivilege\s([0-9]{1,2})\spassword\s0\s')
        Encrypt_conf_pwds_pattern4 = re.compile(r'^username\s(.+?)\spassword\s0\s')
        #username test6 password 0 hazemragab
        # username test7 privilege 15 password 0 hazemragab


        Encrypt_conf_pwds_fulllist = []
        for obj1 in parse.find_objects(Encrypt_conf_pwds_pattern1):
                Encrypt_conf_pwds_fulllist.append(obj1.text)

        for obj2 in parse.find_objects(Encrypt_conf_pwds_pattern2):
                Encrypt_conf_pwds_fulllist.append(obj2.text) 

        for obj3 in parse.find_objects(Encrypt_conf_pwds_pattern3):
            Encrypt_conf_pwds_fulllist.append(obj3.text)
            print(obj3.text)       
        
        for obj4 in parse.find_objects(Encrypt_conf_pwds_pattern4):
            Encrypt_conf_pwds_fulllist.append(obj4.text) 
            print(obj4.text)


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


        ---------------------------------------------------------------------------------------------------------------

        Encrypt_conf_pwds_pattern3 = re.compile(r'^username\s(.+?)\sprivilege\s([0-9]{1,2})\ssecret\s[0-9]\s')
        Encrypt_conf_pwds_pattern4 = re.compile(r'^username\s(.+?)\sssecret\s')
        

        # for obj3 in parse.find_objects(Encrypt_conf_pwds_pattern3):
        #     Encrypt_conf_secrets_fulllist.append(obj3.text)

        # for obj4 in parse.find_objects(Encrypt_conf_pwds_pattern4):
        #     Encrypt_conf_secrets_fulllist.append(obj4.text) 



        # if  not parse.find_objects(Tiger0neAccount):
        #     Check02 = 'FAIL'
        # else:
        #     Check01 = 'PASS'
        # print(Check02)


        ---------------------------------------------------------------------------------------------------


        # Encrypt_conf_secrets_fulllist = []
        # for obj3 in parse.find_objects(Tiger0neAccount):
        #     Encrypt_conf_secrets_fulllist.append(obj3.text)
        #     Tiger0neAccountString = obj3.text
        #     print(Tiger0neAccountString)
        # print(Encrypt_conf_secrets_fulllist)



        # for usrs in Encrypt_conf_secrets_fulllist:
        #     if tigerone_fallback_account not in usrs:
        #         Check02 = 'FAIL'
        #     else:
        #         Check02 = 'PASS'
        
        
        # if tigerone_fallback_account in Encrypt_conf_secrets_fulllist:
        #     Check02 = 'PASS'
        # elif tigerone_fallback_account not in Encrypt_conf_secrets_fulllist:
        #     Check02 = 'FAIL'
        # else:
        #     print('NO VALUE for Check02 tigerone_fallback_account value error')



---------------------------------------------------------------------------------------------------

    

---------------------------------------------------------------------------------------------------

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



---------------------------------------------------------------------------------------------------

    