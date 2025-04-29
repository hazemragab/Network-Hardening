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