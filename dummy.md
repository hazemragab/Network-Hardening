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