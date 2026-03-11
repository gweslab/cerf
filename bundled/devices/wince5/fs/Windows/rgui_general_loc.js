//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//
// Use of this source code is subject to the terms of the Microsoft end-user
// license agreement (EULA) under which you licensed this SOFTWARE PRODUCT.
// If you did not accept the terms of the EULA, you are not authorized to use
// this source code. For a copy of the EULA, please see the LICENSE.RTF on your
// install media.
//
// Messages must be formated in 3 or 5 parts to support automated localization.
L_AM_Message = "AM";
L_Always_Message = "Always";
L_And_Message = "and";
L_BTNAdd_Message = "Add";
L_BTNApply_Message = "Apply changes";
L_BTNCancel_Message = "Cancel changes";
L_BTNClear_Message = "Clear";
L_BTNRelease_Message = "Release";
L_BTNRenew_Message = "Renew";
L_BTNReset_Message = "Reset";
L_BTNUpdate_Message = "Update";
L_BaseStationName_Message = "Gateway name:";
L_Between_Message = "between";
L_Broadband_Message = "Broadband Connection:";
L_CEBuild_Message = "Windows CE Build Version:";
L_CEVersion_Message = "Windows CE Version:";
L_COLBlock_Message = "Block";
L_COLDelete_Message = "Delete";
L_COLEdit_Message = "Edit";
L_COLFilter_Message = "Filter";
L_COLIP_Message = "IP address/hostname";
L_COLOP_Message = "Outbound port(s)";
L_COLProtocol_Message = "Protocol";
L_Clients_Message = "Number of clients:";
L_DHCPEnabled_Message = "DHCP Enabled:";
L_DHCPEnd_Message = "DHCP ending address (optional):";
L_DHCPServer_Message = "DHCP server:";
L_DHCPStart_Message = "DHCP starting address (optional):";
L_DNS1_Message = "DNS1:";
L_DNS2_Message = "DNS2:";
L_DNSPrimary_Message = "Prefered DNS server:";
L_DNSSecondary_Message = "Alternate DNS server:";
L_Delete_Message = "Delete";
L_Disabled_Message = "Disabled";
L_Edit_Message = "Edit";
L_Enabled_Message = "Enabled";
L_Fri_Message = "Friday";
L_From_Message = "From";
L_Gateway_Message = "Default gateway:";
L_HostName_Message = "Host name";
L_IP_Message = "IP address:";
L_LeaseTime_Message = "Lease time for assigned IP address:";
L_LocalDomain_Message = "Local domain name (optional):";
L_LocalIP_Message = "Local IP address:";
L_MACAddress_Message = "MAC address";
L_Mon_Message = "Monday";
L_PM_Message = "PM";

XXX_L_PageBlurb_Message = "Modify the IP address of your base station and establish the Dynamic Host Configuration Protocol (DHCP) for your local area network on this page. When you enable the DHCP server, the base station allocates IP addresses from the specified DHCP address range to each device on your network. The lease time determines how frequently the IP address of each device must be renewed.";
XXX_L_PageBlurb_Message ="To block a computer (also known as a \"client\") on your network from accessing specific data over the Internet, type the IP address of the computer in the box below, and then enter the outbound ports and select the protocol for the type of data you want to block. Next, enter the days and times when you want to prevent that computer from accessing the Internet. To enable the filter, select the <B>Block</B> check box.";
XXX_L_PageTitle_Message = "Client Filtering";
XXX_L_PlatformID_Message = "PlatformID:";
L_Sat_Message = "Saturday";
XXX_L_SecBlurbDHCP_Message = "The DHCP client list displays the computers and other devices with an active DHCP lease on your network. If you reset your base station, only those devices that request or renew an IP address after the reset will appear in this list. <BR><BR>";
XXX_L_SecBlurbLAN_Message = "This section displays a summary of settings for your LAN.<BR><BR>";
XXX_L_SecBlurbStationInfo_Message = "<BR><BR>";
XXX_L_SecBlurbWAN_Message = "This section displays a summary of your Internet settings. When you experience problems connecting to the Internet, you can renew the base station WAN IP address. connecting to the Internet, you can renew the base station WAN IP address. For information about releasing and renewing IP addresses, click <B>Help.</B><BR><BR>";
XXX_L_SecTitleDHCP_Message = "DHCP client list";
XXX_L_SecTitleLAN_Message = "Local Area Network (LAN) settings";
XXX_L_SecTitleStationInfo_Message = "Base station information";
XXX_L_SecTitleWAN_Message = "Wide Area Network (WAN) settings Dynamic";

L_Subnet_Message = "Subnet mask:";
L_Sun_Message = "Sunday";
L_TCP_Message = "TCP";
L_Thr_Message = "Thursday";
L_To_Message = "to";
L_Tue_Message = "Tuesday";
L_UDP_Message = "UDP";
L_WANIP_Message = "WAN IP Address:";
L_WINS1_Message = "WINS1";
L_Wed_Message = "Wednesday";
L_PageDirty_Message					= "You have made unsaved changes to the page. Are you sure you want to leave without saving changes?";


// Error messages
L_IPBadLength_Error_1_Message					= "IP parts must be from 1 to 3 characters in length";
L_IPNonNumeric_Error_1_Message					= "IP parts must contain numbers only";
L_IPBadRange_Error_1_Message					= "IP parts must be from 0 - 255";
L_MACParts_Error_1_Message						= "MAC Parts can only be composed of the numbers 0-9 and characters A-F";
L_BadPW_Error_1_Message							= "Passwords must be from 3 to 16 characters in length";
L_PWDontMatch_Error_1_Message					= "Password and confimation password must match";
L_PortBadRange_Error_1_Message					= "Port specifications must be from 0 - 65535";
L_PortNonNumeric_Error_1_Message				= "Port specifications must contain numbers only";
L_PortEmpty_Error_1_Message						= "Port specification can not be empty";
L_AppForwardNullDesc_Error_1_Message			= "A description is required";
L_AppUDPorTCPRequired_Error_1_Message			= "Either inbound TCP or UDP ports are required";
L_PersistPortForwardNullDesc_Error_1_Message	= "A description is required";
L_BroadcastIP_Error_1_Message					= "Address can not be a broadcast address of '0.0.0.0' or '255.255.255.255'";
L_DuplicatePort_Error_1_Message					= "The inbound port can only be used by one server at a time.";
L_BadHour_Error_1_Message						= "The hour much be within the range 1 - 12.";
L_BadMinute_Error_1_Message						= "The minute must be within the range 0 - 59.";
L_BadSecond_Error_1_Message						= "The second must be within the range 0 - 59";
L_WindowsCETitle_Message						= "Windows CE Remote Management Tool";
L_SSIDLen_Error_1_Message						= "The network name can not be empty";
L_SSIDBad_Error_1_Message						= "The network name can only contains standard characters";
L_WirelessSecErr11_Error_1_Message				= 'The 64-bit WEP key must be 10 characters long';
L_WirelessSecErr12_Error_1_Message				= 'Your WPA passphrase must be between 8 and 63 characters long.';
L_WirelessSecErr13_Error_1_Message				= 'The 128-bit WEP key must be 26 characters long';
L_UserNameEmpty_Error_1_Message					= "User account name can not be empty.";
L_URLEmpty_Error_1_Message						= "The filter URL can not be empty.";
L_NetworkID_Error_1_Message					= "Address can not be a network ID (ending in .0 or .255)";


// Menu items
L_Home_Menu_1_Message = "Home";
L_DeviceManagment_Menu_1_Message = "Device Management";
L_ResetBaseStation_Menu_1_Message = "Reset Base Station";
L_BackUpRestoreSettings_Menu_1_Message = "Back Up / Restore Settings";
L_SetTime_Menu_1_Message = "Set Time";
L_ChangePassword_Menu_1_Message = "Change Password";
L_HostNameConfig_Menu_1_Message = "HostName Config";
L_AddDelNetworkAdapter_Menu_1_Message = "Add/Del Network Adapter";
L_SMBServerStatistics_Menu_1_Message = "SMB Server Statistics";
L_LocalAreaNetwork_Menu_1_Message = "Local Area Network";
L_WideAreaNetwork_Menu_1_Message = "Wide Area Network";
L_BasicSettings_Menu_1_Message = "Basic Settings";
L_Wireless_Menu_1_Message = "Wireless";
L_Security_Menu_1_Message = "Security";
L_WirelessSecurity_Menu_1_Message = "Wireless Security";
L_BaseStationMode_Menu_1_Message = "Base Station Mode";
L_Firewall_Menu_1_Message = "Firewall";
L_ApplicationPortForwarding_Menu_1_Message = "Application Port Forwarding";
L_PortForwarding_Menu_1_Message = "Port Forwarding";
L_VirtualDMZ_Menu_1_Message = "Virtual DMZ";
L_MACFiltering_Menu_1_Message = "Wireless Access Control ";
L_ClientFiltering_Menu_1_Message = "Client Filtering";
L_ParentalControls_Menu_1_Message = "Parental Controls";
L_ParentalControlsRestrictions_Menu_1_Message = "Parental Controls Restrictions";
L_BaseStationLog_Menu_1_Message = "Base Station Log";
L_AddDelUsers_Menu_1_Message = "Add/Del Users";
L_AddDelShare_Menu_1_Message = "Add/Del Share";
L_Printer_Menu_1_Message = "Printer";
L_AddDelPrinter_Menu_1_Message = "Add/Del Printer";
L_PacketCapture_Menu_1_Message = "Packet Capture";
L_EventLog_Menu_1_Message = "Event Log";
L_WatsonMenu_Menu_1_Message = "Error Reporting";

L_PleaseWait_Message = "Please wait while your Gateway applies your settings.";
