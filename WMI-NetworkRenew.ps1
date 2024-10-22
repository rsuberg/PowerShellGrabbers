﻿$networkresult = @{
    0="Successful, no reboot"
    1="Successful, reboot required"
    64="Method not supported on this platform"
    65="Unknown failure"
    66="Invalid subnet mask"
    67="An error occurred while processing an instance that was returned"
    68="Invalid input parameter"
    69="More than 5 gateways specified"
    70="Invalid IP address"
    71="Invalid gateway IP address"
    72="An error occurred while accessing the Registry for the requested information"
    73="Invalid domain name"
    74="Invalid host name"
    75="No primary/secondary WINS server defined"
    76="Invalid file"
    77="Invalid system path"
    78="File copy failed"
    79="Invalid security parameter"
    80="Unable to configure TCP/IP service"
    81="Unable to configure DHCP service"
    82="Unable to renew DHCP lease"
    83="Unable to release DHCP lease"
    84="IP not enabled on adapter"
    85="IPX not enabled on adapter"
    86="Frame or network number bounds error"
    87="Invalid frame type"
    88="Invalid network number"
    89="Duplicate network number"
    90="Parameter out of bounds"
    91="Access denied"
    92="Out of memory"
    93="Already exists"
    94="Path, file, or object not found"
    95="Unable to notify service"
    96="Unable to notify DNS service"
    97="Interface not configurable"
    98="Not all DHCP leases could be released or renewed"
    100="DHCP not enabled on adapter"
    101="Other (4294967295)"
    }



$colNetCards = Get-WmiObject " Win32_NetworkAdapterConfiguration Where (dhcpenabled = True) " # and (ipenabled = true)"
ForEach ($objNetCard in $colNetCards) {
   $res =  $objNetCard.RenewDHCPLease()
   $r=[convert]::ToInt32($res.ReturnValue,10)
   write-host "ifIndex="$objnetcard.Index "ifDescription="$objNetCard.Description.PadRight(50)  "Result="$res.ReturnValue "   `t" $networkresult[$r]
    }