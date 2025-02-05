#Network Functions
Function Show-NetInfo
iface (Index), interfacealias, IPAddress, SubnetMask, Gateway, DNSServers, DHCPEnabled, DHCPServer, 
(for dhcp renew, parameter includes ifaceindex)

Function Do-DhcpRenew { Param([int]$InterfaceIndex)
	Get-WmiObject Win32_NetworkAdapterConfiguration | where InterfaceIndex –eq $InterfaceIndex | select -Property InterfaceIndex, DHCPEnabled, DHCPLeaseObtained, DHCPServer, DNSDomain, Description, IPAddress, DefaultIPGateway | sort InterfaceIndex | fl
	$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex –eq $InterfaceIndex}
	$ans = $adapter.RenewDHCPLease()
	if($ans.ReturnValue -eq 0) {"Success, No Reboot Needed"} else { write-host "Error Code: " $ans.ReturnValue}
	Get-WmiObject Win32_NetworkAdapterConfiguration | where InterfaceIndex –eq $InterfaceIndex | select -Property InterfaceIndex, DHCPEnabled, DHCPLeaseObtained, DHCPServer, DNSDomain, Description, IPAddress, DefaultIPGateway | sort InterfaceIndex | fl

}


--------------
$xml=[xml](Get-Content C:\_BARCOM\config.xml) #ExplorerPlusPlus Config File

$xml.ExplorerPlusPlus.Settings.Setting

$xml.ExplorerPlusPlus.Settings.Setting.count
#DisplayFont
$xml.ExplorerPlusPlus.Settings.Setting.Item("9").name
$xml.ExplorerPlusPlus.Settings.Setting.Item("9").font
#DisplayCentreColor

Clear-Host; $tailsc = $(tailscale status --json) | ConvertFrom-Json; (($tailsc.Peer) | Get-Member | where MemberType -eq "NoteProperty") | foreach {$tailsc.Peer.($_.name) | select * } | sort HostName | ft HostName, Online, Active, OS, ExitNode, ExitNodeOption, Active, Relay, InNetworkMap, InMagicSock, InEngine, LastSeen, LastWrite, LastHandshake

Clear-Host; $rip = Read-Host "Partial PC Name"; $tailsc = $(tailscale status --json) | ConvertFrom-Json; (($tailsc.Peer) | Get-Member | where MemberType -eq "NoteProperty") | foreach {$tailsc.Peer.($_.name) | select * } | where HostName -like ("*"+$rip+"*") | sort HostName | ft HostName, Online, Active, OS, ExitNode, ExitNodeOption, Active, Relay, InNetworkMap, InMagicSock, InEngine, LastSeen, LastWrite, LastHandshake

Clear-Host; $rip = Read-Host "Partial PC Name"; $tailsc = $(tailscale status --json) | ConvertFrom-Json; (($tailsc.Peer) | Get-Member | where MemberType -eq "NoteProperty") | foreach {$tailsc.Peer.($_.name) | select * } | where HostName -like ("*"+$rip+"*") | sort HostName | fl *