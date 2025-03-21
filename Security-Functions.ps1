function Show-UserFromSid { param( [Parameter(Mandatory = $True)] [string]$SID)
    $SIDp = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $SIDp.Translate([System.Security.Principal.NTAccount])
    $objUser.Value
}

function Show-SidFromUser { param( [Parameter(Mandatory = $True)] [string]$User)
    $objUser = New-Object System.Security.Principal.NTAccount($User)
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}

function Show-IPConfig {
    Get-NetAdapter | Where-Object status -eq "Up" |
     ForEach-Object {
        $r = Find-NetRoute -InterfaceIndex $_.ifIndex -RemoteIPAddress 1.1.1.1
        @{"NIC" = $_.Name
            "Description" = $_.InterfaceDescription
            "Gateway" = $r.nexthop[1]
            "IP" = (Get-NetIPAddress -AddressFamily IPv4 -ifIndex $_.ifIndex).ipaddress }
         } |
     convertto-json |
      ConvertFrom-Json |
       Format-Table IP, Gateway, NIC, Description
}