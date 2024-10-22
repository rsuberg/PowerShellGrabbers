#Admin Audit

#Imports AD PS module
Import-module activedirectory

#Sets path to currently logged in user's Desktop
$UserPath = "$($env:USERPROFILE)\Desktop"

# Gathers necessary info and exports all to properly formatted CSV
Get-ADUser -Filter * -Properties name,lastlogondate,enabled | Sort-Object -Property lastlogondate -Descending | Select-Object -Property name,lastlogondate,enabled | Export-Csv -Path $UserPath\users.csv -NoTypeInformation
Get-ADUser -Filter * -Properties name,lastlogondate,enabled | Where-Object Enabled -eq $true | Sort-Object -Property lastlogondate -Descending | Select-Object -Property name,lastlogondate,enabled | Export-Csv -Path $UserPath\enabled.csv -NoTypeInformation
Get-ADGroupMember -Identity "Domain Admins" | Select-Object -Property name | Export-Csv -Path $UserPath\domainadmins.csv -NoTypeInformation
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object -Property name | Export-Csv -Path $UserPath\enterpriseadmins.csv -NoTypeInformation
Get-ADGroupMember -Identity "Administrators" | Select-Object -Property name | Export-Csv -Path $UserPath\admins.csv -NoTypeInformation

# Gets the number of days since last password set and exports all to properly formatted CSV
Get-ADUser -Filter * -Properties * | select name,@{N='Password Last Set'; E={(new-timespan -start $(Get-date $_.PasswordLastSet) -end (get-date)).days}} | Select-Object -Property name,"Password Last Set" | Export-Csv -Path $UserPath\pwdlastset.csv

(Get-ADUser -Filter * -Properties name,lastlogondate,enabled | where enabled -eq $true | where ObjectClass -eq "user").count