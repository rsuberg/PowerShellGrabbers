
# "Export Offlice Licenses to CSV"
function Get-LicArray { param ([switch]$ShowEmail, [switch]$AllAccounts)
<#

.DESCRIPTION
Pulls MS365 license report. Uses GUI to log in, specify save file location, and several prompts.
When the file prompt appears, click "Cancel" to copy report to clipboard and not a file.

.PARAMETER ShowEmail
Shows emails during the interrogation of the service.

.PARAMETER AllAccounts
Reports all accounts in the tenant. Otherwise, will only report accounts that are enabled.

#> 
# This will create an array of users with what licenses they have
$err=""
try #see if connected
{
    Get-MsolDomain -ErrorAction Stop > $null
    Write-Output "Already connected to MSOnline"
}
catch 
{
    Write-Output "Prompt to log in"
    Connect-MsolService -ErrorVariable err -ErrorAction SilentlyContinue # before running.
	if($err.Count -ge 1) {
		Write-Output "Failed to connect. Terminating."
		return
	}
    Write-Output "Connected!"
}
#Load Modules for GUI
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName System.Windows.Forms
#[System.Reflection.Assembly]::LoadWithPartialName(“System.windows.forms”) | Out-Null

#Prompt for File to save to
$OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
$OpenFileDialog.initialDirectory = $initialDirectory
$OpenFileDialog.filter = “CSV Files (*.csv) | *.csv”
Write-Host "Prompt for Save File Name"
$OpenFileDialog.ShowDialog() | Out-Null
$endfile = $OpenFileDialog.filename
if(!($endfile -eq $null)){
	$opnfil=[Microsoft.VisualBasic.Interaction]::MsgBox("Open file with default CSV App? ",4100,'Export MS365 Licenses') #40960+4
	}


#Prompt to keep connection open
Write-Host "Prompt to keep session open"
$keep=[Microsoft.VisualBasic.Interaction]::MsgBox("Keep Connection Open? ",4100,'Export MS365 Licenses') #4096+4
 
#Create array of licenses available
$arr=[System.Collections.ArrayList]@()
$acclic=Get-MsolAccountSku | sort accountskuid -Descending
$accsku=$acclic | select AccountSkuId # ## CALCULATE AVAILABLE LICERNSES
$brand=$accsku.AccountSkuId[0].Split(":")[0]
$brand+=":"
Write-Host "Detected brand: $brand"
foreach ($acc in $accsku) {
    $foreach.current.AccountSkuId=$acc.AccountSkuId.Replace($brand,"")
    #write-host $foreach.current.accountskuid
    }
foreach ($acc in $acclic) {
    $foreach.current.AccountSkuId=$acc.AccountSkuId.Replace($brand,"")
    #write-host $foreach.current.accountskuid
    }
Write-Host "`nAvailable License types:"
$accsku.AccountSkuId

Write-Host 
$acclic | Select-Object AccountSkuId, ActiveUnits, ConsumedUnits ## Print License Counts
$licL=@($accsku.accountskuid)
## Investigate removing brand from AccountskuyID
#We now have AccountSkuID Broken into the plan type as an array

###attempt to replace accountskuid with one without reseller tag. Save to add to end of CSV file.

#Get users and loop through them to get each user's license as an array
if($AllAccounts) {
$usr=Get-MsolUser -All | sort UserPrincipalName | select userprincipalname,displayname
} else {
$usr=Get-MsolUser -All | sort UserPrincipalName | where islicensed -EQ $true | select userprincipalname,displayname
}

#Loop through users
foreach ($lp in  $usr) {
    $usrL=$lp
    $usrLic=Get-MsolUser -UserPrincipalName $usrL.UserPrincipalName | select -ExpandProperty licenses | select accountskuid
    foreach ($usrLicL in $usrLic) {
        $foreach.current.accountskuid=$usrLicL.accountskuid.Replace($brand,"")
        }
    
    $pso= [PSCustomObject] @{user=""}
    $pso|Add-Member -MemberType NoteProperty -Name "DisplayName" -Value ""
    foreach($lic in $licL) {
        $pso|Add-Member -MemberType NoteProperty -Name $lic -Value ""
        }
    $pso.user=$usrL.UserPrincipalName
    $pso.DisplayName=$usrL.DisplayName
    foreach ($usrLicL in $usrLic.accountskuid) {
        $pso.$usrLicL="Yes"
        }
    $arr+=$pso
    if ($ShowEmail) {write-host $usrl.DisplayName "`t " $usrl.UserPrincipalName}
    $pro=($arr.Count/$usr.Count)*100
    Write-Progress -Activity "Reading User Licenses" -PercentComplete $pro
    }
Write-Progress -Completed -Activity "Reading User Licenses"
Write-Host

#Save to file specified earlier
if ($endfile.Length -eq 0) {
    $arr | ConvertTo-Csv -NoTypeInformation | clip
    $endfile = "Clipboard."
    }
else
    {
    $arr | Export-Csv -NoTypeInformation $endfile 
	$s=$acclic | select AccountSkuId, ActiveUnits, ConsumedUnits
	# add-content -path $endfile -value $s ## Print License Counts ## NEEDS WORK - DOES NOT EXPORT CORRECTLY
	if($opnfil) {
		start $endfile
		}
    }
#Prompt with results
$numU=$arr.Count
$numL=$accsku.Count

$null=[Microsoft.VisualBasic.Interaction]::MsgBox("Export Complete. $numU Records `n $numL License Types available`n Saved to $endfile ",1,'Export MS365 Licenses')

if($keep -eq "No") {
    #Disconnect from service
    [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
    Write-Host "Disconnected from MSOLService"
	}
	else {
		write-host "Connection left open. Disconnect manually."
	}
}
# Get-LicArray 
