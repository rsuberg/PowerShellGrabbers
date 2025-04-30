#
# Custom/Found Server Functions
#
function Show-WindowsRoles {
#function Show-WindowsRoles 
#Class: SERVER
	Import-Module ServerManager
	Clear-Host
	$env:COMPUTERNAME
	Write-Host
	Get-WindowsFeature | 
		Where-Object {$_.Installed -match "True"} | 
		ForEach-Object {
		$_.Name | Write-Host
	}
	if($PSVersionTable["psversion"].major -eq 2) {
		Get-WindowsFeature | Where-Object {$_.Installed} | Format-Table name, displayname, installed -AutoSize
	} else {
		Get-WindowsFeature | Where-Object InstallState -eq "Installed" | Format-Table -AutoSize
	}
}

Function Show-ADUserCount {
#Function Show-ADUserCount 
#Class: SERVER
#Requires -Version 3.0
	try {
        $ErrorActionPreference = "Continue"
	    Write-Host "`nLoading Module.`r" -NoNewLine
	    Import-Module ActiveDirectory
	    $usrs = Get-ADUser -Filter 'Enabled -eq $true'
		$admins = Get-ADGroupMember -Identity administrators
		$admins = $admins | Select-Object SamAccountName
		$stdusr = $usrs | where samaccountname -notin $admins.SamAccountName
		$admusr = $usrs | where SamAccountName -in $admins.SamAccountName | select samaccountname, objectguid
	    Write-Host "   Enabled Active User Count: " $usrs.count
	    Write-Host "Enabled Non-Admin User Count: " $stdusr.count
		write-Host "    Enabled Admin User Count: " $admusr.Count
		Write-Host "      Total Admin User Count: " $admins.Count
	    Write-Host
        }
    catch {
        Write-Host "`nCaught error checking with Active Directory`n"
        }
}

function Show-ADUserCountAlt {
	(Get-ADUser -Filter * -Property * | where enabled -eq $true ).count
}

Function Show-ExportUsrsWithAdminStatus {
	if($PSVersionTable.PSVersion.Major -lt 3.0) {Write-Host " PS Version too low " -ForegroundColor White -BackgroundColor Red}
	Import-Module ActiveDirectory
	$usrs = get-aduser -Filter 'enabled -eq "true"' | select SamAccountName, UserPrincipalName, Name, GivenName, Surname, Enabled | sort SamAccountName 
	$admins = Get-ADGroupMember -Identity administrators
	foreach ($usr in $usrs) {
		$adm = (!($usr.SamAccountName -notin $admins.SamAccountName))
		Write-Host $usr.SamAccountName " - "  $adm
		$usr | Add-Member -MemberType NoteProperty -Name IsAdmin -Value $adm
		}
	New-Item -ItemType Directory -Path C:\_BARCOM  -ErrorAction SilentlyContinue
	$usrs | Export-Csv -NoTypeInformation C:\_barcom\AD_ActiveUsers.cs
}

Function Show-ServerStatus {
#Function Show-ServerStatus 
#Class: SERVER
#WARNING: If run on workstation, must be in a logon session
	$ErrorActionPreference = "Continue"
	if( $env:USERDNSDOMAIN.length -ne 0) {"Domain Joined"} else {"Not a domain menber"}
	#Test not reliable. Test ( $env:userdomain -eq $env:COMPUTERNAME )
	$sc = (Get-SmbShare | where name -NotLike "*$").count
	if($sc -ne 0) {"Viewable Shares exist - $sc  found." } else {"No public shares reported"}
	Write-Host "ComputerName   :  $env:COMPUTERNAME"
	Write-Host "LOGONSERVER    :  $env:LOGONSERVER"
	Write-Host "Reported domain:  $env:USERDNSDOMAIN"
	Write-Host "USERDOMAIN     :  $env:USERDOMAIN"
}

function Show-AvailableCustomfunctions {
	write-output " "
	Get-Item -Path function:\  | findstr "Show- Dell- Pax8-" | Sort.exe # Name# Format-Table CommandType, Name |
	write-output " "
}

function Show-RunningVMInfo {
	#Get-VM | where state -eq "Running" | ft VMName, @{e=$_.AutomaticStartAction;l="StartAction"}, @{e=$_.AutomaticStopAction;l="StopAction"}, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
	Get-VM | where state -eq "Running" | ft VMName,AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
	# Get-VM | where state -eq "Running" | ft VMName, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
	$vhds = Get-VM | where state -eq "Running" | select -expandproperty HardDrives
	$vhds | ft VMName, DiskNumber, Path -AutoSize -Wrap
	$vhds | where  DiskNumber -eq $null | get-vhd | ft VhdFormat, VhdType, FileSize, Size, MinimumSize, Attached, Path -AutoSize -Wrap
}

function Show-AllVMInfo {
	#Get-VM | ft VMName, @{e=$_.AutomaticStartAction;l="StartAction"}, @{e=$_.AutomaticStopAction;l="StopAction"}, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
	Get-VM | ft VMName,AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
	# Get-VM | ft VMName, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
	$vhds = Get-VM | select -expandproperty HardDrives
	$vhds | ft VMName, DiskNumber, Path -AutoSize -Wrap
	$vhds | where  DiskNumber -eq $null | get-vhd | ft VhdFormat, VhdType, FileSize, Size, MinimumSize, Attached, Path -AutoSize -Wrap
}

Function Show-ReachableADservers { param ([switch]$Clipboard)
	$svrs = Get-ADComputer -Filter {OperatingSystem -Like "*Windows Server*"} -Property * | sort LastLogonDate | select name, operatingsystem, operatingsystemversion, lastlogondate, pingable, ipaddress, enabled, Deleted, Description
	$svrs = $svrs | sort name
	write-Host "`nComputers Counted: " $svrs.count
	foreach ($svr in $svrs) {$l=Test-NetConnection -ComputerName $svr.name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue; $svr|add-member -MemberType NoteProperty -Name Pingable -Value $l.pingsucceeded -Force; $svr|add-member -MemberType NoteProperty -Name IPAddress -Value ($l.RemoteAddress.IPAddressToString) -Force; $svr.name + "`t" + $svr.pingable + "`t" + $svr.IPAddress}
	$svrs | select name, operatingsystem, operatingsystemversion, lastlogondate, pingable, ipaddress, Description | ft -AutoSize
	$r=($svrs | where Pingable -eq $true).count
	$u=$svrs.count - $r
	Write-Host "Servers Reachable: " $r
	Write-Host "Servers Offline  : " $u
	Write-Host
	if($Clipboard) {$svrs | ConvertTo-Csv -NoTypeInformation | clip}
}

function Show-ReachableADComputers { param ([switch]$Clipboard)
	$comps = Get-ADComputer -Filter {OperatingSystem -NotLike "*Windows Server*"} -Property * | sort LastLogonDate | select name, operatingsystem, operatingsystemversion, lastlogondate, pingable, ipaddress, enabled, Deleted, Description
	$comps = $comps | sort name
	write-Host "`nComputers Counted: " $comps.count
	"Computer`tPingable`tIPAddress"
	foreach ($comp in $comps) {$l=Test-NetConnection -ComputerName $comp.name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue; $comp|add-member -MemberType NoteProperty -Name Pingable -Value $l.pingsucceeded -Force; $comp|add-member -MemberType NoteProperty -Name IPAddress -Value ($l.RemoteAddress.IPAddressToString) -Force; $comp.name + "`t" + $comp.pingable + "`t" + $comp.IPAddress}
	$comps | select name, operatingsystem, operatingsystemversion, lastlogondate, pingable, ipaddress, Description | ft -AutoSize
	$r=($comps | where Pingable -eq $true).count
	$u=$comps.count - $r
	Write-Host "Computers Reachable: " $r
	Write-Host "Computers Offline  : " $u
	Write-Host
	if($Clipboard) {$comps | ConvertTo-Csv -NoTypeInformation | clip}

}

Function Show-ADServers { param ([switch]$Clipboard)
	$comps = Get-ADComputer -Filter {OperatingSystem -Like "*Windows Server*"} -Property * | sort LastLogonDate | select name, operatingsystem,operatingsystemversion, lastlogondate, enabled, Deleted, Description
	write-Host "`nComputers Counted: " $comps.count
	$comps = $comps | sort Name
	#$comps | ft
	return $comps
	if($Clipboard) {$comps | ConvertTo-Csv -NoTypeInformation | clip}
}

Function Show-ADComputers { param ([switch]$Clipboard)
	$comps = Get-ADComputer -Filter {OperatingSystem -NotLike "*Windows Server*"} -Property * | sort LastLogonDate | select Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled, Deleted, Description #, OperatingSystemServicePack
	write-Host "`nComputers Counted: " $comps.count
	$comps = $comps | sort Name
	#$comps | ft
	return $comps
	if($Clipboard) {$comps | ConvertTo-Csv -NoTypeInformation | clip}
}

Function Show-ADComputersAll { param ([switch]$Clipboard)
	$comps = Get-ADComputer -Filter * -Property * | sort LastLogonDate | select Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled, Deleted, Description #, OperatingSystemServicePack
	write-Host "`nComputers Counted: " $comps.count
	$comps = $comps | sort Name
	#$comps | ft
	return $comps
	if($Clipboard) {$comps | ConvertTo-Csv -NoTypeInformation | clip}
}

Function Show-OperatingSystemSpread { param ([switch]$Clipboard)
	$comps = Get-ADComputer -Filter {OperatingSystem -NotLike "*Windows Server*"} -Property * | sort LastLogonDate | select name, operatingsystem, operatingsystemversion, lastlogondate, Description, enabled, Deleted
	$comps | where Enabled -eq $true | group operatingsystem -NoElement | ft Name, Count -AutoSize
	$summ = $comps | where Enabled -eq $true | group operatingsystem -NoElement | select name, count
	$comps2=$summ
	$comps = Get-ADComputer -Filter {OperatingSystem -Like "*Windows Server*"} -Property * | sort LastLogonDate | select name, operatingsystem,operatingsystemversion, lastlogondate, Description, enabled, Deleted
	$comps | where Enabled -eq $true | group operatingsystem -NoElement | ft Name, Count -AutoSize
	$summ = $comps | where Enabled -eq $true | group operatingsystem -NoElement | select name, count
	$comps2=$comps2+"`n"+$summ
	if($Clipboard) {$comps2 | ConvertTo-Csv -NoTypeInformation | clip}
}

Function Show-NetworkComputerSummary {
	#Consider showing offline vs online
	Show-ReachableADservers
	Show-ReachableADComputers
	Show-OperatingSystemSpread
}

FUNCTION Show-Disks() {
	$hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
	$bustype=$hdtype
	$MediaTypeArr=@('Unspecified',"x","x",'HDD','SSD','SCM')

	write-output " "
	#Clear-Host
	Hostname 
    Get-WmiObject win32_logicaldisk | where DriveType -eq 3 | format-table FileSystem, Caption,  DriveType, Size, FreeSpace, @{L='Percent Free';E={($_.FreeSpace / ($_.Size+1)*100)}}, Name, MediaType,  VolumeSerialNumber -autosize # math=free space
   	$drv=Get-WmiObject win32_logicaldisk | select FileSystem, Caption,  DriveType, FreeSpace, Name, MediaType, Size, VolumeSerialNumber | where DriveType -eq 3 
	$drv | ft -autosize
    foreach ($d in $drv) {
        write-output ('Filesystem: {0}  Drive: {1}  Size: {2:N0} MB  Free: {3:N0} MB Percent Free: {4}% Drive: {5} Media:{6} ' -f $d.FileSystem, $d.caption, [math]::truncate($d.Size / 1048576), [math]::truncate($d.FreeSpace / 1048576),  [math]::truncate($d.FreeSpace / ($d.Size+1)*100), $hdtype[$d.DriveType], $MediaTypeArr[$d.mediatype])
		write-output ('Type: {0} {1} Media {2} {3} ' -f $hdtype[$d.MediaType], $d.mediatype, $MediaTypeArr[$d.drivetype], $d.drivetype)
        }
	Get-WmiObject  win32_pnpentity -Filter "(PNPDeviceid like '%DISK%') AND NOT (PNPDeviceid LIKE '%SNAPSHOT%')" | select caption, pnpdeviceid
	write-output " "
	$hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
	$bustype=$hdtype
    $a=Get-WmiObject -Namespace root\microsoft\windows\storage -Class MSFT_Disk | select Model,BusType
    foreach ($b in $a) {$b | Add-Member -MemberType NoteProperty -Name BusInt -Value $hdtype[$b.bustype]}
    $a | Format-List Model, BusInt

}

function Show-DriveSummary { param ([switch]$List, [switch]$Table, [switch]$Physical, [switch]$Summary)
	hostname
	if (!($list -or $Table -or $Physical)) {$Table = $true}
    $MediaTypeArr=@('Unspecified',"x","x",'HDD','SSD','SCM')
    $hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID-*','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')

    $d= Get-PhysicalDisk | Sort-Object DeviceID 
    if($list) {$d | Format-List FriendlyName, Manufacturer, Model, Size, BusType, MediaType, HealthStatus, DeviceId, EnclosureNumber, SlotNumber, OperationalDetails, PhysicalLocation}
    if($table) {$d | Format-Table FriendlyName, Manufacturer, Model, Size, BusType, MediaType, HealthStatus, DeviceId }

    $MediaRes=Get-WmiObject -Class MSFT_PhysicalDisk -Namespace root\Microsoft\Windows\Storage  
    foreach ($l in $mediares) {Add-Member -InputObject $l -MemberType NoteProperty -Name Media -Value $MediaTypeArr[$l.mediatype]
        $t=Get-WmiObject -Namespace root\microsoft\windows\storage -Class MSFT_Disk | where model -EQ $l.FriendlyName
        Add-Member -InputObject $l -MemberType NoteProperty -Name BusInt -Value $hdtype[$l.BusType]
    }
    $d=$MediaRes | Select FriendlyName, Model, MediaType, Media, BusType, BusInt 
    if($list) {$d | Format-List } # FriendlyName, Manufacturer, Model, Size, BusType, MediaType, HealthStatus, DeviceId, EnclosureNumber, SlotNumber, OperationalDetails, PhysicalLocation
    if($table) {$d | Format-Table } # FriendlyName, Manufacturer, Model, Size, BusType, MediaType, HealthStatus, DeviceId, EnclosureNumber, SlotNumber, OperationalDetails, PhysicalLocation
	if ($Physical) {$d | Format-List FriendlyName, Model, Media, BusInt}

# Show Drive Size, DriveType/mediatype as int
   	$drv=Get-WmiObject win32_logicaldisk | select FileSystem, Caption,  DriveType, FreeSpace, Name, MediaType, Size, VolumeSerialNumber | where DriveType -eq 3 
	foreach ($d in $drv) { Add-Member -InputObject $d -MemberType NoteProperty -Name Used -Value ($d.Size - $d.FreeSpace)}
	if($list) {$drv | Format-List }
	if($table) {$drv | Format-Table }

# show Drive Size ## Need Modification to comply with TABLE or LIST specified
    foreach ($d in $drv) {
        write-output ("Filesystem: {0}  Drive: {1} `t Size: {2:N0} MB `t Free: {3:N0} MB `t Used: {4:N0} MB `t Percent Free: {5}% " -f $d.FileSystem, $d.caption, [math]::truncate($d.Size / 1048576), [math]::truncate($d.FreeSpace / 1048576), [math]::truncate(($d.size-$d.freespace)/1048576),  [math]::truncate($d.FreeSpace / ($d.Size+1)*100))
        }
	if($Summary) {
		$sum = Measure-Object $d.Size -Sum
		write-host "Total Size: " $sum
		write-host "Total Free: " -NoNewLine
		Measure-Object $d.FreeSpace -Sum
	}
}

function Show-DiskPartitions {
	Get-WmiObject Win32_DiskDrive | ForEach-Object {
	$disk = $_
	$partitions = "ASSOCIATORS OF " +
					"{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
					"WHERE AssocClass = Win32_DiskDriveToDiskPartition"
	Get-WmiObject -Query $partitions | ForEach-Object {
		$partition = $_
		$drives = "ASSOCIATORS OF " +
				"{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
				"WHERE AssocClass = Win32_LogicalDiskToPartition"
		Get-WmiObject -Query $drives | ForEach-Object {
			New-Object -Type PSCustomObject -Property @{
				Disk        = $disk.DeviceID
				DiskSize    = $disk.Size
				DiskModel   = $disk.Model
				Partition   = $partition.Name
				RawSize     = $partition.Size
				DriveLetter = $_.DeviceID
				VolumeName  = $_.VolumeName
				Size        = $_.Size
				FreeSpace   = $_.FreeSpace
				}
			}
		}
	}
}

Function Show-DriveList { # TODO: Explain DriveType, MediaType
	$hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
	$bustype=$hdtype
	$MediaTypeArr=@('Unspecified',"x","x",'HDD','SSD','SCM')
	Get-WmiObject  -Class Win32_LogicalDisk -errorvariable MyErr -erroraction Stop | ft DeviceID, Caption, Description, DriveType, FileSystem, MediaType, Name, ProviderName
	gwmi win32_pnpentity | where pnpclass -eq "CDROM" | select caption, name, present, status, statusinfo | ft
}

function Show-AvailableCustomfunctions {
	write-output " "
	Get-Item -Path function:\  | findstr "Show- Dell- Pax8-" | Sort.exe # Name# Format-Table CommandType, Name |
	write-output " "
}

Function Show-ShareInfo { param ([switch]$ShowSize, [switch]$OnlyFolders, [switch]$OnlyPrinters, [switch]$IndividualSize, [switch]$Quiet, [switch]$Listing, [switch]$Table, [switch]$CSV, [switch]$AdminShares)
	if($Quiet) {$ErrAct = "SilentlyContinue"} else {$ErrAct = $ErrorActionPreference}
	if($AdminShares) {
		$Shares = Get-SmbShare | where name -like "*$" | sort ShareType, Path 
	} else {
		$Shares = Get-SmbShare | where name -notlike "*$" | sort ShareType, Path #| ft Name, Path, ShareType
	}
	$Shares | Group-Object -NoElement -Property ShareType | Format-Table -AutoSize Name, Count
	if ($OnlyFolders) {$Shares = $Shares | WHERE ShareType -eq "FileSystemDirectory"}
	if ($OnlyPrinters) {$Shares = $Shares | WHERE ShareType -eq "PrintQueue"}
	if($ShowSize) { 
		$f = $Shares | where ShareType -eq "FileSystemDirectory"
		$t = 0
		$f | Format-Table -AutoSize name, path
		foreach ($l in $f) {
			$t=Show-FolderSize $l.Path -Quiet $Quiet -Table $Table
			$t # comes as string from function | Format-Table -AutoSize
		}
	}
	if($IndividualSize) {
		$f = $Shares | where ShareType -eq "FileSystemDirectory"
		$t = 0
		$f | Format-Table -AutoSize name, path
		foreach($l in $f) {
			$t=Show-FolderSize $l.Path  -Quiet $Quiet -Table $Table
			$t # comes as string from function | Format-Table -AutoSize
		}
	}
	if($Listing) {$Shares | ft ShareType, Name, Path}
	if($CSV) {$Shares | select ShareType, Name, Path | ConvertTo-Csv -NoTypeInformation}
}

Function Show-FolderSize { param ([string[]]$fPath, [switch]$Table, [switch]$Quiet, [switch]$CSV, [switch]$PassThru)
	if($fPath.Length -eq 0) {$fPath = ".\*.*"}
	$sz = Get-ChildItem $fPath -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum #| ft Property, Count, @{e={"{0:N0}" -f $_.sum};l="Sum"}
	$sz | Add-Member -MemberType NoteProperty -Name FolderPath -Value $fPath
	$sz | Add-Member -MemberType NoteProperty -Name SizeGB -Value ($sz.sum / 1GB)
	#}
	if(!($Quiet)) {
		if($table) {
			$sz | Format-Table FolderPath, @{e={"{0:N0}" -f $_.sum};l="Size"}, Count, SizeGB 
		} elseif($CSV) {
			$sz | select FolderPath, @{e={"{0:N0}" -f $_.sum};l="Size"}, Count, SizeGB | ConvertTo-Csv -NoTypeInformation
		} else {
			$sz | Format-List FolderPath, @{e={"{0:N0}" -f $_.sum};l="Size"}, Count, SizeGB 
		}
	}
	return $sz
}

Function Show-BackupInstalled {
	$List = @()
	foreach ($UKey in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*')
	{foreach ($Product in (Get-ItemProperty $UKey -ErrorAction SilentlyContinue)){if($Product.DisplayName -and $Product.SystemComponent -ne 1){$List += $Product}}}
	$a=$list.GetLowerBound(0)
	$b=$list.GetUpperBound(0)
	$Apps =  $list | ft displayname, DisplayVersion | findstr "Backup Replibit ShadowProtect"
	#if($null -eq $apps.count) {Write-Host "`nNo backups detected.`n"} else {
		write-Host "`n ";$Apps; write-Host "`n"
		#}
}

Function Show-SQLServers {
	"Searching..."
	$SQLSrv = [System.Data.Sql.SqlDataSourceEnumerator]::Instance.GetDataSources()
	if($null -eq $SQLSrv) {
		"No SQL Servers discovered."
	} else {
		$SQLSrv	| Format-Table ServerName, Version, InstanceName, IsClustered
	}
}

function Show-ComputerInfoSummary {
  $t=get-computerinfo
  $t | Add-Member -MemberType NoteProperty -Name CsProcessorCount -Value ($t.CsProcessors).count
  $t | Add-Member -MemberType NoteProperty -Name ProcessorName -Value $t.CsProcessors[0].Name
  $t | format-list WindowsInstallationType, WindowsProductName, WindowsVersion, OSDisplayVersion, BiosFirmwareType, BiosManufacturer, BiosSeralNumber, CsCaption, CsDNSHostName, CsDomain, CsDomainRole, CsHypervisorPresent, CsManufacturer, CsModel, CsProcessorName, CsProcessorCount,  CsPartOfDomain, CsPauseAfterReset, CsPCSystemTypeEx, CsTotalPhysicalMemory, CsPhyicallyInstalledMemory, CsUserName, OsName, OsVersion, OsUptime, OsBuildType, OsTotalVisibleMemorySize, OsInstallDate, OsMaxNumberOfProcesses, OsPortableOperatingSystem, OsServerLevel, LogonServer
  "Product Suites:"
  $t.OsProductSuites
  " "
}

Function Show-ComputerPurpose {
	$Product = (Get-wmiobject -Class Win32_OperatingSystem)
	$productType = $Product.ProductType;
	$compName = $env:COMPUTERNAME; 
	switch ($productType)
	{
		1 {"`n$compName is a workstation."; break}
		2 {"`n$compName is a domain controller."; break}
		3 {"`n$compName is a server."; break}
	}
	$Product | fl Status, Caption, Version, Description, InstallDate, CSName, OSArchitecture, OSType
}

Function Show-InstalledWindowsFeatures { Param([switch]$Clipboard, [switch]$CSV, [switch]$Table)
#  Show-InstalledPrograms | select DisplayName, DisplayVersion, Version, Publisher | ConvertTo-Csv
	if($PSVersionTable["psversion"].major -eq 2) {
		$feat = Get-WindowsFeature | Where-Object {$_.Installed} | select Name, DisplayName, Installed, InstallState
	} else {
		$feat = Get-WindowsFeature | Where-Object InstallState -eq "Installed" | select Name, DisplayName, Installed, InstallState
	}
	if($Table) {
		$feat
	} else {
	if($Clipboard) {
			if($CSV) {
				$feat | ConvertTo-Csv -NoTypeInformation | clip
			} else {
				$feat | ft -AutoSize | clip
			}
		} else {
			if($CSV) {
				$feat | ConvertTo-Csv -NoTypeInformation 
			} else {
				$feat | ft DisplayName, Name, Installed -AutoSize
			}
		}
	}
}

function Find-Files { param([parameter(Mandatory=$true)][string]$FileSpec)
	$Drives = (Get-Volume | where drivetype -eq "Fixed").DriveLetter
	$Drives = (Get-Volume | where drivetype -eq "Fixed").DriveLetter 
	$Drives = $Drives -join(":\,") -split(",")
	$Drives = $drives[0..($drives.count - 2)]
	Write-Host "Drives: "$Drives
	Get-ChildItem -Include $FileSpec -Path $Drives -Recurse -ErrorAction SilentlyContinue | select Length, FullName, CreationTime, LastAccessTime, LastWriteTime
	
}

#Get-SmbShare | where name -NotLike "*$" | % {Show-FolderSize $_.Path}

#################################
# STOP COPY/PASTE FOR FUNCTIONS #
#       EA   Continue           #
#################################

if (!$global:NoGlobalClear) {Clear-Host 
$PSVersionTable.PSVersion
if($PSVersionTable.PSVersion.Major -lt 3.0) {Write-Host " PS Version too low " -ForegroundColor White -BackgroundColor Red}
Show-AvailableCustomfunctions | ft
}

# Get-ADUser -Filter 'enabled -eq "true"' -Property * | select DisplayName, SamAccountName, Enabled, EmailAddress, LockedOut | ft -AutoSize

#$fpath | % {Show-FolderSize $_ -Quiet| select folderpath, sizegb, sum} | ft -AutoSize
#(Get-SmbShare | where {($_.path -ne "") -and ($_.name -NotLike "*$")}).path | % {Show-FolderSize $_ -Quiet| select folderpath, sizegb, sum} | ft FolderPath, @{e={"{0:N0}" -f $_.sum};l="Size"}, @{e={"{0:N3}" -f $_.SizeGB};l="GB"} -AutoSize
#(Get-SmbShare | where {($_.path -ne "") -and ($_.name -Like "*$")}).path | % {Show-FolderSize $_ -Quiet| select folderpath, sizegb, sum} | ft FolderPath, @{e={"{0:N0}" -f $_.sum};l="Size"}, @{e={"{0:N3}" -f $_.SizeGB};l="GB"} -AutoSize
# 
$fpath = (Get-SmbShare | where {($_.path -ne "") -and ($_.name -NotLike "*$")}).path
$fpath | % {
	$sz = Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
	$sz | Add-Member -MemberType NoteProperty -Name FolderPath -Value $_
	$sz | Add-Member -MemberType NoteProperty -Name SizeGB -Value ($sz.sum / 1GB)
	$sz
}  | ft @{e={"{0:N0}" -f $_.sum};l="Size";a="R"}, @{e={"{0:N3}" -f $_.SizeGB};l="GB";a="Right"}, FolderPath -AutoSize

{
    "ReturnCode":  0,
    "ReturnReason":  "",
    "Logging":  {
                    "SecureBoot":  "",
                    "Stprage":  "",
                    "Memory":  0,
                    "Processor":  {
                                      "AddressWidth":  0,
                                      "Manufacturer":  "",
                                      "MaxClockSpeed":  0,
                                      "LogicalCores":  0
                                  },
                    "TPM":  0
                },
    "ReturnResult":  ""
}