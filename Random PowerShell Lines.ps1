Functions after loading functions
Show-DiskPartitions | sort driveletter | select driveletter, volumename, size, partition

cls;Get-NetIPAddress  | sort InterfaceIndex | where PrefixOrigin -ne 'WellKnown' | ft IPAddress, PrefixLength, PrefixOrigin, InterfaceAlias, AddressState, AddressOrigin -AutoSize

#get-vm-hdd
Get-VM | select -ExpandProperty HardDrives | % {
	$_.VMName
	get-vhd $_.path | ft VhdFormat, VhdType, @{L="Size (GB)";E={$_.Size/1GB};f="F3"},@{L="FileSize (GB)";E={$_.FileSize/1GB};f="F3"}, Path  -AutoSize -Wrap
	}

(Get-Volume | where drivetype -eq "Fixed" | where filesystemlabel -notlike "RECOVERY" | sort driveletter).driveletter

get-childitem -Path C:\, D:\, F:\ -Recurse -Include *.vhd? | select lastwritetime, length, fullname

#Check Office License & Locate OSPP
cscript ((Get-ChildItem -Path 'C:\Program Files\', 'C:\Program Files (x86)\' -include "ospp.vbs" -Recurse -ErrorAction SilentlyContinue | select fullname).fullname) /dstatus

Manipulate into XML

Get-WmiObject Win32_LogicalDisk | sort DeviceID | ft -AutoSize DriveType,
 DeviceID,
 @{n="Size(GB)";e={$_.Size/1GB};f="F3"},
 @{n="Free Space(GB)";e={$_.FreeSpace/1GB};f="F3"},
 @{n="Free%";e={([int]($_.FreeSpace/$_.Size*1000))/10};f="F1"}
 
#Get Folder size in table from shared non-drive admin shares
(Get-SmbShare | where {($_.path -ne "") -and ($_.name -NotLike "?$")}).path | % {Show-FolderSize $_ -Quiet| select folderpath, sizegb, count, sum} | ft -AutoSize Count, @{e={"{0:N0}" -f $_.sum};l="Size";align="right"}, @{e={"{0:N3}" -f $_.SizeGB};l="GB";align="right"}, FolderPath 
(Get-SmbShare | where {($_.path -ne "") -and ($_.name -NotLike "?$")}).path | 
% {Show-FolderSize $_ -Quiet | 
select folderpath, sizegb, count, @{e={"{0:N0}" -f $_.sum};l="Size"}, @{e={"{0:N3}" -f $_.SizeGB};l="GB"}} | 
convertto-csv -NoTypeInformation FolderPath, Count, Size, GB

@Linux WHICH CMD WHERE:
Get-ChildItem -LiteralPath (($env:Path).split(";").replace("`n","")| where {$_.length -ne 0}) -Include *.cpl -ErrorAction SilentlyContinue | where Extension -eq ".cpl" |  select name, FullName
Get-ChildItem -LiteralPath (($env:Path).split(";").replace("`n","")| where {$_.length -ne 0}) -ErrorAction SilentlyContinue | where name -like (Read-Host "Pattern") |  select name, FullName

Get-Volume | where {($_.driveletter) -gt "A"} | sort DriveLetter | ft -AutoSize DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, SizeRemaining, Size,  @{l="PercentRemaining";e={[math]::Round( $_.SizeRemaining/$_.Size*100,3)}}
Get-Volume | where {($_.driveletter) -gt "A"} | where DriveType -ne "CD-ROM" | sort DriveLetter | ft -AutoSize  DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, @{l="Size";a="Right";e={$_.Size.tostring("N0")}}, @{l="SizeRemaining";a="Right";e={$_.SizeRemaining.tostring("N0")}}, @{l="PercentRemaining";e={[math]::Round( $_.SizeRemaining/$_.Size*100,3)}}

#ServerList
"730A", "730B", "ARENA", "ARENADB", "DC730A", "DCVC1", "DCVC4", "SHARE", "UNIFI" | % {gwmi win32_share -ComputerName $_ -ErrorAction SilentlyContinue | select PSComputerName, Name, Path, @{l="Type";e={switch ($_.type) { 0 {'FolderShare'}; 1 {'PrnterShare'}}}} } | where name -notlike "*$" | ft -AutoSize
gwmi win32_share | select PSComputerName, Name, Path, @{l="Type";e={switch ($_.type) { 0 {'FolderShare'}; 1 {'PrnterShare'}}}}  | where {$_.name -notlike "*$"} | ft -AutoSize
gwmi win32_share | select PSComputerName, Name, Path, @{l="Type";e={switch ($_.type) { 0 {'FolderShare'}; 1 {'PrnterShare'}}}}  | where {$_.name -like "*$"} | ft -AutoSize


Get-WmiObject -Class "win32_PhysicalMemoryArray"

Get-WmiObject -Class "win32_PhysicalMemoryArray" | select Name, Model, @{l="SystemMaxMemory-GB";e={$_.MaxCapacity/1MB}}, MemoryDevices, MemoryErrorCorrection, Use | ft
Get-WmiObject win32_physicalmemory | select PartNumber, SMBIOSMemoryType, TypeDetail, FormFactor, DeviceLocator, BankLabel, @{l="Capacity-GB";e={$_.Capacity/1GB}} | ft
(Get-WmiObject win32_physicalmemory | Measure-Object -Sum Capacity) | select @{e={$_.Sum/1GB};l="Total System Memory"} | fl

Get-WmiObject Win32_DiskDrive | sort index | ft -AutoSize Index, InterfaceType, @{n="Size(GB)";e={([int]($_.Size/1GB*10)/10)};f="F3"}, Caption, Model, SerialNumber
Get-WmiObject Win32_LogicalDisk | sort DeviceID | ft -AutoSize DriveType, DeviceID, @{n="Size(GB)";e={$_.Size/1GB};f="F3"}, @{n="Free Space(GB)";e={$_.FreeSpace/1GB};f="F3"},@{n="Free%";e={([int]($_.FreeSpace/$_.Size*1000)/10)}}

Get-NetConnectionProfile | ft Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
Enable-PSRemoting -Force -Verbose

Show Installed DotNet Versions
Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse| Get-ItemProperty | select version | where version -ne $null | sort version
Get-WindowsOptionalFeature -FeatureName netfx* -Online | select FeatureName, DisplayName, State
#Get-WindowsOptionalFeature -FeatureName netfx* -Online | select FeatureName, DisplayName, Description, State, RestartRequired | ft
$f = Read-Host 'Outfile';$w=Read-Host 'Weblink';Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $f

\\Tcoccts1\_barcom$\CCH-Axcess\Workstations
& '\\Tcoccts1\_barcom$\CCH-Axcess\Workstations\document.exe'
& '\\Tcoccts1\_barcom$\CCH-Axcess\Workstations\practice.exe'
& '\\Tcoccts1\_barcom$\CCH-Axcess\Workstations\workstream.exe'
& '\\Tcoccts1\_barcom$\CCH-Axcess\Workstations\tax.exe'

https://www.dropbox.com/scl/fi/d3vuydhona20u9togrcex/document.exe?rlkey=qahl1xjgz0xfzwin01k0prt1i&st=4lji4vpx&dl=0 document
https://uc60734daf76f974a835dbcb6268.dl.dropboxusercontent.com/cd/0/get/CXbYByk3ku4n1yS3TdpDgn_qMq9Tw4GGV-lZb5PO-GsG8DeczbGutyy3L5xx0Xjr6T2jel-l6_IhPf8Z4aDoMQ6-4vgVPD_3A9aWTzlHVIXMVQvGdgo7CG3chA1j4uy6XNRtpvyeIugFDCFLbZ3bSTYvey0MR277iHt2S8uMQhYk4w/file#

https://www.dropbox.com/scl/fi/yfmh5xk9te7e2efp0p889/practice.exe?rlkey=hacrac87ofvtjc000u1kwaadt&st=kiy8cqsx&dl=0 practice
https://uc882708e32e2f863f89aaee99ef.dl.dropboxusercontent.com/cd/0/get/CXbpFPjBMd91gOR60UZjECiKPeAm5IgSNuvrtTSNuU6mpYgkHTbshOly1scEvers4Tgt3Zx8gU1VUB5fWUTLvp7oQcVovva9xz1GpnBzdb1EThRy_8uxc42as43GTm7645i_G0JIyoZT0ae5zmiLbTz9R8BXKmiEZ0HrNpedY25gwQ/file#

https://www.dropbox.com/scl/fi/8fccwuemoxsjbgx34x78x/tax.exe?rlkey=2i2zweai54awgbgs2tmiest57&st=z1o2jvi6&dl=0 tax
https://uc958bfe5ccff16a19760faa0705.dl.dropboxusercontent.com/cd/0/get/CXbgXfD7GwOJXpaB2CeLwc1zvJ0bZ8wLl2vGsFhkgcB31dNHWTIeRBlD-15VzTAAPF3EZEL1Dl7owftuycPftKAaoheX5Y-UICTqYYr5T1OZvnKaYbI8pz4OAeGvArqVXQ8KwjVdQvrqSkKgTpec--GJW_EAmkwWAV2A1mIszr_Dmw/file#

https://www.dropbox.com/scl/fi/ip12af1o8rqeihvxju19p/workstream.exe?rlkey=872zxlnxiz7csihn1p4v67run&st=d11h30uk&dl=0 workstream
https://uc0106bc6d4c5833c6519d2921ec.dl.dropboxusercontent.com/cd/0/get/CXbaKY9-W3Wa1kNEJvmujoh82E5VwPnNu5qtx8VO9KU3XrrwHyA6MabNHmVNaqMi5X3osx33s72GXLsrND-8PVopoouTExIrfsv65YOePgRiI2QcjCifkatoJ0Rgl5iyc0Q_YAXV-tVWLjvcZHUBtIQbJpDlt-4o0MTigdI2AHg8tA/file#


Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName NetFx3

$SourceURI = "https://download.microsoft.com/download/B/4/1/B4119C11-0423-477B-80EE-7A474314B347/NDP452-KB2901954-Web.exe"
$BinPath = "C:\_BARCOM\NDP452-KB2901954-Web.exe"
Invoke-Webrequest -Uri $SourceURI -OutFile $BinPath -UseBasicParsing
Start-Process -FilePath $BinPath -ArgumentList "/q /norestart" -Wait -NoNewWindow

powershell -Command "(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe').'(Default)').VersionInfo | Select-Object -ExpandProperty ProductVersion
