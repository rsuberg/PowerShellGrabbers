## Test multiple CPU's on COW-SPILLMAN
##
## Current Function File
##
## Public Read-Only Link:
## https://1drv.ms/u/s!Am794E9nA2EXgqFCbhvS-SOvgaPOoQ?e=085gTx
##
#{
	
function Show-DisplayAdapterInfo {
	$info = Get-CimInstance win32_VideoController | select Caption, Description, Name, Availability, DeviceID, AdapterCompatibility, AdapterDACType, @{l='RAM (MB)';e={$_.AdapterRAM/1MB}}, @{l='Colors (Million)';e={$_.CurrentNumberOfColors/1MB}}, CurrentBitsPerPixel, VideoModeDescription
	$info | Format-Table -AutoSize
	$info | Format-List
}
	
	
$host.PrivateData.ErrorBackgroundColor = 'Red'
$host.PrivateData.ErrorForegroundColor = 'White'
$ErrorActionPreference = 'Continue'
$Global

if($env:OneDriveCommercial -like "*OnlineStorage*") { #Run My Unique Commands
	&$env:OneDriveConsumer\Portable-Progs\Bginfo.exe $env:OneDriveConsumer\Portable-Progs\BGInfo.bgi /timer:2 /nolicprompt
}

Function Show-InstalledPrograms { Param([switch]$AllFields, [switch]$Table, [switch]$Quiet)
	$List = @()
	foreach ($UKey in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*')
	{foreach ($Product in (Get-ItemProperty $UKey -ErrorAction SilentlyContinue)){if($Product.DisplayName -and $Product.SystemComponent -ne 1){$List += $Product}}}
	$List = $List | sort DisplayName, Publisher 
	if(!($Quiet)) {$List}
	if(!($AllFields)) {$list = $List | ft -AutoSize DisplayName, DisplayVersion, Version, Publisher, InstallDate, EstimatedSize}
	if($Table) {$list | ft -AutoSize}
}

function IsAdmin {
	 return ([Security.Principal.WindowsPrincipal]   [Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-WiFi {
	netsh wlan sho int | findstr /R "Name State SSID Band ^$" | findstr /V "BSSID"
}	

function Show-LocalUsers {
	Get-LocalUser | Select-Object Name, Enabled, PrincipalSource, PasswordRequired, UserMayChangePassword, PasswordChangeableDate, PasswordLastSet, LastLogon, PasswordExpires
	if($Error[0].targetobject -eq "Get-LocalUser") {
		 Get-WmiObject win32_useraccount  | ft Name, Disabled, Lockout, PasswordRequired, PasswordExpires, Domain, LocalAccount, SID
	}
}

function Show-WMIUserAccunt {
	Get-WmiObject win32_useraccount  | ft Name, Disabled, Lockout, PasswordRequired, PasswordExpires, Domain, LocalAccount, SID
}

function Stop-Sleep {
	POWERCFG /X monitor-timeout-ac 30
	POWERCFG /X monitor-timeout-dc 10
	POWERCFG /X disk-timeout-ac 60
	POWERCFG /X disk-timeout-dc 15
	POWERCFG /X standby-timeout-ac 0 
	POWERCFG /X standby-timeout-dc 10
	POWERCFG /X hibernate-timeout-ac 0 
	POWERCFG /X hibernate-timeout-dc 120
	POWERCFG /H ON
}

function Show-UserSession {
   $report = @()
        # Parse 'query session' and store in $sessions: 
        $sessions = query session 
            1..($sessions.count -1) | % {
                $temp = "" | Select Computer,SessionName, Username, Id, State, Type, Device
                $temp.Computer = $c
                $temp.SessionName = $sessions[$_].Substring(1,18).Trim()
                $temp.Username = $sessions[$_].Substring(19,20).Trim()
                $temp.Id = $sessions[$_].Substring(39,9).Trim()
                $temp.State = $sessions[$_].Substring(48,8).Trim()
                $temp.Type = $sessions[$_].Substring(56,12).Trim()
                $temp.Device = $sessions[$_].Substring(68).Trim()
                $report += $temp
            } 
$report | ft
}

function Show-IP { param ([switch]$Virtual, [switch]$Physical, [switch]$Up, [switch]$Down, [switch]$Table, [switch]$List )
	$adps=Get-NetAdapter # | where virtual -EQ $false
	foreach ($adp in $adps) {
		$ips=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adp.ifIndex -ErrorAction SilentlyContinue
		$adp | Add-Member -name IPAddress -value $ips.ipaddress -MemberType NoteProperty -Force
		$adp | Add-Member -name PrefixOrigin -value $ips.prefixorigin -MemberType NoteProperty -Force
		$adp | Add-Member -name PrefixLength -value $ips.prefixlength -MemberType NoteProperty -Force
	#   $adp
	}
	if(($Virtual) -and (!$Physical)) {
		$adps=$adps | where virtual -eq $true
	}
	if((!$Virtual) -and ($Physical)) {
		$adps=$adps | where virtual -eq $false
	}
	if((!$Up) -and ($Down)) {
		$adps=$adps | where status -eq "Disconnected"
	}
	if(($Up) -and (!$Down)) {
		$adps=$adps | where status -eq "Up"
	}
	$adps = $adps | sort virtual, ifindex | select IPAddress, Status, virtual, Name, InterfaceDescription, ifIndex, prefixlength, prefixorigin, linkspeed, MediaType, MacAddress, AdminStatus 
	if($Table) {$adps | Format-Table -AutoSize}
	if($List) {$adps | Format-List}
	if(!(($Table) -or ($List))) {return $adps}
	# $adps
}

function Show-Info() {
	$memtot=0
	#Get-ComputerInfo | select WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer, OsArchitecture | FL
	gwmi Win32_OperatingSystem | select PSComputerName, Caption, OSArchitecture, TotalVirtualMemorySize, TotalVisibleMemorySize, Version, InstallDate, NumberOfLicensedUsers | FL
if($PSVersionTable.psversion.ToString() -gt 2.5) {
		Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Caption, LastBootupTime, OSArchitecture, TotalVirtualMemorySize, TotalVisibleMemorySize, Version, InstallDate, NumberOfLicensedUsers | FL
	}

	gwmi win32_processor | fl Manufacturer, Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, LoadPercentage
	gwmi win32_bios | fl
	gwmi win32_computersystem | select bootupstate, AutomaticResetBootOption, ChassisSKUNumber, Manufacturer, Model, SystemFamily, SystemSKUNumber | FL
	gwmi win32_diskdrive | select interfacetype,mediatype,size,status,statusinfo,model,name |sort-object name | ft
	$a=gwmi win32_diskdrive ; $c=$a | sort-object name 
	foreach ($b in $c) {
		write-output ("Model : " + $b.model)
		write-output ("Status: " + $b.status)
		write-output ("Type  : " + $b.mediatype)
		Write-Output ("Bus   : " + $b.interfacetype)
		write-output ("Size  : {0:0} GB" -f [math]::round($b.size / 1073741824))
		write-output " "
		} 
	$memtot=0
	$a=gwmi win32_physicalmemory ;foreach ($b in $a) {
		write-output ('{0} - {1:0} MB, FormFactor - {2}, Banklabel ~{3} * {4}~ PN={5} SMBIOS-Memorytype <6>' -f $b.tag, [math]::truncate($b.capacity / 1048576),$b.FormFactor,$b.BankLabel,$b.DeviceLocator,$b.PartNumber, $b.MemoryType)
		$memtot=$memtot+($b.capacity/1048576)
		}
    write-output " "
	write-output ('Total memory: {0:0}  MB   {1:0} GB ' -f $memtot, [math]::Truncate($memtot/1024 ) )
    write-output " "
	get-tpm | ft TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManufacturerVersionFull20 -AutoSize
	}

function Show-MemoryDetail {
# Based on System Management BIOS (SMBIOS) Reference Specification 3.4.0a
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0a.pdf
"=======================**"	
$SlotNo = 0
# 7.18.1. Form factor @offset 0x0E
[string[]]$FORM_FACTORS = @(
'Invalid', 'Other', 'Unknown', 'SIMM', # 00-03h
'SIP', 'Chip', 'DIP', 'ZIP', # 04-07h
'Proprietary Card', 'DIMM', 'TSOP', 'Row of chips', # 08-0Bh
'RIMM', 'SODIMM', 'SRIMM', 'FB-DIMM', # 0C-0Fh
'Die' # 10h
)
# 7.18.2. Memory type @offset 0x12
[string[]]$MEMORY_TYPES = @(
'Invalid', 'Other', 'Unknown', 'DRAM', # 00-03h
'EDRAM', 'VRAM', 'SRAM', 'RAM', # 04-07h
'ROM', 'FLASH', 'EEPROM', 'FEPROM', # 08-0Bh
'EPROM', 'CDRAM', '3DRAM', 'SDRAM', # 0C-0Fh
'SGRAM', 'RDRAM', 'DDR', 'DDR2', # 10-13h
'DDR2 FB-DIMM', 'Reserved', 'Reserved', 'Reserved', # 14-17h
'DDR3', 'FBD2', 'DDR4', 'LPDDR', # 18-1Bh
'LPDDR2', 'LPDDR3', 'LPDDR4', 'Logical non-volatile device' # 1C-1Fh
'HBM (High Bandwidth Memory)', 'HBM2 (High Bandwidth Memory Generation 2)',
'DDR5', 'LPDDR5' # 20-23h
)
# 7.18.3. Type detail @offset 0x13
[string[]]$TYPE_DETAILS = @(
'Reserved', 'Other', 'Unknown', 'Fast-paged', # bit 0-3
'Static column', 'Pseudo-static', 'RAMBUS', 'Synchronous', # bit 4-7
'CMOS', 'EDO', 'Window DRAM', 'Cache DRAM', # bit 8-11
'Non-volatile', 'Registered (Buffered)',
'Unbuffered (Unregistered)', 'LRDIMM' # 0C-0Fh
)

function lookUp([string[]]$table, [int]$value)
{
 if ($value -ge 0 -and $value -lt $table.Length) {
 $table[$value]
 } else {
 "Unknown value 0x{0:X}" -f $value
 }
}

function parseTable([array]$table, [int]$begin, [int]$end)
{
 [int]$index = $begin
 $size = [BitConverter]::ToUInt16($table, $index + 0x0C)
 if ($size -eq 0xFFFF) {
  "Unknown memory size"
 } elseif ($size -ne 0x7FFF) {
 if (($size -shr 15) -eq 0) { $size *= 1MB } else { $size *= 1KB }
 } else {
 $size = [BitConverter]::ToUInt32($table, $index + 0x1C)
 }
 "Size: {0:N0} bytes ({1} GB)" -f $size, ($size/1GB)

 $formFactor = $table[$index + 0x0E]
 $formFactorStr = $(lookUp $FORM_FACTORS $formFactor)
 "Memory form factor: 0x{0:X2} {1}" -f $formFactor, $formFactorStr

 $type = $table[$index + 0x12]
 "Memory type: 0x{0:X2} ({1})" -f $type, $(lookUp $MEMORY_TYPES $type)

 $typeDetail = [BitConverter]::ToUInt16($table, $index + 0x13)
 $details = 0..15 |% {
 if (((1 -shl $_) -band $typeDetail) -ne 0) { "{0}" -f $TYPE_DETAILS[$_] }
 }
  "Type detail: 0x{0:X2} ({1})" -f $typeDetail, $($details -join ' | ')

  $speed = [BitConverter]::ToUInt16($table, $index + 0x15)
  if ($speed -eq 0) {
  "Unknown speed"
  } elseif ($speed -ne 0xFFFF) {
   "Speed: {0:N0} MT/s" -f $speed
  } else {
   "Speed: {0:N0} MT/s" -f [BitConverter]::ToUInt32($table, $index + 0x54)
  }
  $SlotNo +=
  $SlotNo
 "======================="
 }

 $index = 0

 $END_OF_TABLES = 127
 $MEMORY_DEVICE = 17

 $BiosTables = (Get-WmiObject -ComputerName . -Namespace root\wmi -Query `
 "SELECT SMBiosData FROM MSSmBios_RawSMBiosTables" `
 ).SMBiosData

 do
 {
  $startIndex = $index

  # ========= Parse table header =========
  $tableType = $BiosTables[$index]
  if ($tableType -eq $END_OF_TABLES) { break }

  $tableLength = $BiosTables[$index + 1]
  # $tableHandle = [BitConverter]::ToUInt16($BiosTables, $index + 2)
  $index += $tableLength

  # ========= Parse unformatted part =========
  # Find the '\0\0' structure termination
  while ([BitConverter]::ToUInt16($BiosTables, $index) -ne 0) { $index++ }
  $index += 2

  # adjustment when the table ends with a string
  if ($BiosTables[$index] -eq 0) { $index++ }

  if ($tableType -eq $MEMORY_DEVICE) { parseTable $BiosTables $startIndex $index }
 } until ($tableType -eq $END_OF_TABLES -or $index -ge $BiosTables.length)
}

Function Show-VideoConnections {
	write-output " "
	"=======================**"	
	[string[]]$VidType = @("VGA HD15","SVideo","Composite","Component","DVI","HDMI","LVDS/MIPI/DSI","JPN","SDI","DP-Ext","DP-Embed","SDTV-Dongle","MiraCast","Indirect-Wired")
	"Active Video connections:"
	$v=Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -erroraction silentlycontinue
	foreach ($s in $v) {$VidType[$s.VideoOutputTechnology] }
}

function Show-Monitors {
	#Modified to eliminate some errors on the monitor model detection, possibly when no monitor is active, RDP connected, or laptop closed. 3/6/2023
$Computername = @("localhost")
  	write-output " "
  #List of Manufacture Codes that could be pulled from WMI and their respective full names. Used for translating later down.
  $ManufacturerHash = @{"AAC" =	"AcerView";"ACR" = "Acer";"AOC" = "AOC";"AIC" = "AG Neovo";"APP" = "Apple Computer";"AST" = "ASTResearch";"AUO" = "Asus";"BNQ" = "BenQ";"CMO" = "Acer";"CPL" = "Compal";"CPQ" = "Compaq";"CPT" = "Chunghwa Pciture Tubes, Ltd.";"CTX" = "CTX";"DEC" = "DEC";"DEL" = "Dell";    "DPC" = "Delta";    "DWE" = "Daewoo";"EIZ" = "EIZO";"ELS" = "ELSA";"ENC" = "EIZO";"EPI" = "Envision";"FCM" = "Funai";"FUJ" = "Fujitsu";"FUS" = "Fujitsu-Siemens";"GSM" = "LG Electronics";"GWY" = "Gateway 2000";"HEI" = "Hyundai";"HIT" = "Hyundai";"HSL" = "Hansol";"HTC" = "Hitachi/Nissei";"HWP" = "HP";"IBM" = "IBM";"ICL" = "Fujitsu ICL";"IVM" = "Iiyama";"KDS" = "Korea Data Systems";"LEN" = "Lenovo";"LGD" = "Asus";"LPL" = "Fujitsu";"MAX" = "Belinea";"MEI" = "Panasonic";"MEL" = "Mitsubishi Electronics";"MS_" = "Panasonic";"NAN" = "Nanao";"NEC" = "NEC";"NOK" = "Nokia Data";"NVD" = "Fujitsu";"OPT" = "Optoma";"PHL" = "Philips";"REL" = "Relisys";    "SAN" = "Samsung";"SAM" = "Samsung";"SBI" = "Smarttech";"SGI" = "SGI";"SNY" = "Sony";"SRC" = "Shamrock";"SUN" = "Sun Microsystems";    "SEC" = "Hewlett-Packard";"TAT" = "Tatung";"TOS" = "Toshiba";"TSB" = "Toshiba";"VSC" = "ViewSonic";"ZCM" = "Zenith";"UNK" = "Unknown";"_YV" = "Fujitsu";}
  	[string[]]$VidType = @("VGA HD15","SVideo","Composite","Component","DVI","HDMI","LVDS/MIPI/DSI","JPN","SDI","DP-Ext","DP-Embed","SDTV-Dongle","MiraCast","Indirect-Wired")

  #Takes each computer specified and runs the following code:
    #Creates an empty array to hold the data
    $Monitor_Array = @()

    $Monitors=Get-WmiObject WmiMonitorID -Namespace root\wmi -erroraction silentlycontinue
    #Takes each monitor object found and runs the following code:
    ForEach ($Monitor in $Monitors) {
      
      #Grabs respective data and converts it from ASCII encoding and removes any trailing ASCII null values
      if ($Monitor.UserFriendlyName.length -ne 0) {
		If ($null -ne [System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName))  {
			$Mon_Model = ([System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName)).Replace("$([char]0x0000)","")
		} else {
			$Mon_Model = "---"
		}
	  } else {
		  $Mon_Model = "---"
	  }
      $Mon_Serial_Number = ([System.Text.Encoding]::ASCII.GetString($Monitor.SerialNumberID)).Replace("$([char]0x0000)","")
      $Mon_Attached_Computer = ($Monitor.PSComputerName).Replace("$([char]0x0000)","")
      $Mon_Manufacturer = ([System.Text.Encoding]::ASCII.GetString($Monitor.ManufacturerName)).Replace("$([char]0x0000)","")
      
            #Filters out "non monitors". Place any of your own filters here. These two are all-in-one computers with built in displays. I don't need the info from these.
      If ($Mon_Model -like "*800 AIO*" -or $Mon_Model -like "*8300 AiO*") {Break}
      
      $VidCon=$VidType[(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams | Where-Object InstanceName -Like $Monitor.InstanceName).VideoOutputTechnology]
      #Sets a friendly name based on the hash table above. If no entry found sets it to the original 3 character code
      $Mon_Manufacturer_Friendly = $ManufacturerHash.$Mon_Manufacturer
      If ($null -eq $Mon_Manufacturer_Friendly) {
        $Mon_Manufacturer_Friendly = $Mon_Manufacturer
      }
      
      #Creates a custom monitor object and fills it with 4 NoteProperty members and the respective data
      $Monitor_Obj = [PSCustomObject]@{
        MonitorManufacturer     = $Mon_Manufacturer_Friendly
        MonitorModel            = $Mon_Model
        MonitorSerialNumber     = $Mon_Serial_Number
        MonitorAttachedComputer = $Mon_Attached_Computer
		MonitorConnection       = $VidCon
      }
      
      #Appends the object to the array
      $Monitor_Array += $Monitor_Obj
    } #End ForEach Monitor
	write-output "Monitors:" $Monitor_Array.count
 
    #Outputs the Array
    $Monitor_Array | format-table
    $Monitor_Array | Format-List MonitorManufacturer, MonitorModel, MonitorConnection, MonitorSerialNumber
	
 } #End ForEach Computer

Function Show-PCSummary {
$a=	gwmi Win32_OperatingSystem | select PSComputerName, Caption, OSArchitecture, TotalVirtualMemorySize, TotalVisibleMemorySize, Version 
$b=$a | ConvertTo-Json -Depth 1
$b = $b.Replace("Caption","OSName")
$c = $b.Replace("}",",")
$a =gwmi win32_processor | select Caption, DeviceID, Manufacturer, MaxClockSpeed, Name, SocketDesignation
$b=$a | ConvertTo-Json -Depth 1
$b = $b.Replace("Caption","CPU Family")
$b = $b.Replace("Name","CPU Name")
$b=$b.Replace("{","")
$c = $c + $b.Replace("}",",")
$a=gwmi win32_computersystem | select BootupState, AutomaticResetBootOption, ChassisSKUNumber, Manufacturer, Model, SystemFamily, SystemSKUNumber
$b=$a | ConvertTo-Json -Depth 1
$b=$b.replace("Manufacturer","Case Manufacturer")
$b=$b.Replace("{","")
$c = $c + $b.Replace("}",",")
$a=	gwmi win32_bios | select SerialNumber
$b=$a | ConvertTo-Json -Depth 1
$c = $c + $b.Replace("{","")
$a = $c | ConvertFrom-Json
$a

	$ze=gwmi win32_diskdrive | select interfacetype,mediatype,size,status,statusinfo,model,name |sort-object name | ft
	$a=gwmi win32_diskdrive ; $c=$a | sort-object name 
	foreach ($b in $c) {write-output "Model: " $b.model; write-output "Status: " $b.status;write-output "Type: " $b.mediatype,$b.interfacetype;write-output ("Size: {0:0} GB" -f [math]::round($b.size / 1073741824));write-output " "} 
	$memtot=0
	$a=gwmi win32_physicalmemory ;foreach ($b in $a) {
		write-output ('{0} - {1:0} MB, FormFactor - {2}, Banklabel ~{3} * {4}~ PN={5} SMBIOS-Memorytype <6>' -f $b.tag, [math]::truncate($b.capacity / 1048576),$b.FormFactor,$b.BankLabel,$b.DeviceLocator,$b.PartNumber, $b.MemoryType)
		$memtot=$memtot+($b.capacity/1048576)
		}
    $z=$ze 
	$z | findstr ":"
	write-output ('Total memory: {0:0}  MB   {1:0} GB ' -f $memtot, [math]::Truncate($memtot/1024 ) )
		get-tpm -erroraction silentlycontinue | ft TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManufacturerVersionFull20
    Get-WmiObject win32_logicaldisk | where DriveType -eq 3 | format-table FileSystem, Caption,  DriveType, Size, FreeSpace, @{L='Percent Free';E={($_.FreeSpace / ($_.Size+1)*100)}}, Name, MediaType,  VolumeSerialNumber -autosize # math=free space
	$hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
    $a=Get-WmiObject -Namespace root\microsoft\windows\storage -Class MSFT_Disk | select Model,BusType
    foreach ($b in $a) {$b | Add-Member -MemberType NoteProperty -Name BusInt -Value $hdtype[$b.bustype]}
    $a 
#}

# Based on System Management BIOS (SMBIOS) Reference Specification 3.4.0a
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0a.pdf
"=======================**"	

# 7.18.1. Form factor @offset 0x0E
[string[]]$FORM_FACTORS = @(
'Invalid', 'Other', 'Unknown', 'SIMM', # 00-03h
'SIP', 'Chip', 'DIP', 'ZIP', # 04-07h
'Proprietary Card', 'DIMM', 'TSOP', 'Row of chips', # 08-0Bh
'RIMM', 'SODIMM', 'SRIMM', 'FB-DIMM', # 0C-0Fh
'Die' # 10h
)
# 7.18.2. Memory type @offset 0x12
[string[]]$MEMORY_TYPES = @(
'Invalid', 'Other', 'Unknown', 'DRAM', # 00-03h
'EDRAM', 'VRAM', 'SRAM', 'RAM', # 04-07h
'ROM', 'FLASH', 'EEPROM', 'FEPROM', # 08-0Bh
'EPROM', 'CDRAM', '3DRAM', 'SDRAM', # 0C-0Fh
'SGRAM', 'RDRAM', 'DDR', 'DDR2', # 10-13h
'DDR2 FB-DIMM', 'Reserved', 'Reserved', 'Reserved', # 14-17h
'DDR3', 'FBD2', 'DDR4', 'LPDDR', # 18-1Bh
'LPDDR2', 'LPDDR3', 'LPDDR4', 'Logical non-volatile device' # 1C-1Fh
'HBM (High Bandwidth Memory)', 'HBM2 (High Bandwidth Memory Generation 2)',
'DDR5', 'LPDDR5' # 20-23h
)
# 7.18.3. Type detail @offset 0x13
[string[]]$TYPE_DETAILS = @(
'Reserved', 'Other', 'Unknown', 'Fast-paged', # bit 0-3
'Static column', 'Pseudo-static', 'RAMBUS', 'Synchronous', # bit 4-7
'CMOS', 'EDO', 'Window DRAM', 'Cache DRAM', # bit 8-11
'Non-volatile', 'Registered (Buffered)',
'Unbuffered (Unregistered)', 'LRDIMM' # 0C-0Fh
)

function lookUp([string[]]$table, [int]$value)
{
 if ($value -ge 0 -and $value -lt $table.Length) {
 $table[$value]
 } else {
 "Unknown value 0x{0:X}" -f $value
 }
}

function parseTable([array]$table, [int]$begin, [int]$end)
{
 [int]$index = $begin
 $size = [BitConverter]::ToUInt16($table, $index + 0x0C)
 if ($size -eq 0xFFFF) {
  "Unknown memory size"
 } elseif ($size -ne 0x7FFF) {
 if (($size -shr 15) -eq 0) { $size *= 1MB } else { $size *= 1KB }
 } else {
 $size = [BitConverter]::ToUInt32($table, $index + 0x1C)
 }
 "Size: {0:N0} bytes ({1} GB)" -f $size, ($size/1GB)

 $formFactor = $table[$index + 0x0E]
 $formFactorStr = $(lookUp $FORM_FACTORS $formFactor)
 "Memory form factor: 0x{0:X2} {1}" -f $formFactor, $formFactorStr

 $type = $table[$index + 0x12]
 "Memory type: 0x{0:X2} ({1})" -f $type, $(lookUp $MEMORY_TYPES $type)

 $typeDetail = [BitConverter]::ToUInt16($table, $index + 0x13)
 $details = 0..15 |% {
 if (((1 -shl $_) -band $typeDetail) -ne 0) { "{0}" -f $TYPE_DETAILS[$_] }
 }
  "Type detail: 0x{0:X2} ({1})" -f $typeDetail, $($details -join ' | ')

  $speed = [BitConverter]::ToUInt16($table, $index + 0x15)
  if ($speed -eq 0) {
  "Unknown speed"
  } elseif ($speed -ne 0xFFFF) {
   "Speed: {0:N0} MT/s" -f $speed
  } else {
   "Speed: {0:N0} MT/s" -f [BitConverter]::ToUInt32($table, $index + 0x54)
  }
 "======================="
 }

 $index = 0

 $END_OF_TABLES = 127
 $MEMORY_DEVICE = 17

 $BiosTables = (Get-WmiObject -ComputerName . -Namespace root\wmi -Query `
 "SELECT SMBiosData FROM MSSmBios_RawSMBiosTables" `
 ).SMBiosData

 do
 {
  $startIndex = $index

  # ========= Parse table header =========
  $tableType = $BiosTables[$index]
  if ($tableType -eq $END_OF_TABLES) { break }

  $tableLength = $BiosTables[$index + 1]
  # $tableHandle = [BitConverter]::ToUInt16($BiosTables, $index + 2)
  $index += $tableLength

  # ========= Parse unformatted part =========
  # Find the '\0\0' structure termination
  while ([BitConverter]::ToUInt16($BiosTables, $index) -ne 0) { $index++ }
  $index += 2

  # adjustment when the table ends with a string
  if ($BiosTables[$index] -eq 0) { $index++ }

  if ($tableType -eq $MEMORY_DEVICE) { parseTable $BiosTables $startIndex $index }
 } until ($tableType -eq $END_OF_TABLES -or $index -ge $BiosTables.length)
 $SysSlotUsage_Arr=@("Reserved","Other","Unknown","Available","In Use")
$ss = gwmi Win32_systemslot | select CurrentUsage, Name, Model, SlotDesignation, Status 
foreach ($l in $ss) {$l.CurrentUsage = $SysSlotUsage_Arr[$l.CurrentUsage]}
$ss | ft

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

function Show-DriveSummary { param ([switch]$List, [switch]$Table, [switch]$Physical)
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
	Get-WmiObject  -Class Win32_LogicalDisk -errorvariable MyErr -erroraction Continue | ft DeviceID, Caption, Description, DriveType, FileSystem, MediaType, Name, ProviderName
	gwmi win32_pnpentity | where pnpclass -eq "CDROM" | select caption, name, present, status, statusinfo | ft
}

function Show-SlotUsage {
	$SysSlotUsage_Arr=@("Reserved","Other","Unknown","Available","In Use")
	$ConnType_Arr=@("Unknown","Other",'M','F','Shielded','Unshielded')
	$ss = gwmi Win32_systemslot | select CurrentUsage, Name, Model, SlotDesignation, Status, ConnectorType, ConnectorPinOut 
	foreach ($l in $ss) {
		$l.CurrentUsage = $SysSlotUsage_Arr[$l.CurrentUsage]
		$l | Add-Member -MemberType NoteProperty -Name ConnectorDesc -Value $ConnType_Arr[$l.ConnectorType]
		}
	$ss | ft SlotDesignation, CurrentUsage, Status, Name, Model, ConnectorType, ConnectorDesc, ConnectorPinOut
}

function Show-MemoryDetailTable {
# Based on System Management BIOS (SMBIOS) Reference Specification 3.4.0a
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0a.pdf
#"=======================**"	

#Init Arrays for Table
$MemorySlot= [PSCustomObject]@{
    Slot = 0
    Size     = ''
    FormFactorStr = ''
    Details = ''
    Speed = ''
}
$MemorySlotArr=@{}


# 7.18.1. Form factor @offset 0x0E
[string[]]$FORM_FACTORS = @(
'Invalid', 'Other', 'Unknown', 'SIMM', # 00-03h
'SIP', 'Chip', 'DIP', 'ZIP', # 04-07h
'Proprietary Card', 'DIMM', 'TSOP', 'Row of chips', # 08-0Bh
'RIMM', 'SODIMM', 'SRIMM', 'FB-DIMM', # 0C-0Fh
'Die' # 10h
)
# 7.18.2. Memory type @offset 0x12
[string[]]$MEMORY_TYPES = @(
'Invalid', 'Other', 'Unknown', 'DRAM', # 00-03h
'EDRAM', 'VRAM', 'SRAM', 'RAM', # 04-07h
'ROM', 'FLASH', 'EEPROM', 'FEPROM', # 08-0Bh
'EPROM', 'CDRAM', '3DRAM', 'SDRAM', # 0C-0Fh
'SGRAM', 'RDRAM', 'DDR', 'DDR2', # 10-13h
'DDR2 FB-DIMM', 'Reserved', 'Reserved', 'Reserved', # 14-17h
'DDR3', 'FBD2', 'DDR4', 'LPDDR', # 18-1Bh
'LPDDR2', 'LPDDR3', 'LPDDR4', 'Logical non-volatile device' # 1C-1Fh
'HBM (High Bandwidth Memory)', 'HBM2 (High Bandwidth Memory Generation 2)',
'DDR5', 'LPDDR5' # 20-23h
)
# 7.18.3. Type detail @offset 0x13
[string[]]$TYPE_DETAILS = @(
'Reserved', 'Other', 'Unknown', 'Fast-paged', # bit 0-3
'Static column', 'Pseudo-static', 'RAMBUS', 'Synchronous', # bit 4-7
'CMOS', 'EDO', 'Window DRAM', 'Cache DRAM', # bit 8-11
'Non-volatile', 'Registered (Buffered)',
'Unbuffered (Unregistered)', 'LRDIMM' # 0C-0Fh
)

function lookUp([string[]]$table, [int]$value)
{
 if ($value -ge 0 -and $value -lt $table.Length) {
 $table[$value]
 } else {
 "Unknown value 0x{0:X}" -f $value
 }
}

function parseTable([array]$table, [int]$begin, [int]$end)
{
 [int]$index = $begin
 $size = [BitConverter]::ToUInt16($table, $index + 0x0C)
 if ($size -eq 0xFFFF) {
# ##  "Unknown memory size"
$MemorySlot.Size = "Unknown"
 } elseif ($size -ne 0x7FFF) {
 if (($size -shr 15) -eq 0) { $size *= 1MB } else { $size *= 1KB }
 } else {
 # ##$size = [BitConverter]::ToUInt32($table, $index + 0x1C)
 }
# ## "Size: {0:N0} bytes ({1} GB)" -f $size, ($size/1GB)
 $MemorySlot.size=$size/1GB


 $formFactor = $table[$index + 0x0E]
 $formFactorStr = $(lookUp $FORM_FACTORS $formFactor)
 # ## "Memory form factor: 0x{0:X2} {1}" -f $formFactor, $formFactorStr
 $MemorySlot.FormFactorStr = $formFactorStr

 $type = $table[$index + 0x12]
 # ## "Memory type: 0x{0:X2} ({1})" -f $type, $(lookUp $MEMORY_TYPES $type)

 $typeDetail = [BitConverter]::ToUInt16($table, $index + 0x13)
 $details = 0..15 |% {
 if (((1 -shl $_) -band $typeDetail) -ne 0) { "{0}" -f $TYPE_DETAILS[$_] }
 }
# ##  "Type detail: 0x{0:X2} ({1})" -f $typeDetail, $($details -join ' | ')
  $MemorySlot.Details = $($details -join ' | ')
  $speed = [BitConverter]::ToUInt16($table, $index + 0x15)
  if ($speed -eq 0) {
# ##  "Unknown speed"
  $MemorySlot.Speed="Unknown"
  } elseif ($speed -ne 0xFFFF) {
# ##    "Speed: {0:N0} MT/s" -f $speed
   $MemorySlot.Speed = "{0:N0} MT/s" -f $speed
  } else {
# ##   "Speed: {0:N0} MT/s" -f [BitConverter]::ToUInt32($table, $index + 0x54)
   $MemorySlot.Speed = "{0:N0} MT/s" -f [BitConverter]::ToUInt32($table, $index + 0x54)
  }
# ## End Detect Loop ## #

  $MemorySlot.Slot =$MemorySlotArr.Count+1
 # $MemorySlot.Slot

# ##  $MemorySlot | ft
  $MemorySlotArr[$MemorySlot.Slot]=$MemorySlot
  $MemorySlot = New-Object $MemorySlot
 # $MemorySlotArr =  $MemorySlotArr + $MemorySlot
# ## "======================= " + $MemorySlot.Slot
write-output "." # -NoNewline
 }

 $index = 0

 $END_OF_TABLES = 127
 $MEMORY_DEVICE = 17

 $BiosTables = (Get-WmiObject -ComputerName . -Namespace root\wmi -Query `
 "SELECT SMBiosData FROM MSSmBios_RawSMBiosTables" `
 ).SMBiosData

 do
 {
  $startIndex = $index

  # ========= Parse table header =========
  $tableType = $BiosTables[$index]
  if ($tableType -eq $END_OF_TABLES) { break }

  $tableLength = $BiosTables[$index + 1]
  # $tableHandle = [BitConverter]::ToUInt16($BiosTables, $index + 2)
  $index += $tableLength

  # ========= Parse unformatted part =========
  # Find the '\0\0' structure termination
  while ([BitConverter]::ToUInt16($BiosTables, $index) -ne 0) { $index++ }
  $index += 2

  # adjustment when the table ends with a string
  if ($BiosTables[$index] -eq 0) { $index++ }

  if ($tableType -eq $MEMORY_DEVICE) { parseTable $BiosTables $startIndex $index }
 } until ($tableType -eq $END_OF_TABLES -or $index -ge $BiosTables.length)
 write-output " "
  $MemorySlotArr |  ft

}

function Show-EOLInfo {
#  Param(
#    [Parameter(Mandatory=$false)]
#    [Switch]$Detail
#        ) 
    clear-host
    write-output "Collecting...`r" # -NoNewline
    $Data = New-Object -TypeName PSObject
    $memtot = 0
    $ErrorActionPreference = "Continue"
	$hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
	$bustype=$hdtype
	$MediaTypeArr=@('Unspecified',"Undefined","Undefined",'HDD','SSD','SCM')
	$Arr_ChassisType = @("0-x", "Other", "Unknown", "Desktop", "Low Profile Desktop", "Pizza Box", "Mini Tower", "Tower", "Portable", "Laptop", "Notebook", "Hand Held", "Docking Station", "All in One", "Sub Notebook ", "Space-Saving", "Lunch Box", "Main System Chassis", "Expansion Chassis", "SubChassis", "Bus Expansion Chassis", "Peripheral Chassis", "Storage Chassis", "Rack Mount Chassis", "Sealed-Case PC", "Tablet", "Convertible", "Detachable")
    $a=Get-WmiObject win32_physicalmemory  
    foreach ($b in $a) {
		$memtot=$memtot+($b.capacity/1048576)
		}
    if($Detail) {
	    #write-output ('Total memory: {0:0}  MB   {1:0} GB ' -f $memtot, [math]::Truncate($memtot/1024 ) )
    }
    $Data | Add-Member -MemberType NoteProperty -Name TotalMemory-GB -Value ([math]::Truncate($memtot/1024 ))
	[string[]]$VidType = @("VGA HD15","SVideo","Composite","Component","DVI","HDMI","LVDS/MIPI/DSI","JPN","SDI","DP-Ext","DP-Embed","SDTV-Dongle","MiraCast","Indirect-Wired")
	$v=Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams
	$t=""; $x=""
	foreach ($s in $v) {$x += $VidType[$s.VideoOutputTechnology] ; $x += ", "}
	$x+="*"; $x = $x.replace(", *"," ")
    $Data | Add-Member -MemberType NoteProperty -Name Hostname -Value (Get-WmiObject win32_computersystem ).name
    $Data | Add-Member -MemberType NoteProperty -Name Domain -Value (Get-WmiObject win32_computersystem ).Domain
    $Data | Add-Member -MemberType NoteProperty -Name Username -Value (Get-WmiObject win32_computersystem ).username
    $Data | Add-Member -MemberType NoteProperty -Name VideoConnections -Value $x
    $Data | Add-Member -MemberType NoteProperty -Name CPU -Value (Get-WmiObject win32_processor).name
    $Data | Add-Member -MemberType NoteProperty -Name ChipCount -Value (( Get-WmiObject win32_processor).name).count
    $Data | Add-Member -MemberType NoteProperty  -Name CPUCores -Value (Get-WmiObject Win32_Processor).NumberOfCores
    $data | Add-Member -MemberType NoteProperty -Name Threads -Value (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors 
    $data | Add-Member -MemberType NoteProperty -Name Manufacturer -value (Get-WmiObject win32_computersystem ).manufacturer
    $Data | Add-Member -MemberType NoteProperty -Name Model -Value (Get-WmiObject win32_computersystem).model
    $Data | Add-Member -MemberType NoteProperty -Name SerialNo -Value (Get-WmiObject win32_bios).serialnumber
    $Data | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value (gwmi win32_operatingsystem ).name.split('|')[0]
	$Data | Add-Member -MemberType NoteProperty -Name TPM-Present -Value (Get-Tpm).TpmPresent
	$Data | Add-Member -MemberType NoteProperty -Name TPM-Ready -Value (Get-Tpm).TpmReady
	$Data | Add-Member -MemberType NoteProperty -Name TPM-Enabled -Value (Get-Tpm).TpmEnabled
	$Data | Add-Member -MemberType NoteProperty -Name TPM-Ver20 -Value (Get-Tpm).ManufacturerVersionFull20
	$Data | Add-Member -MemberType NoteProperty -Name ChassisStyle -value  ($Arr_ChassisType[(Get-WmiObject Win32_SystemEnclosure).ChassisTypes]).replace("{","").Replace("}","")
    $DrvA =""
    $c=""
	$DrvC=0
    $drv=Get-WmiObject win32_logicaldisk | select FileSystem, Caption,  DriveType, FreeSpace, Name, MediaType, Size, VolumeSerialNumber, Status, StatusInfo | where DriveType -eq 3 
    $drvA = ""
   foreach ($d in $drv) {
		Add-Member -InputObject $d -MemberType NoteProperty -Name Used -Value ($d.size - $d.freespace)
		$a=('Filesystem: {0}  Drive: {1}  Size: {2:N0} MB  Used: {8:N0} MB  Free: {3:N0} MB  Percent Free: {4}% Drive: {5} Media:{6} Status: {7}' -f $d.FileSystem, $d.caption, [math]::truncate($d.Size / 1048576), [math]::truncate($d.FreeSpace / 1048576),  [math]::truncate($d.FreeSpace / ($d.Size+1)*100), $hdtype[$d.DriveType], $MediaTypeArr[$d.mediatype], $d.Status, [math]::Truncate($d.Used / 1048576))
    	$b= ('Type: {0} -{1}- Media {2} -{3}- ' -f $hdtype[$d.MediaType], $d.mediatype, $MediaTypeArr[$d.drivetype], $d.drivetype)
        $c=($a,$b) -join("`n")
        $drvA=($drvA,$c) -join("`n")
		$DrvC++
    }
    $Data | Add-Member -MemberType NoteProperty -Name DriveCount -value $DrvC
	$Data | Add-Member -MemberType NoteProperty -Name Drives -Value $DrvA
	
	# Get-WmiObject win32_computersystem | select   Manufacturer, Model, SystemFamily, SystemSKUNumber | FL

    # Get-WmiObject win32_bios | fl SerialNumber
    $drv=Get-WmiObject win32_logicaldisk | select FileSystem, Caption,  DriveType, FreeSpace, Name, MediaType, Size, VolumeSerialNumber, Status, StatusInfo | where DriveType -eq 3 
    # foreach ($d in $drv) {
    #     write-output ('Filesystem: {0}  Drive: {1}  Size: {2:N0} MB  Free: {3:N0} MB Percent Free: {4}% Drive: {5} Media:{6} Status: {7}' -f $d.FileSystem, $d.caption, [math]::truncate($d.Size / 1048576), [math]::truncate($d.FreeSpace / 1048576),  [math]::truncate($d.FreeSpace / ($d.Size+1)*100), $hdtype[$d.DriveType], $MediaTypeArr[$d.mediatype], $d.Status)
    # write-output ('Type: {0} -{1}- Media {2} -{3}- ' -f $hdtype[$d.MediaType], $d.mediatype, $MediaTypeArr[$d.drivetype], $d.drivetype)
    #     }
	write-output "             "
    #"DATA----"
    #$Data | Format-List
	# $DrvC = drive count
	#write-output "Number of Drives: $DrvC" 
	# $Data.Drives | Format-List
	Show-Monitors
	Show-DiskPartitions | sort DriveLetter | select DriveLetter, VolumeName, Partition, DiskModel | fl
    return $Data
} 

function Show-Battery {
	$Arr_Batt_Chemistry=@('x','Other','Unknown','LeadAcid','NiCd','NiMH','LiIon','Zinc Air','LiPo')
	$Arr_Availability=@("x",'Other','Unknown','Running/Full Power','Warning','In Test','Not Applicable','Power Off','Offline','Off Duty','Degraded','Not Installed','Install Error','PowerSave/Unknown','PowerSave/Low Power','PowerSave/Standby','Power Cycle','PowerSave/Warning','Paused','Not Ready','Not Configured','Quiesced')
	$Arr_Batt_BattStat=@("x",'Other','Unknown','FullyCharged','Low','Critical','Charging','Charging/High','Charging/Low','Charging/Critical','Undefined','PartiallyCharged')
	$Batt=Get-WmiObject win32_Battery | Select SystemName, Caption, Name, DeviceID, Availability, BatteryStatus, Description, Status, StatusInfo, Chemistry, EstimatedRunTime, EstimatedChargeRemaining
	if ($Batt.count -eq 0) {
		"`nNo Battery Information retrieved`n"
		return
	}
	$Batt | Add-Member -MemberType NoteProperty -Name Chemistry-Desc -Value $Arr_Batt_Chemistry[$Batt.Chemistry]
	$Batt | Add-Member -MemberType NoteProperty -Name Availability-Desc -Value $Arr_Availability[$Batt.Availability]
	$Batt | Add-Member -MemberType NoteProperty -Name Status-Desc -Value $Arr_Batt_BattStat[$Batt.BatteryStatus]
	$Batt
	New-TimeSpan -minutes ($Batt.EstimatedRunTime/100000) | ft Days, Hours, Minutes
	New-TimeSpan -minutes ($Batt.EstimatedRunTime) | ft Days, Hours, Minutes
}

function Show-OfficeDetails {
	$a=Get-ChildItem -Recurse -Path 'C:\Program Files\', 'C:\Program Files (x86)\'  -ErrorAction SilentlyContinue  -Include outlook.exe | where Fullname -notlike '*Download*'
	if($null -eq $a.FullName) {
		"`nNo office installation found in standard program files folders.`n"
		$a=Get-ChildItem -Recurse -Path 'C:\Program Files\', 'C:\Program Files (x86)\' -ErrorAction SilentlyContinue  -Include ospp.vbs
		if($null -ne $a.FullName) {cscript $a.FullName /dstatus}
	} else {
		$a.FullName
		[System.Diagnostics.FileVersionInfo]::GetVersionInfo($a.FullName) | fl
		$a=Get-ChildItem -Recurse -Path 'C:\Program Files\', 'C:\Program Files (x86)\' -ErrorAction SilentlyContinue  -Include ospp.vbs
		cscript $a.FullName /dstatus
	}
}

function Show-NetVer {
	#Ref: https://mostechtips.com/how-to-use-powershell-to-check-net-framework-version/
	$b = $PSVersionTable.PSVersion
	Write-Output ("`nPowerShell: " + $b + "`n`n.Net Version")
	Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, Version | Sort-Object Version
 }

function Show-AllCustomFunctions {
	$Global:FunctionProcess = "Show-EOLInfo"
	Show-EOLInfo
	$Global:FunctionProcess = "Show-Info"
	Show-Info
	$Global:FunctionProcess = "Show-Disks"
	Show-Disks
	$Global:FunctionProcess = "Show-VideoConnections"
	Show-VideoConnections
	$Global:FunctionProcess = "Show-Monitors"
	Show-Monitors
	$Global:FunctionProcess = "Show-Disks"
	Show-Disks
	$Global:FunctionProcess = "Show-DiskPartitions"
	Show-DiskPartitions | sort DriveLetter | format-table  DriveLetter, DiskSize, FreeSpace, DiskModel, VolumeName, Partition
	$Global:FunctionProcess = "Show-DriveSummary"
	Show-DriveSummary -Physical
	$Global:FunctionProcess = "Show-UserSession"
	Show-UserSession
	$Global:FunctionProcess = "Show-IP"
	Show-IP | where virtual -eq $false | ft IPAddress, Name, Status, InterfaceDescription, LinkSpeed, @{L='Config';E={$_.PrefixOrigin}}
	$Global:FunctionProcess = "Show-SlotUsage"
	Show-SlotUsage
	$Global:FunctionProcess = "Show-MemoryDetail"
	Show-MemoryDetail
	$Global:FunctionProcess = "None"
}

function Show-AvailableCustomfunctions { param([switch]$NoSort)
	write-output " "
	if($NoSort) {
		Get-Item -Path function:\  | sort Name | findstr "Show- Dell- Pax8- WMI- DellOMSA-"
	} else {
		Get-Item -Path function:\  | findstr "Show- Dell- Pax8- WMI- DellOMSA-" | Sort.exe 
	}
	write-output " "
}

Function Show-SMB {
	$shares = Get-WmiObject Win32_Share
	if(($shares | where name -notlike "*$").Count -ne 0)  {
		$shares | Where ShareType -ne "InterprocessCommunication" | Sort-Object Path | Format-Table Name, Path, ShareState, ShareType
	} else {
	Write-Output "No shares exist"}
}

Function Show-SMB-OLD {
	Get-WmiObject Win32_Share | ft -autosize Name, Path, Caption, Description, Status, Type
	}

Function Show-DiskPartitionInfo {
	Show-DiskPartitions |sort DriveLetter | ft DiskSize, Size, FreeSpace, DriveLetter, DiskModel, VolumeName, Partition
}

Function Show-FolderSize { param ([string]$fPath)
	if($fPath.Length -eq 0) {$fPath = ".\*.*"}
	#$fPath = ".\*.*"
	$sz = Get-ChildItem $fPath -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum #| ft Property, Count, @{e={"{0:N0}" -f $_.sum};l="Sum"}
	$sz | Add-Member -MemberType NoteProperty -Name FolderPath -Value $fPath
	$sz | Format-List FolderPath, @{e={"{0:N0}" -f $_.sum};l="Size"}, Count
}

Function ExplainArray { param ([ValidateSet("HDType","MediaType","SysSlotUsage","ConnType","BattChemistry","BattStat","Availability")]$ArraySel, [int]$ArrayVal) 
# 1-hdtype, 2-MediaTypeArr, 3-SysSlotUsage_Arr, 4-ConnType_Arr, 5-Arr_Batt_Chemistry, 6-Arr_Availability, 7-Arr_Batt_BattStat
	$hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
	$MediaTypeArr=@('Unspecified',"x","Floppy/Removable",'HDD','SSD','SCM')
	$SysSlotUsage_Arr=@("Reserved","Other","Unknown","Available","In Use")
	$ConnType_Arr=@('Unknown', 'Other', 'Male', 'Female', 'Shielded', 'Unshielded', 'SCSI (A) High-Density (50 pins)', 'SCSI (A) Low-Density (50 pins)', 'SCSI (P) High-Density (68 pins)', 'SCSI SCA-I (80 pins)', 'SCSI SCA-II (80 pins)', 'SCSI Fibre Channel (DB-9, Copper)', 'SCSI Fibre Channel (Fibre)', 'SCSI Fibre Channel SCA-II (40 pins)', 'SCSI Fibre Channel SCA-II (20 pins)', 'SCSI Fibre Channel BNC', 'ATA 3-1/2 Inch (40 pins)', 'ATA 2-1/2 Inch (44 pins)', 'ATA-2', 'ATA-3', 'ATA/66', 'DB-9', 'DB-15', 'DB-25', 'DB-36', 'RS-232C', 'RS-422', 'RS-423', 'RS-485', 'RS-449', 'V.35', 'X.21', 'IEEE-488', 'AUI', 'UTP Category 3', 'UTP Category 4', 'UTP Category 5', 'BNC', 'RJ11', 'RJ45', 'Fiber MIC', 'Apple AUI', 'Apple GeoPort', 'PCI', 'ISA', 'EISA', 'VESA', 'PCMCIA', 'PCMCIA Type I', 'PCMCIA Type II', 'PCMCIA Type III', 'ZV Port', 'CardBus', 'USB', 'IEEE 1394', 'HIPPI', 'HSSDC (6 pins)', 'GBIC', 'DIN', 'Mini-DIN', 'Micro-DIN', 'PS/2', 'Infrared', 'HP-HIL', 'Access.bus', 'NuBus', 'Centronics', 'Mini-Centronics', 'Mini-Centronics Type-14', 'Mini-Centronics Type-20', 'Mini-Centronics Type-26', 'Bus Mouse', 'ADB', 'AGP', 'VME Bus', 'VME64', 'Proprietary', 'Proprietary Processor Card Slot', 'Proprietary Memory Card Slot', 'Proprietary I/O Riser Slot', 'PCI-66MHZ', 'AGP2X', 'AGP4X', 'PC-98', 'PC-98-Hireso', 'PC-H98', 'PC-98Note', 'PC-98Full', 'PCI-X', 'Sbus IEEE 1396-1993 32 bit', 'Sbus IEEE 1396-1993 64 bit', 'MCA', 'GIO', 'XIO', 'HIO', 'NGIO', 'PMC', 'Future I/O', 'InfiniBand', 'AGP8X', 'PCI-E')
	$Arr_Batt_Chemistry=@('x','Other','Unknown','LeadAcid','NiCd','NiMH','LiIon','Zinc Air','LiPo')
	$Arr_Availability=@("x",'Other','Unknown','Running/Full Power','Warning','In Test','Not Applicable','Power Off','Offline','Off Duty','Degraded','Not Installed','Install Error','PowerSave/Unknown','PowerSave/Low Power','PowerSave/Standby','Power Cycle','PowerSave/Warning','Paused','Not Ready','Not Configured','Quiesced')
	$Arr_Batt_BattStat=@("x",'Other','Unknown','FullyCharged','Low','Critical','Charging','Charging/High','Charging/Low','Charging/Critical','Undefined','PartiallyCharged')
	
	if ($ArraySel -EQ 1 -or $ArraySel -EQ "HDType") { return $hdtype[$ArrayVal] } #hdtype
	if ($ArraySel -EQ 2 -or $ArraySel -EQ "MediAtype") { return $MediaTypeArr[$ArrayVal] } #MediaTypeArr
	if ($ArraySel -EQ 3 -or $ArraySel -EQ "SysSlotUsage") { return $SysSlotUsage_Arr[$ArrayVal] } #SysSlotUsage_Arr
	if ($ArraySel -EQ 4 -or $ArraySel -EQ "ConnType") { return $ConnType_Arr[$ArrayVal] } #ConnType_Arr
	if ($ArraySel -EQ 5 -or $ArraySel -EQ "BattChemistry") { return $Arr_Batt_Chemistry[$ArrayVal] } #Arr_Batt_Chemistry
	if ($ArraySel -EQ 6 -or $ArraySel -EQ "Availability") { return $Arr_Availability[$ArrayVal] } #Arr_Availability
	if ($ArraySel -EQ 7 -or $ArraySel -EQ "BattStat") { return $Arr_Batt_BattStat[$ArrayVal] } #Arr_Batt_BattStat
}

Function Show-Processor {
	gwmi win32_processor | select DeviceID, LoadPercentage, Manufacturer, Name, NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors, ThreadCount, UpgradeMethod, VirtualizationFirmwareEnabled, VMMonitorModeExtensions | fl
}

Function Show-DiskSmartInfo {
 Get-Disk | Get-StorageReliabilityCounter | sort DeviceId | fl DeviceId, FlushLatencyMax, LoadUnloadCycleCount, PowerOnHours, ReadErrorsCorrected, ReadErrorsTotal, ReadErrorsUncorrected, Temperature, Wear, WriteErrorsTotal, WriteErrorsCorrected, WriteErrorsUncorrected, WriteLatencyMax, ObjectId
}

Function Show-DiskSummary {
#Show-Disks
        Clear-Host
        Hostname
        Get-WmiObject win32_logicaldisk | where DriveType -eq 3 | format-table FileSystem, Caption,  DriveType, Size, FreeSpace, @{L='Percent Free';E={($_.FreeSpace / ($_.Size+1)*100)}}, Name, MediaType,
VolumeSerialNumber -autosize # math=free space
        $drv=Get-WmiObject win32_logicaldisk | select FileSystem, Caption,  DriveType, FreeSpace, Name, MediaType, Size, VolumeSerialNumber | where DriveType -eq 3
        $drv | ft -autosize
    foreach ($d in $drv) {
        Write-Host ("Filesystem: {0}  `tDrive: {1}  `tSize: {2:N0} MB `tFree: {3:N0} MB `tPercent Free: {4}% " -f $d.FileSystem, $d.caption, [math]::truncate($d.Size / 1048576), [math]::truncate($d.FreeSpace / 1048576),  [math]::truncate($d.FreeSpace / ($d.Size+1)*100))
        }
       # Get-WmiObject  win32_pnpentity -Filter "(PNPDeviceid like '%DISK%') AND NOT (PNPDeviceid LIKE '%SNAPSHOT%')" | select caption, pnpdeviceid
        write-Host
        $hdtype=('Unk','SCSI','ATAPI','ATA','1394','SSA','FibChasn','USB','RAID','iSCSI','SAS','SATA','SD','MMC','Virt-RES','FileBacked-Virt','StorSpc','NVMe')
        $bustype=$hdtype
    $a=Get-WmiObject -Namespace root\microsoft\windows\storage -Class MSFT_Disk | select Model,BusType
    foreach ($b in $a) {$b | Add-Member -MemberType NoteProperty -Name BusInt -Value $hdtype[$b.bustype]}
    $a
#Show-DiskPartitions

#        Get-WmiObject Win32_DiskDrive | ForEach-Object {
#        $disk = $_
#        $partitions = "ASSOCIATORS OF " +
#                                        "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
#                                        "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
#        Get-WmiObject -Query $partitions | ForEach-Object {
#                $partition = $_
#                $drives = "ASSOCIATORS OF " +
#                                "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
#                                "WHERE AssocClass = Win32_LogicalDiskToPartition"
#                Get-WmiObject -Query $drives | ForEach-Object {
#                        New-Object -Type PSCustomObject -Property @{
#                                Disk        = $disk.DeviceID
#                                DiskSize    = $disk.Size
#                                DiskModel   = $disk.Model
#                                Partition   = $partition.Name
#                                RawSize     = $partition.Size
#                                DriveLetter = $_.DeviceID
#                                VolumeName  = $_.VolumeName
#                                Size        = $_.Size
#                                FreeSpace   = $_.FreeSpace
#                                }
#                        }
#                }
#        }
}

<# Orvil Reference EOL:
Client Location : Al Willeford Chevrolet/Main
Computer Name : DESKTOP-MQ5O6JG
User : Not Logged In
Agent Type : WorkStation
Manufacturer : Hewlett-Packard
Agent Mainboard : HP Compaq Elite 8300 SFF
Agent OS : Microsoft Windows 10 Pro x64
Agent Memory Total : 8066mb
Agent Serial Number : MXL3521985
CPU : Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
C Drive Total Space : 223 GB
C Drive Free Space : 179 GB
C Drive Free Percent : 81%
Total Internal Drive : 1
#>

&{Clear-Host 
$PSVersionTable.PSVersion
if($PSVersionTable.PSVersion.Major -lt 3.0) {Write-Host " PS Version too low " -ForegroundColor White -BackgroundColor Red}
Show-AvailableCustomfunctions -NoSort | ft
}

