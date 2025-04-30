#WMI Details
Function WMI-OperatingSystemDetails {
	#CIM_OperatingSystem
	Get-WmiObject -Class Win32_OperatingSystem | Select-Object CSName, Manufacturer, Caption, Version, BuildNumber, Debug, LastBootUpTime, InstallDate, LocalDateTime, EncryptionLevel, NameNumberOfUsers, Organization, RegisteredUser
}

Function WMI-Processor {
	$a = Get-WmiObject win32_processor | select Availability, CpuStatus, DeviceID, ExtClock, MaxClockSpeed, CurrentClockSpeed, PowerManagementSupported, ProcessorType, SocketDesignation, Architecture, Description, 	Manufacturer, Name, NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors, Role, SecondLevelAddressTranslationExtensions, UpgradeMethod, VirtualizationFirmwareEnabled, VMMonitorModeExtensions
	if ($a.count -eq $null) {$c = 1;$b=$a} else {$c = $a.count;$b=$a[0]}
	Write-Host "CPU Chips: $c" -nonewline
	$b | Add-Member -MemberType NoteProperty -Name SLAT -Value $b.SecondLevelAddressTranslationExtensions
	$b = $b | Select-Object -Property * -ExcludeProperty SecondLevelAddressTranslationExtensions
	$b | Format-List 
}

Function WMI-Memory {
	[string[]]$FORM_FACTORS = @('Invalid', 'Other', 'Unknown', 'SIMM', 'SIP', 'Chip', 'DIP', 'ZIP', 'Proprietary Card', 'DIMM', 'TSOP', 'Row of chips', 'RIMM', 'SODIMM', 'SRIMM', 'FB-DIMM', 'Die' )
	[string[]]$MEMORY_TYPES = @('Invalid', 'Other', 'Unknown', 'DRAM', 'EDRAM', 'VRAM', 'SRAM', 'RAM', 'ROM', 'FLASH', 'EEPROM', 'FEPROM', 'EPROM', 'CDRAM', '3DRAM', 'SDRAM', 'SGRAM', 'RDRAM', 'DDR', 'DDR2', 'DDR2 FB-DIMM', 'Reserved', 'Reserved', 'Reserved', 'DDR3', 'FBD2', 'DDR4', 'LPDDR', 'LPDDR2', 'LPDDR3', 'LPDDR4', 'Logical non-volatile device', 'HBM (High Bandwidth Memory)', 'HBM2 (High Bandwidth Memory Generation 2)','DDR5', 'LPDDR5' )
	[string[]]$TYPE_DETAILS = @('Reserved', 'Other', 'Unknown', 'Fast-paged', 'Static column', 'Pseudo-static', 'RAMBUS', 'Synchronous', 'CMOS', 'EDO', 'Window DRAM', 'Cache DRAM', 'Non-volatile', 'Registered (Buffered)','Unbuffered (Unregistered)', 'LRDIMM' )
	$TYPE_DETAILS_HASH = @{'Reserved'=1; 'Other'=2; 'Unknown'=4; 'Fast-paged'=8; 'Static column'=16; 'Pseudo-static'=32; 'RAMBUS'=64; 'Synchronous'=128; 'CMOS'=256; 'EDO'=512; 'Window DRAM'=1024; 'Cache DRAM'=2048; 'Non-volatile'=4096; 'Registered (Buffered)'=8192;'Unbuffered (Unregistered)'=16384; 'LRDIMM'=8192 }
	Function ExplainMemory { Param ([int]$FormFactor, [int]$MemoryType, [int]$TypeDetails) 
		if($FormFactor) {$FORM_FACTORS[$FormFactor + 1]}
		if($MemoryType) {$MEMORY_TYPES[$MemoryType]}
		if($TypeDetails) {
			[array]$array=$null
			foreach ($Bit in ($type_details_hash.GetEnumerator() | Sort-Object -Property Value )){
				if (($TypeDetails -band $Bit.Value) -ne 0){
					$array += $Bit.Key 
				}
			}
		$array -join " | "
	    }
	}

	$a = Get-WmiObject Win32_PhysicalMemory 
	$a | Format-Table -AutoSize BankLabel, @{n="Capacity(GB)";e={$_.Capacity/1GB}}, Caption, DeviceLocator, FormFactor, Manufacturer, MemoryType, Model, PartNumber, SerialNumber, PositionInRow, Speed, SKU, Tag, TypeDetail 
	$b = ($a.capacity | Measure-Object -sum).sum/(1048576*1024)
	Write-Host "TotalCapacity: $b GB`n" 
}

Function WMI-CaseInfo {
	$Arr_ChassisType = @("0-x", "Other", "Unknown", "Desktop", "Low Profile Desktop", "Pizza Box", "Mini Tower", "Tower", "Portable", "Laptop", "Notebook", "Hand Held", "Docking Station", "All in One", "Sub Notebook ", "Space-Saving", "Lunch Box", "Main System Chassis", "Expansion Chassis", "SubChassis", "Bus Expansion Chassis", "Peripheral Chassis", "Storage Chassis", "Rack Mount Chassis", "Sealed-Case PC", "Tablet", "Convertible", "Detachable")
	$a = Get-WmiObject Win32_SystemEnclosure | select Name, Tag, Caption, ChassisTypes, LockPresent, Manufacturer, SKU, VisibleAlarm, SerialNumber
	$a.ChassisTypes = $Arr_ChassisType[$a.ChassisTypes]
	$a 
}

Function WMI-MemorySlots {
	$a = Get-WmiObject -Class "win32_PhysicalMemoryArray" | select tag, MaxCapacity, MemoryDevices, MemoryErrorCorrection, Use, Description
	$a.MaxCapacity = $a.MaxCapacity /1048576
	$b=(Get-WmiObject Win32_PhysicalMemory).count
	if ($b -eq $null) {$b = 1}
	$s = $b.ToString() + " of " + $a.MemoryDevices.ToString()
	$a | Add-Member -MemberType NoteProperty -Name SlotUsage -Value $s
	$a | Format-List *
}

Function WMI-Disks {
	Get-WmiObject Win32_DiskDrive | sort index | ft -AutoSize Index, InterfaceType, @{n="Size(GB)";e={([int]($_.Size/1GB*10)/10)}}, Caption, Model, SerialNumber
	Get-WmiObject Win32_LogicalDisk | sort DeviceID | ft -AutoSize DriveType, DeviceID, @{n="Size(GB)";e={$_.Size/1GB}}, @{n="Free Space(GB)";e={$_.FreeSpace/1GB}},@{n="Free%";e={([int]($_.FreeSpace/$_.Size*1000))/10}}
}

#copy-item -passthru | ft Length, FullName, CreationTime, LastAccessTime, LastWriteTime, Attributes
Function Show-WMIFunctions {
	Clear-Host
	( get-item function:\wmi-* | sort name).name | ForEach-Object {&$_}
}

Function WMI-NetAdapter {
	Get-NetAdapter | where AdminStatus -ne "Down" | select MacAddress, Status, LinkSpeed, AdminStatus, MediaConnectionState, Name, DriverDescription, Virtual, VlanID | where virtual -eq $false | ft -a
}

# Get-WmiObject -class "win32_physicalmemory" | Format-Table -AutoSize DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB}},  FormFactor, MemoryType, Model,  TypeDetail, PartNumber
# Calculate total storage in GB:
# [int](((gwmi win32_logicaldisk | select size | Measure-Object size -Sum).sum / 1073741824)*100)/100
# Calculate total used space across all in GB:
#$a = (gwmi win32_logicaldisk | select size | Measure-Object size -Sum).sum; $b = (gwmi win32_logicaldisk | select FreeSpace | Measure-Object FreeSpace -Sum).Sum; [int]((($a-$b)/1073741824)*100)/100
if (!$global:NoGlobalOutput) {Show-WMIFunctions}
