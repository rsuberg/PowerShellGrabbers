# Memory Summary Function
#Function Show-MemorySummary {
# 7.18.1. Form factor @offset 0x0E [Val+1]
[string[]]$FORM_FACTORS = @(
'Invalid', 'Other', 'Unknown', 'SIMM', # 00-03h
'SIP', 'Chip', 'DIP', 'ZIP', # 04-07h
'Proprietary Card', 'DIMM', 'TSOP', 'Row of chips', # 08-0Bh
'RIMM', 'SODIMM', 'SRIMM', 'FB-DIMM', # 0C-0Fh
'Die' # 10h
)

# 7.18.2. Memory type @offset 0x12 [Val]
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

# 7.18.3. Type detail @offset 0x13 **BIT-MAPPED**
[string[]]$TYPE_DETAILS = @(
'Reserved', 'Other', 'Unknown', 'Fast-paged', # bit 0-3
'Static column', 'Pseudo-static', 'RAMBUS', 'Synchronous', # bit 4-7
'CMOS', 'EDO', 'Window DRAM', 'Cache DRAM', # bit 8-11
'Non-volatile', 'Registered (Buffered)',
'Unbuffered (Unregistered)', 'LRDIMM' # 0C-0Fh
)

$TYPE_DETAILS_HASH = @{
'Reserved'=1; 'Other'=2; 'Unknown'=4; 'Fast-paged'=8; # bit 0-3
'Static column'=16; 'Pseudo-static'=32; 'RAMBUS'=64; 'Synchronous'=128; # bit 4-7
'CMOS'=256; 'EDO'=512; 'Window DRAM'=1024; 'Cache DRAM'=2048; # bit 8-11
'Non-volatile'=4096; 'Registered (Buffered)'=8192;
'Unbuffered (Unregistered)'=16384; 'LRDIMM'=8192 # 0C-0Fh
}

# Memory Enums Explain Functions
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

#
#OneLiner
#Uses ExplainMemory and above tables

#$PysicalMemory = Get-WmiObject -class "win32_physicalmemory" -namespace "root\CIMV2"
#$PysicalMemory | Format-Table -AutoSize Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB}}, Speed, MemoryType, Manufacturer, Model, PartNumber, SerialNumber, @{n="TypeDesc";e={ExplainMemory -MemoryType $_.SMBiosMemorytype}}, @{n="FormFactorStr";e={ExplainMemory -FormFactor $_.formfactor}},  @{n="Details";e={ExplainMemory -TypeDetails $_.TypeDetail}}# , FormFactor, SMBIOSMemoryType, TypeDetail

#$PysicalMemory | Format-List   Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB}}, Speed, MemoryType, Manufacturer, Model, PartNumber, SerialNumber, @{n="TypeDesc";e={ExplainMemory -MemoryType $_.SMBiosMemorytype}}, @{n="FormFactorStr";e={ExplainMemory -FormFactor $_.formfactor}},  @{n="Details";e={ExplainMemory -TypeDetails $_.TypeDetail}}# , FormFactor, SMBIOSMemoryType, TypeDetail

#
function Show-MemorySummary { Param ( [string]$Computername = ".", [switch]$Listing
	) 
	#cls 
	$PysicalMemory = Get-WmiObject -class "win32_physicalmemory" -namespace "root\CIMV2" -ComputerName $Computername 
    $WmiSlots = Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2" -ComputerName $Computername
    $MaxMemA = ($WmiSlots.MaxCapacityEx)/1MB
    $MaxMemB = ($WmiSlots.MaxCapacity)/1MB
	$TotalSlots = (($WmiSlots).MemoryDevices | Measure-Object -Sum).Sum 
	$MaxMemInSlot = $MaxMemB / $TotalSlots
	$UsedSlots = (($PysicalMemory) | Measure-Object).Count  
	 
	Write-Host "Memory Modules:" -ForegroundColor Green 
	$PysicalMemory | Format-Table -AutoSize Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB}; a="Center"}, Speed, @{n="TypeDesc";e={ExplainMemory -MemoryType $_.SMBiosMemorytype}; a="Center"}, @{n="FormFactorStr";e={ExplainMemory -FormFactor $_.formfactor}; a="Center"},  @{n="Details";e={ExplainMemory -TypeDetails $_.TypeDetail}}, Manufacturer, Model, PartNumber, SerialNumber # , FormFactor, SMBIOSMemoryType, TypeDetail, MemoryType
	if($Listing) {$PysicalMemory | Format-List Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB}}, Speed, @{n="TypeDesc";e={ExplainMemory -MemoryType $_.SMBiosMemorytype}}, @{n="FormFactorStr";e={ExplainMemory -FormFactor $_.formfactor}},  @{n="Details";e={ExplainMemory -TypeDetails $_.TypeDetail}}, Manufacturer, Model, PartNumber, SerialNumber}
	#$PysicalMemory | Format-Table -AutoSize Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB},a="Center"}, Speed, FormFactor, MemoryType, Model, SMBIOSMemoryType, TypeDetail, Manufacturer, PartNumber, SerialNumber
	 

    Write-Host "Max Memory         : " -ForegroundColor Green -NoNewline
	Write-Host "$MaxMemA GB"  
	Write-Host "Max Memory         : " -ForegroundColor Green -NoNewline
	Write-Host "$($MaxMemA/1KB) TB"  
	Write-Host "Total Memory       : " -ForegroundColor Green -NoNewline
	Write-Host "$((($PysicalMemory).Capacity | Measure-Object -Sum).Sum/1GB) GB" 
	Write-Host "Max Memory         : "  -ForegroundColor Green -NoNewline
    Write-Host "$MaxMemB GB"
	Write-Host "Used Memory Slots  : " -ForegroundColor Green -NoNewline
	Write-Host $UsedSlots 
	Write-Host "Total Memory Slots : " -ForegroundColor Green -NoNewline
	Write-Host $TotalSlots 
	Write-Host "Maximum Device Size: " -ForegroundColor Green -NoNewline
	Write-Host "$MaxMemInSlot GB"
	 
	If($UsedSlots -eq $TotalSlots) { 
	    	Write-Host "All memory slots are in use. No available slots!" -ForegroundColor Yellow 
	} 
}

function Show-MemorySummaryFlat { Param ( [string]$Computername = ".", [switch]$Listing) 
	#cls
	"**MATH MAY BE WRONG ON CALCULATED FIELDS**"
	
	$PysicalMemory = Get-WmiObject -class "win32_physicalmemory" -namespace "root\CIMV2" -ComputerName $Computername 
    $WmiSlots = Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2" -ComputerName $Computername
    $MaxMem = ($WmiSlots.MaxCapacityEx)/1GB
	$TotalSlots = (($WmiSlots).MemoryDevices | Measure-Object -Sum).Sum 
	$MaxMemInSlot = $MaxMem / $TotalSlots
	$UsedSlots = (($PysicalMemory) | Measure-Object).Count  
 
	Write-Output "Memory Modules:" 
	$PysicalMemory | Format-Table -AutoSize Tag, BankLabel, DeviceLocator, @{n="Size(GB)";e={$_.Capacity/1GB}; a="Center"}, Speed, @{n="TypeDesc";e={ExplainMemory -MemoryType $_.SMBiosMemorytype}; a="Center"}, @{n="FormFactorStr";e={ExplainMemory -FormFactor $_.formfactor}; a="Center"},  @{n="Details";e={ExplainMemory -TypeDetails $_.TypeDetail}}, Manufacturer, Model, PartNumber, SerialNumber # , FormFactor, SMBIOSMemoryType, TypeDetail, MemoryType
	#$PysicalMemory | Format-Table -AutoSize Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB},a="Center"}, Speed, FormFactor, MemoryType, Model, SMBIOSMemoryType, TypeDetail, Manufacturer, PartNumber, SerialNumber
 	if($Listing) {$PysicalMemory | Format-List Tag, BankLabel, DeviceLocator, @{n="Capacity(GB)";e={$_.Capacity/1GB}}, Speed, @{n="TypeDesc";e={ExplainMemory -MemoryType $_.SMBiosMemorytype}}, @{n="FormFactorStr";e={ExplainMemory -FormFactor $_.formfactor}},  @{n="Details";e={ExplainMemory -TypeDetails $_.TypeDetail}}, Manufacturer, Model, PartNumber, SerialNumber}

	Write-Output "Total Memory       : $((($PysicalMemory).Capacity | Measure-Object -Sum).Sum/1GB) GB" 
    Write-Output "Max Memory         : $MaxMem GB"  
	Write-Output "Used Memory Slots  : $UsedSlots "
	Write-Output "Total Memory Slots : $TotalSlots"
	Write-Output "Maximum Device Size: $MaxMemInSlot GB"
 
	If($UsedSlots -eq $TotalSlots) { 
		Write-Output " ** All memory slots are in use. No available slots! ** "
	}
}

<#
$WmiSlots = Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2" 
$PysicalMemory = Get-WmiObject -class "win32_physicalmemory" -namespace "root\CIMV2" 
$TotalSlots = (($WmiSlots).MemoryDevices | Measure-Object -Sum).Sum 
$UsedSlots = (($PysicalMemory) | Measure-Object).Count  
Write-Host "Total Memory Slots : "  $TotalSlots
Write-Host "Used Memory Slots  : "  $UsedSlots

$TotalSlots = ((Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2").MemoryDevices | Measure-Object -Sum).Sum 
$UsedSlots = ((Get-WmiObject -class "win32_physicalmemory" -namespace "root\CIMV2") | Measure-Object).Count  
Write-Host "Total Memory Slots : "  $TotalSlots
Write-Host "Used Memory Slots  : "  $UsedSlots

#>
if (!$global:NoGlobalOutput) {Show-MemorySummary}