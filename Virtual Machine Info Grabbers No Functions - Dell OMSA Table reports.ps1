get-disk | sort disknumber | ft DiskNumber, PartitionStyle, ProvisioningType, OperationalStatus, HealthStatus, BusType, BootFromDisk, FriendlyName, IsBoot, IsClustered,  IsOffline, IsSystem, Manufacturer, Model, Size, AllocatedSize, OfflineReason, AdapterSerialNumber, Location

Total Count:
(gwmi win32_share).count

(gwmi win32_share) | ft Type, Status, Name, Path, Description

(gwmi win32_share) | sort type, name | ft -a Type, Status, Name, Path, Description
(gwmi win32_share) | sort type, name | select Type, Status, Name, Path, Description | convertto-csv -notypeinformation | clip

function Show-PathSize{ param([string]$path)
  $sb = (Get-ChildItem $path  -Recurse | Measure-Object length -sum).sum
  $sm= $sb / 1MB 
  write-host "Bytes: $sb"
  write-host "MB: $sm"
}

DisplayName, Publisher, DisplayVersion, 


&{
### RUNNING ###
cls
write-output "Running Virtual Machines:"
Get-VM | where state -eq "Running" | ft VMName, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
$vhds = Get-VM | where state -eq "Running" | select -expandproperty HardDrives
write-output "Virtual Machine Configurations:"
Get-VM | ft -AutoSize VMName, State, OperationalStatus, MemoryAssigned, AutomaticStartAction, AutomaticStopAction, Generation, ProcessorCount, {$_.networkAdapters.count},  {$_.HardDrives.count} ; `
write-output "All Virtual Disks (file-backed):"
$vhds | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, FileSize, Size, MinimumSize, Attached, Path -AutoSize -Wrap
write-output "All Virtual Disks (MB Sizes, file-backed):"
Get-VM | where state -eq "Running" | select -expandproperty HardDrives | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, @{l="FileSZ";e={$_.FileSize/1GB};f="0"}, @{l="SZ";e={$_.Size/1GB};f="0"}, @{l="MinSZ";e={$_.MinimumSize/1GB};f="0"}, Path -AutoSize -Wrap ; `
write-output "Physical Disks tied to a virtual machine:"
Get-VM | where state -eq "Running" | select -expandproperty HardDrives | where disknumber -Match "[0-9]+" | ft -autosize
write-output "Virtual disks mapped to virtual machines:"
Get-VM | where state -eq "Running" | select -expandproperty HardDrives | select VMName, ControllerType, Path
}


&{
### ALL MACHINES ###
cls
write-output "Running Virtual Machines:"
Get-VM | ft VMName, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
$vhds = Get-VM | select -expandproperty HardDrives
write-output "Virtual Machine Configurations:"
Get-VM | ft -AutoSize VMName, State, OperationalStatus, MemoryAssigned, AutomaticStartAction, AutomaticStopAction, Generation, ProcessorCount, {$_.networkAdapters.count},  {$_.HardDrives.count} ; `
write-output "All Virtual Disks (file-backed):"
$vhds | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, FileSize, Size, MinimumSize, Attached, Path -AutoSize -Wrap
write-output "All Virtual Disks (MB Sizes, file-backed):"
Get-VM | select -expandproperty HardDrives | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, @{l="FileSZ";e={$_.FileSize/1GB};f="0"}, @{l="SZ";e={$_.Size/1GB};f="0"}, @{l="MinSZ";e={$_.MinimumSize/1GB};f="0"}, Path -AutoSize -Wrap ; `
write-output "Physical Disks tied to a virtual machine:"
Get-VM | select -expandproperty HardDrives | where disknumber -Match "[0-9]+" | ft -autosize
write-output "Virtual disks mapped to virtual machines:"
Get-VM  | select -expandproperty HardDrives | select VMName, ControllerType, Path
}

====
AVHD Tracking
--


$r=omreport chassis -fmt xml
$x = [xml]$r
$x.OMA.Parent.processor.DevProcessorObj | ft -AutoSize Manufacturer, Version, Brand, maxSpeed, curSpeed, status, upgrade
$x.OMA.Parent.memory.MemDevObj | select Manufacturer, PartNumber, SerialNumber, AssetTag, extendedSize, size, formfactor, type, typeDetail | ft -AutoSize

&{
Clear-Host
if($host.ui.RawUI.BufferSize.Width -lt 1199) {"Window size narrow, <1200, wrapping will likely occur."}
omreport chassis processors -fmt tbl | findstr /v /c:----
Write-Output "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport chassis info -fmt tbl | findstr /v /c:----
Write-Output "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport chassis memory -fmt tbl | findstr /v /c:----
Write-Output "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport chassis remoteaccess -fmt tbl | findstr /v /c:----
Write-Output "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport storage controller -fmt tbl | findstr /v /c:----
Write-Output "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport storage controller controller=0 info=pdslotreport -fmt tbl | findstr /v /c:----
Write-Output "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport storage  vdisk controller=0 -fmt tbl | findstr /v /c:----
" ";" "
} 

Get-VMHost | fl ComputerName, VirtualHardDiskPath, VirtualMachinePath, MacAddressMinimum, MacAddressMaximum, @{e={[math]::round($_.MemoryCapacity/1048576/1024)};l="MemoryCapacity(MB)"}, LogicalProcessorCount, NumaSpanningEnabled, EnableEnhancedSessionMode, InternalNetworkAdapters, ExternalNetworkAdapters
Get-VMHost | ft -AutoSize ComputerName, VirtualHardDiskPath, VirtualMachinePath, MacAddressMinimum, MacAddressMaximum,  @{e={[math]::round($_.MemoryCapacity/1048576/1024)};l="MemoryCapacity(MB)"}, LogicalProcessorCount

--
omreport storage pdisk controller=0 -fmt tbl
write-host "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine
omreport storage controller controller=0 info=pdslotreport -fmt tbl
write-host "##########" -backgroundcolor Red -foregroundcolor White -NoNewLine

