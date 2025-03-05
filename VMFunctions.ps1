#Virtual Machine Functions

#Get-DiskImage -ImagePath "D:\External\ISO-Files\SERVER_EVAL_x64FRE_en-us.iso" | select ImagePath, @{l="ImageSize";e={[math]::round($_.FileSize/1073741824,3)}}

function Show-AVHDTrace { param([parameter(Mandatory=$true)][string]$VHDFile)
#  $VHDFile =Read-Host "VHD"
  do {
    $s = get-vhd $VHDFile
    $s | select  VhdFormat, FileSize, Size, Path, ParentPath | ft -AutoSize
    $VHDFile = $s.ParentPath
  } until ($VHDFile.Length -eq 0)
}

Function Do-VHDTraceMerge{ param([parameter(Mandatory=$true)][string]$VHDFile)
#  $VHDFile =Read-Host "VHD"
  do {
    $s = get-vhd $VHDFile
    $s | select  VhdFormat, FileSize, Size, Path, ParentPath | ft -AutoSize
    $VHDFile = $s.ParentPath
    if($s.ParentPath.length -ne 0) {Merge-VHD -Path $s.Path}
  } until ($VHDFile.Length -eq 0)
}

function Show-RunningVMInfo {
### RUNNING ###
if(!(isadmin)) {Write-Warning "`nAdmin Rights Required.`n`n"; break}
cls
write-output "Running Virtual Machines:"
Get-VM | where state -eq "Running" | ft VMName, State, AutomaticStartAction, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
Get-VM | where state -eq "Running" | ft VMName, State, AutomaticStartAction, AutomaticStartAction, AutomaticStopAction, @{e={$_.memorystartup/1073741824};l="StartMemory-GB"},@{e={$_.MemoryAssigned/1073741824};l="AssignMemory-GB"}, OperationalStatus, State, ProcessorCount, Name -AutoSize
$vhds = Get-VM | where state -eq "Running" | select -expandproperty HardDrives
write-output "Virtual Machine Configurations:"
Get-VM | ft -AutoSize VMName, State, OperationalStatus, MemoryAssigned, AutomaticStartAction, AutomaticStopAction, Generation, ProcessorCount, {$_.networkAdapters.count},  {$_.HardDrives.count} ; `
write-output "All Virtual Disks (file-backed):"
  $vhds | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, FileSize, Size, @{l = '%Allocated'; e = { $_.size / $_.size * 100 }; f = "0" }, MinimumSize, Attached, Path -AutoSize -Wrap
write-output "All Virtual Disks (MB Sizes, file-backed):"
  $vhds | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, @{l = "FileSZ"; e = { $_.FileSize / 1GB }; f = "0" }, @{l = "SZ"; e = { $_.Size / 1GB }; f = "0" }, @{l = "MinSZ"; e = { $_.MinimumSize / 1GB }; f = "0" }, @{l = '%Allocated'; e = { $_.size / $_.size * 100};f = "0"}, Path -AutoSize -Wrap ; `
write-output "Physical Disks tied to a virtual machine:"
$vhds | where disknumber -Match "[0-9]+" | ft -autosize
write-output "Virtual disks mapped to virtual machines:"
$vhds | select VMName, ControllerType, Path
}


function Show-AllVMInfo {
### ALL MACHINES ###
if(!(isadmin)) {Write-Warning "`nAdmin Rights Required.`n`n"; break}
cls
write-output "All Virtual Machines:"
Get-VM | ft VMName, State, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
Get-VM | ft VMName, State, AutomaticStartAction, AutomaticStopAction, @{e={$_.memorystartup/1073741824};l="StartMemory-GB"},@{e={$_.MemoryAssigned/1073741824};l="AssignMemory-GB"}, OperationalStatus, ProcessorCount, Name -AutoSize
$vhds = Get-VM | select -expandproperty HardDrives
write-output "Virtual Machine Configurations:"
Get-VM | ft -AutoSize VMName, State, OperationalStatus, MemoryAssigned, AutomaticStartAction, AutomaticStopAction, Generation, ProcessorCount, {$_.networkAdapters.count},  {$_.HardDrives.count} ; 
write-output "All Virtual Disks (file-backed):"
$vhds | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, FileSize, Size, MinimumSize, Attached, Path -AutoSize -Wrap
write-output "All Virtual Disks (MB Sizes, file-backed):"
$vhds | where disknumber -NotMatch "[0-9]+" | get-vhd  | ft VhdFormat, VhdType, @{l="FileSZ";e={$_.FileSize/1GB};f="0"}, @{l="SZ";e={$_.Size/1GB};f="0"}, @{l="MinSZ";e={$_.MinimumSize/1GB};f="0"}, Path -AutoSize -Wrap ; 
write-output "Physical Disks tied to a virtual machine:"
$vhds | where disknumber -Match "[0-9]+" | ft -autosize
write-output "Virtual disks mapped to virtual machines:"
$vhds | select VMName, ControllerType, Path | ft -AutoSize
}
