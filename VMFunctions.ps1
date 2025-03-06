#Virtual Machine Functions

#Get-DiskImage -ImagePath "D:\External\ISO-Files\SERVER_EVAL_x64FRE_en-us.iso" | select-Object ImagePath, @{l="ImageSize";e={[math]::round($_.FileSize/1073741824,3)}}

function Show-AVHDTrace { param([parameter(Mandatory=$true)][string]$VHDFile)
#  $VHDFile =Read-Host "VHD"
  do {
    $s = get-vhd $VHDFile
    $s | select-Object  VhdFormat, FileSize, Size, Path, ParentPath | Format-Table -AutoSize
    $VHDFile = $s.ParentPath
  } until ($VHDFile.Length -eq 0)
}

Function Do-VHDTraceMerge{ param([parameter(Mandatory=$true)][string]$VHDFile)
#  $VHDFile =Read-Host "VHD"
  do {
    $s = get-vhd $VHDFile
    $s | select-Object  VhdFormat, FileSize, Size, Path, ParentPath | Format-Table -AutoSize
    $VHDFile = $s.ParentPath
    if($s.ParentPath.length -ne 0) {Merge-VHD -Path $s.Path}
  } until ($VHDFile.Length -eq 0)
}

function Show-RunningVMInfo {
### RUNNING ###
if(!(isadmin)) {Write-Warning "`nAdmin Rights Required.`n`n"; break}
Clear-Host 
write-output "Running Virtual Machines:"
Get-VM | Where-Object state -eq "Running" | Format-Table VMName, State, AutomaticStartAction, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, State, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
Get-VM | Where-Object state -eq "Running" | Format-Table VMName, State, AutomaticStartAction, AutomaticStartAction, AutomaticStopAction, @{e={$_.memorystartup/1073741824};l="StartMemory-GB"},@{e={$_.MemoryAssigned/1073741824};l="AssignMemory-GB"}, OperationalStatus, State, ProcessorCount, Name -AutoSize
$vhds = Get-VM | Where-Object state -eq "Running" | select-Object -expandproperty HardDrives
write-output "Virtual Machine Configurations:"
Get-VM | Format-Table -AutoSize VMName, State, OperationalStatus, MemoryAssigned, AutomaticStartAction, AutomaticStopAction, Generation, ProcessorCount, {$_.networkAdapters.count},  {$_.HardDrives.count} ; `
write-output "All Virtual Disks (file-backed):"
  $vhds | Where-Object disknumber -NotMatch "[0-9]+" | get-vhd  | Format-Table VhdFormat, VhdType, FileSize, Size, @{l = '%Allocated'; e = { $_.size / $_.size * 100 }; f = "0" }, MinimumSize, Attached, Path -AutoSize -Wrap
write-output "All Virtual Disks (MB Sizes, file-backed):"
  $vhds | Where-Object disknumber -NotMatch "[0-9]+" | get-vhd  | Format-Table VhdFormat, VhdType, @{l = "FileSZ"; e = { $_.FileSize / 1GB }; f = "0" }, @{l = "SZ"; e = { $_.Size / 1GB }; f = "0" }, @{l = "MinSZ"; e = { $_.MinimumSize / 1GB }; f = "0" }, @{l = '%Allocated'; e = { $_.size / $_.size * 100};f = "0"}, Path -AutoSize -Wrap ; `
write-output "Physical Disks tied to a virtual machine:"
$vhds | Where-Object disknumber -Match "[0-9]+" | Format-Table -autosize
write-output "Virtual disks mapped to virtual machines:"
$vhds | select-Object VMName, ControllerType, Path
}


function Show-AllVMInfo {
### ALL MACHINES ###
if(!(isadmin)) {Write-Warning "`nAdmin Rights Required.`n`n"; break}
Clear-Host 
write-output "All Virtual Machines:"
Get-VM | Format-Table VMName, State, AutomaticStartAction, AutomaticStopAction, MemoryStartup, MemoryAssigned, OperationalStatus, ProcessorCount, Name, ComputerName, Notes -AutoSize -Wrap
Get-VM | Format-Table VMName, State, AutomaticStartAction, AutomaticStopAction, @{e={$_.memorystartup/1073741824};l="StartMemory-GB"},@{e={$_.MemoryAssigned/1073741824};l="AssignMemory-GB"}, OperationalStatus, ProcessorCount, Name -AutoSize
$vhds = Get-VM | select-Object -expandproperty HardDrives
write-output "Virtual Machine Configurations:"
Get-VM | Format-Table -AutoSize VMName, State, OperationalStatus, MemoryAssigned, AutomaticStartAction, AutomaticStopAction, Generation, ProcessorCount, {$_.networkAdapters.count},  {$_.HardDrives.count} ; 
write-output "All Virtual Disks (file-backed):"
$vhds | Where-Object disknumber -NotMatch "[0-9]+" | get-vhd  | Format-Table VhdFormat, VhdType, FileSize, Size, MinimumSize, Attached, Path -AutoSize -Wrap
write-output "All Virtual Disks (MB Sizes, file-backed):"
$vhds | Where-Object disknumber -NotMatch "[0-9]+" | get-vhd  | Format-Table VhdFormat, VhdType, @{l="FileSZ";e={$_.FileSize/1GB};f="0"}, @{l="SZ";e={$_.Size/1GB};f="0"}, @{l="MinSZ";e={$_.MinimumSize/1GB};f="0"}, Path -AutoSize -Wrap ; 
write-output "Physical Disks tied to a virtual machine:"
$vhds | Where-Object disknumber -Match "[0-9]+" | Format-Table -autosize
write-output "Virtual disks mapped to virtual machines:"
$vhds | select-Object VMName, ControllerType, Path | Format-Table -AutoSize
}
