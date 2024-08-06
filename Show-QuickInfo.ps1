function Show-QuickInfo {
$comp = "."; $t = @{}
write-host "Processor`r"
$proc = Get-WmiObject win32_processor | select Manufacturer,  Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors, ThreadCount
if($proc.count -eq $null) {$c = 1} else {$c = $proc.count}
$proc | Add-Member -MemberType NoteProperty -Name Count -Value $c
$t.Add("Processor",$proc)
write-host "Memory   `r"
$memtot = 0; $a=Get-WmiObject win32_physicalmemory  
foreach ($b in $a) {
	$memtot=$memtot+($b.capacity/1048576)
	}
$memtot=$memtot / 1024
$t.add("Memory Total GB",$memtot)
write-host "OS Info  `r"
$t.add("OperatingSystem",(Get-WmiObject win32_operatingsystem | select Caption, Version, PortableOperatingSystem, ProductType))
write-host "Computer `r"
$t.add("ComputerSystem",(Get-WmiObject win32_computersystem | select Caption, BootupState, DNSHostName, Domain, Manufacturer, Model, PartOfDomain, SystemFamily, SystemSKUNumber, UserName))
write-host "         "
$t | convertto-json
return $t
}