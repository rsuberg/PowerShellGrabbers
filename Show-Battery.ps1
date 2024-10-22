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
Show-Battery
