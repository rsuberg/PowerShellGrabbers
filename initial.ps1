write-host "Sample File"
$host.PrivateData.ErrorBackgroundColor = 'Red'
$host.PrivateData.ErrorForegroundColor = 'White'
$ErrorActionPreference = 'Continue'
$Global

Function Show-InstalledPrograms { Param([switch]$AllFields, [switch]$Table, [switch]$Quiet)
	$List = @()
	"Est is KB"
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
