# PowerShellGrabbers
Powershell Information Grabbers

Most functions can be loaded directly into PowerShell once you have the raw file link with the command:

 $uri = Read-Host "GitHub RAW uri"; iex ( iwr -Uri $uri).content  

 
$uri = 'https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/main/All-CustomServerFunctions-1.ps1'; iex ( iwr -Uri $uri -UseBasicParsing).content
$uri = 'https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/main/All-Summary-Functions.ps1'; iex ( iwr -Uri $uri -UseBasicParsing).content
$uri = 'https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/main/Show-MemorySummary.ps1'; iex ( iwr -Uri $uri -UseBasicParsing).content
$uri = 'https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/main/WMI-Details.ps1'; $z = iex ( iwr -Uri $uri -UseBasicParsing).content

$Global
$uri = 'https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/refs/heads/main/Get-LicenseArray.ps1'; iex ( iwr -Uri $uri -UseBasicParsing).content
@('_Dell-Warranty-API.ps1','_Pax8-Functions.ps1') | % {$d = "https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/main/" + $_;iex ( iwr -Uri $d -UseBasicParsing).content;"#"}

$host.PrivateData.ErrorBackgroundColor = 'Red'
$host.PrivateData.ErrorForegroundColor = 'White'
$ErrorActionPreference = 'Continue'

$t = $host.UI.RawUI.WindowTitle
@("All-CustomServerFunctions-1.ps1","All-Summary-Functions.ps1","Show-MemorySummary.ps1","WMI-Details.ps1") | 
   % {
      $host.UI.RawUI.WindowTitle = $_
      $d = "https://raw.githubusercontent.com/rsuberg/PowerShellGrabbers/main/" + $_;
	  $x = iex ( iwr -Uri $d -UseBasicParsing).content;
   }
$host.UI.RawUI.WindowTitle = $t
cls; Show-AvailableCustomfunctions

