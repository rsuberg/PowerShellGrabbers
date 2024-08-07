# PowerShellGrabbers
Powershell Information Grabbers

Most functions can be loaded directly into PowerShell once you have the raw file link with the command:

 $uri = Read-Host "GitHub RAW uri"; iex ( iwr -Uri $uri).content  

 
