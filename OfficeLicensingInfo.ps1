&"C:\Program Files (x86)\Microsoft Office\Office16\vNextDiag.ps1"
&"C:\Program Files\Microsoft Office\Office16\vNextDiag.ps1"

PrintLicensesInformationPerMode
PrintLicensesInformationPerMode | ConvertFrom-Json | ft


PrintLicensesInformation -mode nul | ConvertFrom-Json | ft Type, Product, Email, LicenseState, EntitlementStatus, NotBefore, NotAfter, NextRenewal, LicenseId, TenantId

cls; cscript "C:\Program Files (x86)\Microsoft Office\Office16ospp.vbs" /dstatus
cls; cscript "C:\Program Files\Microsoft Office\Office16\OSPP.VBS" /dstatus

cls ; cscript "C:\Program Files (x86)\Microsoft Office\Office16\ospp.vbs" /dstatus; PrintLicensesInformation -mode nul | ConvertFrom-Json | ft Type, Product, Email, LicenseState, EntitlementStatus, NotBefore, NotAfter, NextRenewal