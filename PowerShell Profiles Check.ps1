# PowerShell Profiles Check
&{
Write-Host $PROFILE.AllUsersAllHosts " - " -NoNewline; Test-Path $PROFILE.AllUsersAllHosts
Write-Host $PROFILE.AllUsersCurrentHost " - " -NoNewline; Test-Path $PROFILE.AllUsersCurrentHost
Write-Host $PROFILE.AllUsersAllHosts " - " -NoNewline; Test-Path $PROFILE.AllUsersAllHosts
Write-Host $PROFILE.CurrentUserAllHosts " - " -NoNewline; Test-Path $PROFILE.CurrentUserAllHosts
Write-Host $PROFILE.CurrentUserCurrentHost " - " -NoNewline; Test-Path $PROFILE.CurrentUserCurrentHost
}