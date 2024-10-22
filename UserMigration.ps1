#function Show-LocalUserDetails { param([string]$UserName)
$username = "scans"
$Details = @{}
$a= net user $UserName
$a.count
write-host "User: "  ($a[0][29..50] -join(""))
if ($a.count -ne 0) {
  $Details | Add-Member -MemberType NoteProperty -Name Name -Value ($a[0][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name FullName -Value ($a[1][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name Comment -Value ($a[2][29..50] -join("")) #Description
  $Details | Add-Member -MemberType NoteProperty -Name UsersComment -Value ($a[3][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name Active -Value ($a[5][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name Expires -Value ($a[6][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value ($a[8][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name PasswordExpires -Value ($a[9][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name PasswordChangeable -Value ($a[10][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name PasswordRequired -Value ($a[11][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name PasswordUserChangeable -Value ($a[12][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name LastLogin -Value ($a[18][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name LocalGroupMembers -Value ($a[22][29..50] -join(""))
  $Details | Add-Member -MemberType NoteProperty -Name GlobalGroupMembers -Value ($a[23][29..50] -join(""))
  $Details.UserName
  $Details  | Get-Member
  return $details
}
#}

# "D:\OnlineStorage\OneDrive-Business\OneDrive - Barcom Technology Solutions\Documents\Customers\DMC Mechanical\New Users.csv"
#Function QueryAllLocalUsers { param([string]$FileName)
$FileName = "C:\_BARCOM\users.csv"
    $users = ""
    if (!(get-item -Path $FileName -ErrorAction SilentlyContinue).count) {
        $users =  Get-WmiObject  -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select *
        $users | Export-Csv -NoTypeInformation $FileName
        }
        #select 
    $users = import-csv $FileName
#}
#Name, FullName, Caption, Description, Disabled, PasswordChangeable, PasswordRequired, 