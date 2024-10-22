#Complete User, Contact, Group list for MS365 tenant already connected
#Outpout to Excel

#open excell
$excel = New-Object -ComObject excel.application
$excel.visible = $True

#add a default workbook
$workbook = $excel.Workbooks.Add()
$workbook.Worksheets.Item(1).name = "Contacts"
$excel.Worksheets.Add() | Out-Null
$excel.Worksheets.Item(1).name = "GroupMembers"
$excel.Worksheets.Add() | Out-Null
$excel.Worksheets.Item(1).name = "Groups"
$excel.Worksheets.Add() | Out-Null
$excel.Worksheets.Item(1).name = "Users"
$excel.Worksheets | select index, name

$lst= $excel.Worksheets | select name,index
$workbook=$excel.Worksheets.Item(($lst | where name -EQ "Users").index)
$workbook.Activate()

#Save File as it stands
$outputpath = join-path -Path "C:\Shared" -ChildPath "\excelltest.xlsx"
Write-Host "Saving -$outputpath-"
$workbook.SaveAs($outputpath)

#give the remaining worksheet a name
$uregwksht= $workbook.Worksheets.Item(1)
$uregwksht.Name = 'Users'
$workbook.save()

$a=Get-MsolUser
$i=2
$excel.Cells.Item(1,1)="UserPrincipalName"
foreach ($u in $a) {$excel.Cells.Item($i,1)=$u.userprincipalname;$i++}
$usedRange = $uregwksht.UsedRange	
$usedRange.EntireColumn.AutoFit() | Out-Null