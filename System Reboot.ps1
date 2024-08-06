#System Reboot
&{
clear-host
gwmi win32_operatingsystem | Format-List LastBootUpTime
#Get-WinEvent -FilterHashtable @{logname = 'System'; id = 1074, 6005, 6006, 6008, 6009, 41, 1076, 6013, 12} -MaxEvents 20  | Format-Table -wrap

Get-WinEvent -FilterHashtable @{logname = 'System'; id = 1074, 6005, 6006, 6008, 6009, 41, 1076, 6013, 12} -MaxEvents 50   |
                    ForEach-Object {
                        $EventData = New-Object PSObject | Select-Object Date, EventID, User, Action, Reason, ReasonCode, Comment, Computer, Message, Process, Provider
                        $EventData.Date = $_.TimeCreated
                        $EventData.User = $_.Properties[6].Value
                        $EventData.Process = $_.Properties[0].Value
                        $EventData.Action = $_.Properties[4].Value
                        $EventData.Reason = $_.Properties[2].Value
                        $EventData.ReasonCode = $_.Properties[3].Value
                        $EventData.Comment = $_.Properties[5].Value
                        $EventData.Computer = $Computer
                        $EventData.EventID = $_.id
                        $EventData.Message = $_.Message
                        $EventData.Provider = $_.ProviderName
                    
                        $EventData | Select-Object Date, EventID, Action, User, Reason, Provider, Message

                    } | Sort-Object Date | Format-Table -AutoSize -Wrap
}
