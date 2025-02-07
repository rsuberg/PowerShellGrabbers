$acc_token = ""
$content_arr = ""

Function Dell-Authorize {
    #Authorize
    $Uri1 = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
    $headers = @{
        "Accept" = "application/json"
        }
    $body=@{
        "grant_type" = "client_credentials"
        "client_id"     = "l72304bdd2017243f6b3e7e31f80f8385a"
        "client_secret" = "d0b057616f2c4528b85ffa62499d5627"
        "Content-Type" = "application/x-www-form-urlencoded"
        }
        <#
        $body=@{
            "grant_type" = "client_credentials"
            "client_id"     =  (Get-StoredCredential -Target dell-api).UserName
            "client_secret" = [System.Net.NetworkCredential]::new("",(Get-StoredCredential -Target dell-api).Password).Password
            "Content-Type" = "application/x-www-form-urlencoded"
        }

        #>
    $errvar = ""
    $response = Invoke-WebRequest -Method Post -Uri $Uri1 -Body $body -ErrorVariable errvar -ErrorAction SilentlyContinue
    if ($errvar.message.length -gt 1) { $errvar.message | ConvertFrom-Json | Format-List; break }
#   $response | Format-List
    $content_arr = $response.content | ConvertFrom-Json
    $content_arr | Add-Member -MemberType NoteProperty -Name Authorized -Value (Get-Date)
    $content_arr | Add-Member -MemberType NoteProperty -Name Status -Value $response.RawContent.Split("`r")[0]
    $content_arr | Add-Member -MemberType NoteProperty -Name Expires -Value $content_arr.Authorized.AddSeconds($content_arr.expires_in)
    $acc_token = $content_arr.access_token
    $content_arr | Select-Object Authorized, expires, expires_in, Status | Format-List
    $Global:acc_token =  $content_arr.access_token
    $Global:content_arr = $content_arr
}

# clear-host

function Dell-Entitlements { param ([string]$SerialNumber)
    #Entitlements
    #Read-Host "Serial Number"
    $Error.Clear()
    if($content_arr.Expires -lt (Get-Date)) {"Authorization expired."; return}
    try {
        Clear-Host
        while ($SerialNumber.Length -eq 0) { $SerialNumber = Read-Host "Serial Number"}
        $Uri2 = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements"
        $body=@{
            "servicetags" = $SerialNumber
        }
        $headers = @{
            "Authorization" = "Bearer $acc_token"
            "Accept" = "application/json"
            }
        $errros = ""
        $answer = Invoke-WebRequest -Method Get -Uri $Uri2 -Body $body -Headers $headers -ErrorVariable errros -ErrorAction Continue
        if($errros.status -ne 200) {$errros | ConvertFrom-Json | Format-List title, status, detail, instance}
        $info = $answer.Content | ConvertFrom-Json #CONSIDER FOREACH(infolp in info) {.....}
        if ($info.invalid) {
            $info | Format-List serviceTag, invalid
            return
            }
        $info | Select-Object id, serviceTag, orderBuid, shipDate, productCode, localChannel, productId, productLineDescription, productFamily, systemDescription, productLobDescription, countryCode, duplicated, invalid | Format-List
        Write-Host "Product Ship Date: " -NoNewline
        $info.shipDate.split("T")[0]
        Write-Host "Warranty Start Date: " -NoNewline
        ($info.entitlements | Sort-Object startDate  | Select-Object -First 1).startdate.split("T")[0]
        Write-Host "Warranty End Date: " -NoNewline
        ($info.entitlements | Sort-Object endDate -Descending | Select-Object -First 1).enddate.split("T")[0]

	Write-Host 
        Write-Host "Calculated Server End of Service Life: " -NoNewline
        $eosl = (Get-Date(($info.entitlements | Sort-Object endDate | Select-Object -First 1).startdate.split("T")[0])).AddYears(7)
        $eosl.ToString().Split(" ")[0]
        if($eosl -lt (get-date)){"SERVER EOL (7Yr): TRUE"} else {"SERVER EOL (7Yr): FALSE"}

	Write-Host 
        Write-Host "Calculated Workstation End of Service Life: " -NoNewline
        $eodl = (Get-Date(($info.entitlements | Sort-Object endDate | Select-Object -First 1).startdate.split("T")[0])).AddYears(5)
        $eodl.ToString().Split(" ")[0]
        if($eodl -lt (get-date)){"WORKSTATION EOL (5Yr): TRUE"} else {"WORKSTATION EOL (5Yr): FALSE"}

        $info.entitlements | Sort-Object startDate, entitlementType, serviceLevelCode | Format-Table -AutoSize -Wrap
        #$info.entitlements | Format-Table -AutoSize -Wrap
        }
    catch {
        write-host "`n$Error" -BackgroundColor Red -ForegroundColor White
        }
    }

function Dell-Shipped { param ([string]$SerialNumber)
    #Entitlements
    #Read-Host "Serial Number"
    if($content_arr.Expires -lt (Get-Date)){"Authorization expired."; return}
    Clear-Host
    while ($SerialNumber.Length -eq 0) { $SerialNumber = Read-Host "Serial Number"}
    # AS-SHIPPED hardware components
    # Asset Details:
    #   ### https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-components
    Clear-Host
    $body=@{
        "servicetag" = $SerialNumber
    }
    $headers = @{
        "Authorization" = "Bearer $acc_token"
        "Accept" = "application/json"
        }
    $errros = ""
    $answer = ""
    $Uri2 = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-components"
    $answer = Invoke-WebRequest -Method Get -Uri $Uri2 -Body $body -Headers $headers -ErrorVariable errros -ErrorAction Continue
    if($errros.status -ne 200) {$errros | ConvertFrom-Json | Format-List title, status, detail, instance}
    $info = $answer.Content | ConvertFrom-Json
        if ($info.invalid) {
        $info | Format-List serviceTag, invalid
        return
        }
    $info | Format-List id, serviceTag, orderBuid, shipDate, productCode, localChannel, productId, productLineDescription, productFamily, systemDescription, productLobDescription, countryCode, duplicated, invalid
    $info.components | Sort-Object itemDescription,partDescription | Format-Table -AutoSize -Wrap
}
    
Function Dell-Summary { param ([string]$SerialNumber)
    #Entitlements
    #Read-Host "Serial Number"
    if($content_arr.Expires -lt (Get-Date)){"Authorization expired."; return}
    Clear-Host
    while ($SerialNumber.Length -eq 0) { $SerialNumber = Read-Host "Serial Number"}
    # Asset Summary:
    #  ### https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlement-components
    Clear-Host
    $body=@{
        "servicetag" = $SerialNumber
    }    
    $headers = @{
        "Authorization" = "Bearer $acc_token"
        "Accept" = "application/json"
        }
    $errros = ""
    $answer = ""
    $Uri2 = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlement-components"
    $answer = Invoke-WebRequest -Method Get -Uri $Uri2 -Body $body -Headers $headers -ErrorVariable errros -ErrorAction Continue
    if($errros.status -ne 200) {$errros | ConvertFrom-Json | Format-List title, status, detail, instance}
    $info = $answer.Content | ConvertFrom-Json
        if ($info.invalid) {
        $info | Format-List serviceTag, invalid
        return
        }
############ Entitlements
    $info | Format-List id, serviceTag, orderBuid, shipDate, productCode, localChannel, productId, productLineDescription, productFamily, systemDescription, productLobDescription, countryCode, duplicated, invalid
        Write-Host "Product Ship Date: " -NoNewline
        $info.shipDate.split("T")[0]
        Write-Host "Warranty Start Date: " -NoNewline
        ($info.entitlements | Sort-Object startDate  | Select-Object -First 1).startdate.split("T")[0]
        Write-Host "Warranty End Date: " -NoNewline
        ($info.entitlements | Sort-Object endDate -Descending | Select-Object -First 1).enddate.split("T")[0]

	Write-Host 
        Write-Host "Calculated Server End of Service Life: " -NoNewline
        $eosl = (Get-Date(($info.entitlements | Sort-Object endDate | Select-Object -First 1).startdate.split("T")[0])).AddYears(7)
        $eosl.ToString().Split(" ")[0]
        if($eosl -lt (get-date)){"SERVER EOL (7Yr): TRUE"} else {"SERVER EOL (7Yr): FALSE"}

	Write-Host 
        Write-Host "Calculated Workstation End of Service Life: " -NoNewline
        $eodl = (Get-Date(($info.entitlements | Sort-Object endDate | Select-Object -First 1).startdate.split("T")[0])).AddYears(5)
        $eodl.ToString().Split(" ")[0]
        if($eodl -lt (get-date)){"WORKSTATION EOL (5Yr): TRUE"} else {"WORKSTATION EOL (5Yr): FALSE"}


    $info.entitlements | Format-Table -AutoSize -Wrap
    $info.components |Sort-Object itemDescription, partDescription | Format-Table -AutoSize -Wrap
}
    #################################################################
    ##### MULTIPLE RESPONSE PROCESSING #####
    #################################################################
    #Clear-Host
 #   $info = $answer.Content | ConvertFrom-Json
 #   Write-Host "Configurations queried: "$info.Count
 #   $info | foreach {
 #       $_ | Select-Object serviceTag, invalid, productLineDescription, systemDescription, shipDate | Format-List
 #       if(($_.invalid)) {
 #           Write-Host "Invalid Serial Number: " $_.servicetag
 #           } 
 #       else {
 #           Write-Host "Product Ship Date: " -NoNewline
 #           $_.shipDate.split("T")[0]
 #           Write-Host "Warranty Start Date: " -NoNewline
 #           ($_.entitlements | Sort-Object startDate  | Select-Object -First 1).startdate.split("T")[0]
 #           Write-Host "Warranty End Date: " -NoNewline
 #           ($_.entitlements | Sort-Object endDate -Descending | Select-Object -First 1).enddate.split("T")[0]
 #           Write-Host "Calculated Server End of Service Life: " -NoNewline
 #           $eosl = (Get-Date(($_.entitlements | Sort-Object endDate -Descending | Select-Object -First 1).enddate.split("T")[0])).AddYears(7)
 #           $eosl.ToString()
 #           $_.entitlements | Sort-Object startDate, entitlementType, serviceLevelCode | Format-Table
 #           #$_.entitlements | Format-Table
 #       }
#    }

function Dell-StoreCredential {
    $cred = get-credential -Message "Dell API Credential"
    New-StoredCredential -Target Dell-API -UserName $cred.UserName -Password $cred.Password
}
Write-Host "Loaded Dell Functions:`n"
Get-Item function: | findstr "Dell-" | sort.exe
Write-Host "`n"
