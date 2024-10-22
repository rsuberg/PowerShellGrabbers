#Test Credential Options

function Test-LocalCredential {[CmdletBinding()] 
    Param
    (
		[switch]$SecurePrompt, 
        [string]$UserName,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$Password
    )
	if($SecurePrompt) {
		$gc = Get-Credential
		$Username = $gc.GetNetworkCredential().UserName
		$Password = $gc.GetNetworkCredential().password
		if( $gc.GetNetworkCredential().domain.length -ne 0) {$ComputerName =  $gc.GetNetworkCredential().domain}
	}
    if (!($UserName) -or !($Password)) {
        Write-Warning 'Test-LocalCredential: Please specify both user name and password'
    } else {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
        $DS.ValidateCredentials($UserName, $Password)
    }
}

Function Test-ADUserCredentials {
    Import-Module Activedirectory
	#ClearUserInfo
    $Cred = $Null
    $DomainNetBIOS = $Null
    $UserName  = $Null
    $Password = $Null

    #Get user credentials
    $Cred = Get-Credential -Message "Enter Your Credentials (Domain\Username)"
    if ($Cred -eq $Null)
                        {
                            Write-Host "Please enter your username in the form of Domain\UserName and try again" -BackgroundColor Black -ForegroundColor Yellow
                            Rerun
                            Break
                        }

    #Parse provided user credentials
    $DomainNetBIOS = $Cred.username.Split("{\}")[0]
    $UserName = $Cred.username.Split("{\}")[1]
    $Password = $Cred.GetNetworkCredential().password

    Write-Host "`n"
    Write-Host "Checking Credentials for $DomainNetBIOS\$UserName" -BackgroundColor Black -ForegroundColor White
    Write-Host "***************************************"

    If ($DomainNetBIOS -eq $Null -or $UserName -eq $Null)
                        {
                            Write-Host "Please enter your username in the form of Domain\UserName and try again" -BackgroundColor Black -ForegroundColor Yellow
                            Rerun
                            Break
                        }
    #    Checks if the domain in question is reachable, and get the domain FQDN.
    Try
    {
        $DomainFQDN = (Get-ADDomain $DomainNetBIOS).DNSRoot
    }
    Catch
    {
        Write-Host "Error: Domain was not found: " $_.Exception.Message -BackgroundColor Black -ForegroundColor Red
        Write-Host "Please make sure the domain NetBios name is correct, and is reachable from this computer" -BackgroundColor Black -ForegroundColor Red
        Rerun
        Break
    }

    #Checks user credentials against the domain
    $DomainObj = "LDAP://" + $DomainFQDN
    $DomainBind = New-Object System.DirectoryServices.DirectoryEntry($DomainObj,$UserName,$Password)
    $DomainName = $DomainBind.distinguishedName

    If ($DomainName -eq $Null)
        {
            Write-Host "Domain $DomainFQDN was found: True" -BackgroundColor Black -ForegroundColor Green

            $UserExist = Get-ADUser -Server $DomainFQDN -Properties LockedOut -Filter {sAMAccountName -eq $UserName}
            If ($UserExist -eq $Null)
                        {
                            Write-Host "Error: Username $Username does not exist in $DomainFQDN Domain." -BackgroundColor Black -ForegroundColor Red
                            Break
                        }
            Else
                        {
                            Write-Host "User exists in the domain: True" -BackgroundColor Black -ForegroundColor Green


                            If ($UserExist.Enabled -eq "True")
                                    {
                                        Write-Host "User Enabled: "$UserExist.Enabled -BackgroundColor Black -ForegroundColor Green
                                    }

                            Else
                                    {
                                        Write-Host "User Enabled: "$UserExist.Enabled -BackgroundColor Black -ForegroundColor RED
                                        Write-Host "Enable the user account in Active Directory, Then check again" -BackgroundColor Black -ForegroundColor RED
                                        Break
                                    }

                            If ($UserExist.LockedOut -eq "True")
                                    {
                                        Write-Host "User Locked: " $UserExist.LockedOut -BackgroundColor Black -ForegroundColor Red
                                        Write-Host "Unlock the User Account in Active Directory, Then check again..." -BackgroundColor Black -ForegroundColor RED
                                        Break
                                    }
                            Else
                                    {
                                        Write-Host "User Locked: " $UserExist.LockedOut -BackgroundColor Black -ForegroundColor Green
                                    }
                        }
            Write-Host "Authentication failed for $DomainNetBIOS\$UserName with the provided password." -BackgroundColor Black -ForegroundColor Red
            Write-Host "Please confirm the password, and try again..." -BackgroundColor Black -ForegroundColor Red
            Break
        }
    Else
        {
        Write-Host "SUCCESS: The account $Username successfully authenticated against the domain: $DomainFQDN" -BackgroundColor Black -ForegroundColor Green
        Break
        }
    #Clear User Info
	$Cred = $Null
    $DomainNetBIOS = $Null
    $UserName  = $Null
    $Password = $Null
}

function Create-LocalUser {[CmdletBinding()] 
    Param
    (
		[switch]$SecurePrompt, 
        [string]$UserName,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$Password
    )
	if($SecurePrompt) {
		$gc = Get-Credential
		$Username = $gc.GetNetworkCredential().UserName
		$Password = $gc.GetNetworkCredential().password
		if( $gc.GetNetworkCredential().domain.length -ne 0) {$ComputerName =  $gc.GetNetworkCredential().domain}
	}
    if (!($UserName) -or !($Password)) {
        Write-Warning 'Create-LocalUser: Please specify both user name and password'
    } else {
		New-LocalUser -Name $UserName -Password $Password
		}
}
