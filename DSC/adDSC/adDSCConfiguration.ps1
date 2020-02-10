configuration DomainController
{
    param
    (
        [Parameter(Mandatory)]
        [String]$adDomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [Object]$usersArray,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$UserCreds,

        [Int]$RetryCount = 20,
        [Int]$RetryIntervalSec = 30
    )
   
    $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
    $shortDomain = $adDomainName.Split('.')[0]
    $ComputerName = $wmiDomain.PSComputerName
    
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${shortDomain}\$($Admincreds.UserName)", $Admincreds.Password)
    
    $ClearDefUserPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserCreds.Password))

    Import-DscResource -ModuleName xActiveDirectory, xNetworking, xComputerManagement, PSDesiredStateConfiguration, xPendingReboot
    
    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)

    Node 'localhost'
    {
        LocalConfigurationManager {
            DebugMode          = 'All'
            RebootNodeIfNeeded = $true
        }

        WindowsFeature DNS { 
            Ensure = "Present" 
            Name   = "DNS"		
        }

        Script EnableDNSDiags {
            SetScript  = { 
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics" 
            }
            GetScript  = { @{ } }
            TestScript = { $false }
            DependsOn  = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools {
            Ensure    = "Present"
            Name      = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }

        xDnsServerAddress DnsServerAddress 
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn      = "[WindowsFeature]DNS"
        }

        WindowsFeature ADDSInstall { 
            Ensure    = "Present" 
            Name      = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS" 
        } 

        WindowsFeature ADDSTools {
            Ensure    = "Present"
            Name      = "RSAT-ADDS-Tools"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WindowsFeature ADAdminCenter {
            Ensure    = "Present"
            Name      = "RSAT-AD-AdminCenter"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        Script InstallAADConnect {
            SetScript  = {
                $AADConnectDLUrl = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
                $exe = "$env:SystemRoot\system32\msiexec.exe"

                $tempfile = [System.IO.Path]::GetTempFileName()
                $folder = [System.IO.Path]::GetDirectoryName($tempfile)

                $webclient = New-Object System.Net.WebClient
                $webclient.DownloadFile($AADConnectDLUrl, $tempfile)

                Rename-Item -Path $tempfile -NewName "AzureADConnect.msi"
                $MSIPath = $folder + "\AzureADConnect.msi"

                Invoke-Expression "& `"$exe`" /i $MSIPath /qn /passive /forcerestart"
            }

            GetScript  = { @{ } }
            TestScript = { 
                return Test-Path "$env:TEMP\AzureADConnect.msi" 
            }
        }
         
        xADDomain FirstDS 
        {
            DomainName                    = $adDomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = "C:\NTDS"
            LogPath                       = "C:\NTDS"
            SysvolPath                    = "C:\SYSVOL"
            DependsOn                     = "[WindowsFeature]ADDSInstall"
        } 

        Script CreateOU {
            SetScript  = {
                $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
                $segments = $wmiDomain.DnsForestName.Split('.')
                $path = [string]::Join(", ", ($segments | ForEach-Object { "DC={0}" -f $_ }))
                New-ADOrganizationalUnit -Name "OrgUsers" -Path $path
            }
            GetScript  = { @{ } }
            TestScript = { 
                $test = Get-ADOrganizationalUnit -Server "$using:ComputerName.$using:adDomainName" -Filter 'Name -like "OrgUsers"' -ErrorAction SilentlyContinue
                return ($test -ine $null)
            }
        }

        Script AddTestUsers {
            SetScript  = {
                $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
                $mailDomain = $wmiDomain.DnsForestName
                $server = "$($wmiDomain.PSComputerName).$($wmiDomain.DnsForestName)"
                $segments = $wmiDomain.DnsForestName.Split('.')
                $OU = "OU=OrgUsers, {0}" -f [string]::Join(", ", ($segments | ForEach-Object { "DC={0}" -f $_ }))
                
                $clearPw = $using:ClearDefUserPw
                $Users = $using:usersArray

                foreach ($User in $Users) {
                    $Displayname = $User.'FName' + " " + $User.'LName'
                    $UserFirstname = $User.'FName'
                    $UserLastname = $User.'LName'
                    $SAM = $User.'SAM'
                    $UPN = $User.'FName' + "." + $User.'LName' + "@" + $Maildomain
                    $Password = $clearPw
                    "$DisplayName, $Password, $SAM"
                    New-ADUser `
                        -Name "$Displayname" `
                        -DisplayName "$Displayname" `
                        -SamAccountName $SAM `
                        -UserPrincipalName $UPN `
                        -GivenName "$UserFirstname" `
                        -Surname "$UserLastname" `
                        -Description "$Description" `
                        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
                        -Enabled $true `
                        -Path "$OU" `
                        -ChangePasswordAtLogon $false `
                        -PasswordNeverExpires $true `
                        -server $server `
                        -EmailAddress $UPN
                }
            }
            GetScript  = { @{ } }
            TestScript = { 
                $Users = $using:usersArray
                $samname = $Users[0].'SAM'
                $user = get-aduser -filter { SamAccountName -eq $samname } -ErrorAction SilentlyContinue
                return ($user -ine $null)
            }
            DependsOn  = '[Script]CreateOU'
        }

        Script Shortcuts {
            SetScript  = {   
                $WshShell = New-Object -comObject WScript.Shell
                $dt = "C:\Users\Public\Desktop\"

                $links = @(
                    @{site = "%windir%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"; name = "PowerShell ISE"; icon = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell_ise.exe, 0" },
                    @{site = "%SystemRoot%\system32\dsa.msc"; name = "AD Users and Computers"; icon = "%SystemRoot%\system32\dsadmin.dll, 0" },
                    @{site = "%SystemRoot%\system32\domain.msc"; name = "AD Domains and Trusts"; icon = "%SystemRoot%\system32\domadmin.dll, 0" },
                    @{site = "%SystemRoot%\system32\dnsmgmt.msc"; name = "DNS"; icon = "%SystemRoot%\system32\dnsmgr.dll, 0" },
                    @{site = "%windir%\system32\services.msc"; name = "Services"; icon = "%windir%\system32\filemgmt.dll, 0" }
                )

                foreach ($link in $links) {
                    $Shortcut = $WshShell.CreateShortcut("$($dt)$($link.name).lnk")
                    $Shortcut.TargetPath = $link.site
                    $Shortcut.IconLocation = $link.icon
                    $Shortcut.Save()
                }
            }
            GetScript  = { @{ } }
            TestScript = { 
                return $false
            }
        }
        
        Script AddTools {
            SetScript  = {
                # Install AAD Tools
                mkdir c:\temp -ErrorAction Ignore
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

                Install-Module -Name MSOnline -Force

                Install-Module -Name AzureAD -Force
            }

            GetScript  = { @{ } }
            TestScript = { 
                $key = Get-Module -Name AzureAD -ListAvailable
                return ($key -ine $null)
            }
        }
    }
}