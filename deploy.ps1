function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [String[]]
        $type,

        [Parameter(Mandatory = $true)]
        [string]$message,

        [Parameter(Mandatory = $false)]
        [string]$logfile
    )

    if (!$logfile) { $logfile = "$env:TEMP\deployad.log" }

    Switch ($type) {
        'Information' {
            Write-Output "[$([DateTime]::Now)] [INFORMATION]: $message"
            "[$([DateTime]::Now)] [INFORMATION]: $message" | Out-File -FilePath $logfile -Append
        }
        'Warning' {
            Write-Output -ForegroundColor Yellow "[$([DateTime]::Now)] [WARNING]: $message"
            "[$([DateTime]::Now)] [INFORMATION]: $message" | Out-File -FilePath $logfile -Append
        }
        'Error' {
            Write-Output -ForegroundColor Red "[$([DateTime]::Now)] [ERROR]: $message"
            "[$([DateTime]::Now)] [INFORMATION]: $message" | Out-File -FilePath $logfile -Append
        }
    }
}

function Set-DeploymentBlobContent {
    param(
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Specifies the name of the resource group to be used."
        )]
        [string] $ResourceGroupName,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Specifies the name of the Storage account to be created/used."
        )]
        [string] $StorageAccountName,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Specifies the location where the resources should be created if they are not existent before"
        )]
        [string]$salocation = "eastus",
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Specifies the source folder which will represent the blob containers in the storage account"
        )]
        [array]$foldercontent = @("DSC", "Scripts", "Templates")
    )

    try {
        $currentPath = $PSScriptRoot
        Write-log -type information -message "Script Directory: '$PSScriptRoot'"
        Write-log -type information -message "For each of these folder there will be a blob container: $foldercontent"
        $foldertoupload = @()
        foreach ($folder in $foldercontent) {
            $testpath = Join-Path -Path $currentPath -ChildPath "$folder"
            Write-log -type information -message "Testing path: '$testpath'"
            If (-Not (Test-Path -Path $testpath)) {
                Write-Log -type Error -message "Testing local paths FAILED: Cannot find path to folder to upload '$testpath'. No blob container will be created."
            }
            else {
                $foldertoupload += $testpath
                Write-log -type information -message "Testing path: $testpath SUCCEDED"
            }
        }

        Write-log -type information -message "Following blob container will be created: $foldercontent"
       
        #Checks if resource group is existent. If not, terminate the script.
        try {
            $null = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
            Write-log -type information -message "Resource group $ResourceGroupName exists, updating deployment"
        }
        catch {
            Write-log -type error -message "$ResourceGroupName is not existent."
            break
        }
        #Checks if storage account is existent. If not, storage account will be created
        try {
            $null = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
            Write-log -type information -message "Storage account $StorageAccountName exists, updating deployment"
        }
        catch {
            $null = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Location $salocation -SkuName Standard_LRS
            Write-log -type information -message "Created new storage account $StorageAccountName."
        }
        #Get storage accoutn context
        Write-log -type information -message "Getting storage account context."
        $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
        $ctx = $storageAccount.Context

        # Check if blob container is already existent. If not, create them. And upload all files from local disk to the blob container.
        foreach ($folder in $foldertoupload) {
            $short = $folder.Substring($folder.LastIndexOf("\") + 1)

            try {
                $null = Get-AzStorageContainer -Name $short.ToLower() -Context $ctx -ErrorAction Stop
                Write-log -type information -message "Container $short exists."
            }
            catch {
                $null = New-AzStorageContainer -Name $short.ToLower() -Context $ctx -Permission blob
                Write-log -type information -message "Created blob container: $short."
            }

            Write-log -type information -message "Uploading content of $short to the corresponding container"
            try {
                $FilesToUpload = Get-ChildItem -Path $folder -ErrorAction Stop
                $null = $FilesToUpload | Set-AzStorageBlobContent -Container $short.ToLower() -Context $ctx -Force -ErrorAction Stop
                Write-log -type information -message "Successfully uploaded:"; $FilesToUpload.Name
            }
            catch {
                Write-log -type error -message "Could not upload content to $short."
            }
        }
    }
    catch {
        Write-Error "Upload FAILED: $_"
    }
}

function logon {
    if (($ctx = Get-AzContext -ErrorAction Stop) -eq $null) {
        Write-Log -type Information "You are not logged in to Azure yet. Please login with your credentials"
        try {
            $null = Connect-AzAccount
            $ctx = Get-AzContext
            Write-Log -type Information ("Successfully logged on to Azure with: " + $ctx.name)
        }
        catch {
            Write-Log -type error -message "Connection to Azure failed because: $_"
        }
    }
    else {
        write-log -type information -message ("Your are already connected to Azure tenant: " + $ctx.name)
        "Would you like to move on with this account? (Y) Would you like to logon to another account? (A) Or rather exit here and rethink? (E) - (Default is Exit)"
        $Readhost = Read-Host " ( Y / A / E ) " 
        Switch ($ReadHost) { 
            Y { Write-log -type information -message "Moving on..." } 
            A {
                Write-log -type information -message "Alright. Disconnecting..."
                try { 
                    $null = Disconnect-AzAccount 
                }
                catch {
                    Write-Log -type error -message "Disconnection from Azure failed because: $_"
                    exit 
                }
                Write-log -type information -message "Please logon to Azure with your credentials:"
                try { 
                    $null = Connect-AzAccount
                    $ctx = Get-AzContext
                    Write-Log -type Information -message ("Connection successful to tenant: " + $ctx.name)
                }
                catch { Write-Log -type error -message "Connection to Azure failed because: $_" } 
            } 
            E { 
                Write-log -type information -message "Alright. Exiting..."
                exit
            } 
            Default { Write-Host "D"; $PublishSettings = $false } 
        } 
    }
}

function deploydc {
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Your resource group"
        )]
        [string] $RGName,

        [Parameter(
            Mandatory = $false,
            HelpMessage = "Your storage account for the deployment files"
        )]
        [string] $storageAccount = $RGName.ToLower() + "sa",

        [Parameter(
            Mandatory = $true,
            HelpMessage = "Your azure region"
        )]
        [string] $DeployRegion,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "AD Administrator Login"
        )]
        [string] $userName,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "AD Administrator Password"
        )]
        [string] $secpasswd,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "@nd part AD domain name. E.g. Contoso.com"
        )]
        [string] $adDomainName
    )

    $startTime = Get-Date
    Write-Host "Beginning deployment at $starttime"
 
    #DEPLOYMENT OPTIONS
    $vmSize = "Standard_A2_v2"
    # Must be unique for simultaneous/co-existing deployments
    # "master" or "dev"
    $usersArray = @(
        @{ "FName" = "Bob"; "LName" = "Jones"; "SAM" = "bjones" },
        @{ "FName" = "Bill"; "LName" = "Smith"; "SAM" = "bsmith" },
        @{ "FName" = "Mary"; "LName" = "Phillips"; "SAM" = "mphillips" },
        @{ "FName" = "Sue"; "LName" = "Jackson"; "SAM" = "sjackson" }
    )
    $defaultUserPassword = "P@ssw0rd"

    # custom resolution for generated RDP connections
    $RDPWidth = 1920
    $RDPHeight = 1080
    #END DEPLOYMENT OPTIONS

    #ensure we're logged in
    logon
<#
    #Verify/create resource group
    try {
        $null = Get-AzResourceGroup -Name $RGName -ErrorAction Stop
        Write-log -type information -message "Resource group $RGName exists. Using it for this deployment."
    }
    catch {
        $null = New-AzResourceGroup -Name $RGName -Location $DeployRegion -Tag @{ Shutdown = "true"; Startup = "false" }
        Write-log -type information -message "Created new resource group $RGName."
    }

    #Verify/create storage account and upload required linked template files
    Set-DeploymentBlobContent -ResourceGroupName $RGName -StorageAccountName $StorageAccount -Salocation $DeployRegion -Verbose
#>
    #deploy
    $AssetLocation = "https://$storageaccount.blob.core.windows.net/"

    $parms = @{
        "adminPassword"              = $secpasswd;
        "adminUsername"              = $userName;
        "adDomainName"               = $adDomainName;
        "vmSize"                     = $vmSize
        "assetLocation"              = $assetLocation;
        "virtualNetworkAddressRange" = "10.0.0.0/16";
        #The first IP deployed in the AD subnet, for the DC
        "adIP"                       = "10.0.1.4";
        "adSubnetAddressRange"       = "10.0.1.0/24";
        #if multiple deployments will need to route between vNets, be sure to make this distinct between them
        "usersArray"                 = $usersArray;
        "defaultUserPassword"        = "P@ssw0rd";
    } 

    $version ++
    #$TemplateFile = $assetLocation + "deploy.json"
    $TemplateFile = "$PSScriptRoot\deploy.json"

    Write-log -type information -message "Trigger deployment"
    $deployment = New-AzResourceGroupDeployment -ResourceGroupName $RGName -TemplateParameterObject $parms -TemplateFile $TemplateFile -Name "adLabDeploy$version" -Force -Verbose

    if ($deployment) {
        $url = "$($assetLocation)scripts\Addons.ps1"
        $tempfile = "$env:TEMP\Addons.ps1"
        $webclient = New-Object System.Net.WebClient
        $webclient.DownloadFile($url, $tempfile)
        . $tempfile

        $RDPFolder = "$env:USERPROFILE\desktop\$RGName\"
        if (!(Test-Path -Path $RDPFolder)) {
            mkdir $RDPFolder
        }
        $ADName = $ADDomainName.Split('.')[0]
        $vms = Get-AzResource -ResourceGroupName $RGName | Where-Object { ($_.ResourceType -like "Microsoft.Compute/virtualMachines") }
        if ($vms) {
            foreach ($vm in $vms) {
                $ip = Get-IPForVM -ResourceGroupName $RGName -VMName $vm.Name
                New-RDPConnectoid -ServerName $ip -LoginName "$($ADName)\$($userName)" -RDPName $vm.Name -OutputDirectory $RDPFolder -Width $RDPWidth -Height $RDPHeight
            }
        }

        $userList = "Local test user list:`r`n`r`n"
        $userList += ConvertTo-Json $usersArray
        $userList += "`r`n`r`nTest user password:`r`n$defaultUserPassword"

        Out-File -FilePath "$($RDPFolder)TestUsers.txt" -InputObject $userList
        Start-Process $RDPFolder
    }

    $endTime = Get-Date

    Write-log -type information -message "Total Deployment time:"
    New-TimeSpan -Start $startTime -End $endTime | Select-Object Hours, Minutes, Seconds
}

#deploydc -RGName "stress" -DeployRegion "eastus" -userName "localadmin" -secpasswd 'Pa$$w0rdPa$$w0rd' -adDomainName "contoso.local"