<#
.DESCRIPTION

See the readme.md file for comprehensive details on how this is strung together

You'll need the ExchangeOnlineManagement, SharePoint, MSonline and AzureAD modules for this script to run, if they are not isntalled they will be automatically installed for you.

.NOTES
    Name:           TenantReporter
    Version:        1.0
    Author:         Mikael Lognseth @ Innit Cloud Solutions AS
    Creation Date:  15.04.2021
    Purpose/Change: Initial development
#>

Write-Host "Checking for elevated permissions..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
    Break
    }
else {
    Write-Host "Script is running as administrator - executing code..." -ForegroundColor DarkGreen

    $ErrorActionPreference = "SilentlyContinue"
    $VerbosePreference = "SilentlyContinue"
    
    Function Get-AzureMFAStatus {

    [CmdletBinding()]
    param(
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
            )]

        [string[]]   $UserPrincipalName,
        [int]        $MaxResults = 4000,
        [bool]       $isLicensed = $true,
        [switch]     $SkipAdminCheck
    )

    BEGIN {
        if ($SkipAdminCheck.IsPresent) {
            $AdminUsers = Get-MsolRole -ErrorAction Stop | foreach {Get-MsolRoleMember -RoleObjectId $_.ObjectID} | Where-Object {$_.EmailAddress -ne $null} | Select EmailAddress -Unique | Sort-Object EmailAddress
        }
    }

    PROCESS {
        if ($UserPrincipalName) {
            foreach ($User in $UserPrincipalName) {
                try {
                    Get-MsolUser -UserPrincipalName $User -ErrorAction Stop | select DisplayName, UserPrincipalName, `
                        @{Name = "isAdmin"; Expression = {if ($SkipAdminCheck) {Write-Output "-"} else {if ($AdminUsers -match $_.UserPrincipalName) {Write-Output $true} else {Write-Output $false}}}}, `
                        @{Name = "MFAEnabled"; Expression={if ($_.StrongAuthenticationMethods) {Write-Output $true} else {Write-Output $false}}}

                } catch {
                    $Object = [pscustomobject]@{
                        DisplayName       = "_NotSynced"
                        UserPrincipalName = $User
                        isAdmin           = "-"
                        MFAEnabled        = "-"
                    }
                    Write-Output $Object
                }
            }
        } else {
            $AllUsers = Get-MsolUser -MaxResults $MaxResults | Where-Object {$_.IsLicensed -eq $isLicensed} | select DisplayName, UserPrincipalName, `
                @{Name = "isAdmin"; Expression = {if ($SkipAdminCheck) {Write-Output "-"} else {if ($AdminUsers -match $_.UserPrincipalName) {Write-Output $true} else {Write-Output $false}}}}, `
                @{Name = "MFAEnabled"; Expression={if ($_.StrongAuthenticationMethods) {Write-Output $true} else {Write-Output $false}}}

            Write-Output $AllUsers | Sort-Object isAdmin, MFAEnabled -Descending
        }
    }
    END {}
    }

    #Sets PSGallery to "trusted repo"
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    #All modules you will need for this script

    $Modules = @(
        "ExchangeOnlineManagement"
        "MSonline"
        "AzureAD"
        "Microsoft.Online.SharePoint.PowerShell"
    )

    #Check whether or not the modules are installed already - if no, install them.
    foreach ($Module in $Modules) {
        if (!(Get-InstalledModule -Name $Module)) {
            Write-Host($Module + " is not installed") -ForegroundColor Yellow
            Write-Host("Installing " + $Module) -ForegroundColor Green
    		Install-Module -Name $Module -Confirm:$false -Force -AllowClobber
    		Import-Module -Name $Module
    	}
    	else {
    		Write-Host($Module + " is already installed.") -ForegroundColor Green
    	}
    }

    $CurrentTime = Get-Date -UFormat %R
    $CurrentTime = $CurrentTime.ToString()
    $FolderPath = "C:\TenantReporter\"
    $LogPath = $FolderPath + "log_" + $CurrentTime + ".txt"

    if (!($FolderPath)) {
        New-Item -Path "C:\" -Name "TenantReporter" -ItemType Directory
    }

    Start-Transcript -Path $LogPath -Force

    #Authentication Flow.

    $title = ""
    $msg     = "Does your account require MFA to sign in?"
    $options = "&Yes", "&No"
    $default = 1  # 0=Yes, 1=No

    do {
        $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
        if ($response -eq 0) {
            #Prompt for sign in using MFA
            Write-Host("Since you are using MFA; you will be prompted to sign in to each service individually") -f Magenta
            $OrganizationName = Read-Host("Organization name (The bit before .onmicrosoft.com)")
            $SPOurl = "https://" + $OrganizationName + "-admin.sharepoint.com"
            Connect-AzureAD
            Connect-MsolService
            Connect-SPOService -Url $SPOurl
            Connect-ExchangeOnline
        }
        if ($response -eq 1) {
            #Prompt for sign in using basic / traditional auth.
            Write-Host "Please enter valid Admin credentials" -f Magenta
            $Creds = Get-Credential
            Connect-ExchangeOnline -Credential $Creds
            $DomainPrefix = Get-AcceptedDomain | Where-Object {$_.DomainName -match ".onmicrosoft.com"} | select -Last 1
            $DomainPrefix = $DomainPrefix.DomainName
            $OrganizationName = $DomainPrefix -replace ".{16}$"
            start-sleep -s 5
            $SPOurl = "https://" + $OrganizationName + "-admin.sharepoint.com"
            Connect-MsolService -Credential $Creds
            Connect-SPOService -Url $SPOurl -Credential $Creds  
            Connect-AzureAD -Credential $Creds
        }
    } until ($response -eq 1 -or $response -eq 0)


    $Users = Get-Mailbox -RecipientTypeDetails UserMailbox

    $LicensedUsers = (Get-MsolUser | where {$_.IsLicensed -eq $true}).Count
    Write-Host("Your organization currently has " + $LicensedUsers + " Licensed users") -ForegroundColor Blue
    $AuthPolicyUsers = 0
    Write-Host("Getting authentication policies for all users") -ForegroundColor Cyan
    foreach ($user in $users) {
        $AuthenticationPolicy = Get-AuthenticationPolicy -Identity $user.emailaddress
        if ($AuthenticationPolicy -ne $true) {
            $AuthPolicyUsers++
        }
    }

    Write-Host("$AuthPolicyUsers users do not have an authentication policy") -ForegroundColor DarkYellow

    Write-Host("Getting OAuthStatus")
    $OAuthStatus = Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled

    if ($OAuthStatus -match $false) {
        Write-Host("Modern authentication is not enabled for organization") -ForegroundColor Red
    }
    if ($OAuthStatus -match $true) {
        Write-Host("Modern authentication is enabled for organization") -ForegroundColor Green
    }

    #Gets the date 60 days ago based on current time
    $Users = Get-mailbox -RecipientTypeDetails UserMailbox
    $60DaysBack = (Get-Date).AddDays(-60)
    $UserLastSignInCount = 0

    #Iterates through all users checking if they signed in after the given date, this can be prone to error as 365 does not give us a good way of fetching this data, but it gives us an    indication.

    $LastLogon = Get-Mailbox -RecipientTypeDetails UserMailbox -Resultsize Unlimited | Get-MailboxStatistics | Select-Object DisplayName,LastLogonTime

    foreach ($User in $LastLogon) {
        if ($LastLogon.LastLogonTime -ge $60DaysBack) {
            $UserLastSignInCount++
        }
    }

    Write-Host("Getting MFA Status of all users")

    $MFAUsers = 0

    foreach ($User in $Users) {
        $UserMFAStatus = Get-AzureMFAStatus -UserPrincipalName $User.UserPrincipalName
        if ($UserMFAStatus.MFAEnabled -eq $false) {
            $MFAUsers++
        }
    }

    if ($MFAUsers -ne 0) {
        Write-Host("$MFAUsers user(s) have not enabled MFA") -ForegroundColor Red
    } else {
        Write-Host("All users have enabled MFA") -ForegroundColor Green
    }

    #Get all SharePoint sites and see if they are shared externally.

    $Sites = Get-SPOSite

    foreach ($Site in $Sites) {
        $SiteSharing = $Site.SharingCapability.ToString()
        $SiteTitle = $Site.Title
        $SiteUrl = $Site.Url
        if ($SiteSharing -eq "ExternalUserAndGuestSharing") {
            Write-Host($SiteTitle + " is shared externally!`nSite URL: " + $SiteUrl)
        }
    }

    $SPTotalSize = 0
    $ODTotalSize = 0

    $OneDriveHash = @{}
    $SharePointHash = @{}

    $sposites = get-sposite -IncludePersonalSite $false -limit all | Sort-Object StorageUsageCurrent -Descending          ## get all non-ODFB sites
    foreach ($sposite in $sposites) {                           ## loop through all of these sites
    $mbsize = $sposite.StorageUsageCurrent                    ## save total size to a variable to be formatted later
        $SharePointHash.Add($sposite.Url, $mbsize.tostring('N0'))
        #write-host -foregroundcolor $highlightmessagecolor $sposite.title,"=",$mbsize.tostring('N0'),"MB"
        $SPTotalSize += $mbsize
    }

    $sposites = get-sposite -IncludePersonalSite $true -Limit all -Filter "Url -like '-my.sharepoint.com/personal/" | Sort-Object StorageUsageCurrent -Descending
    foreach ($sposite in $sposites) {
        $mbsize = $sposite.StorageUsageCurrent
        $OneDriveHash.Add($sposite.Owner, $mbsize.tostring('N0'))
        #Write-Host -foregroundcolor $highlightmessagecolor $sposite.title,"=",$mbsize.tostring('N0'),"MB"
        $ODTotalSize += $mbsize
    }
    $OneDriveHash
    $SharePointHash
    $MbxSize = ((get-exomailbox -ResultSize Unlimited | get-exomailboxstatistics).TotalItemSize.Value.ToMB() | measure-object -sum).sum

    $UserMbx = (Get-mailbox -RecipientTypeDetails UserMailbox).Count
    $SharedMbx = (Get-Mailbox -RecipientTypeDetails SharedMailbox).Count
    $DistLists = (Get-DistributionGroup).Count

    $ODTotalSize = $ODTotalSize / 1024
    $SPTotalSize = $SPTotalSize / 1024
    $MbxSize = $MbxSize / 1024

    Write-Host("There are $SharedMbx shared mailboxes in your org and $DistLists distribution groups") -f Green
    Write-Host("There are $UserMbx user mailboxes in your org with a total of $MbxSize GB worth of data") -f Green
    Write-Host("Total OneDrive usage: $ODTotalSize GB") -f Green
    Write-Host("Total SharePoint usage: $SPTotalSize GB") -f Green

    $TotalDataSize = $SPTotalSize + $ODTotalSize + $MbxSize

    Write-Host("Total storage used: $TotalDataSize GB `n") -f Blue

    $ReportsPath = "C:\TenantReporter\reports\"

    if (!($ReportsPath)) {
        New-Item -Path "C:\TenantReporter" -Name "reports" -ItemType Directory
    }


    $CurrentTime = Get-Date -UFormat %R
    $CurrentTime = $CurrentTime.ToString()
    $Prefix = "C:\TenantReporter\reports\" + $OrganizationName

    $MailboxReports = $Prefix + "_mailboxes.csv" 
    $GuestReports = $Prefix + "_guests.csv" 
    $SharePointReports = $Prefix + "_sharepoint.csv" 
    $OneDriveReports = $Prefix + "_onedrive.csv" 
    $GroupReports = $Prefix + "_groups.csv" 

    $title = ""
    $msg     = "Do you wish to create and export usage reports to a csv file?"
    $options = "&Yes", "&No"
    $default = 0  # 0=Yes, 1=No

    do {
        $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
        if ($response -eq 0) {
            #Prompt for sign in using MFA
            Write-Host("Generating reports... `nYou will find the reports in C:\TenantReporter\reports\") -f Magenta
            
            Get-Mailbox -Resultsize Unlimited -RecipientTypeDetails UserMailbox | Select-Object DisplayName,PrimarySmtpAddress,UserPrincipalName | Export-Csv -Path $MailboxReports -Encoding UTF8 -NoTypeInformation
            Get-Mailbox -Resultsize Unlimited -RecipientTypeDetails SharedMailbox | Select-Object DisplayName,PrimarySmtpAddress,UserPrincipalName | Export-Csv -Path $MailboxReports -Encoding UTF8 -NoTypeInformation -Append
            Get-DistributionGroup | Select-Object DisplayName,PrimarySmtpAddress,GroupType,RecipientTypeDetails | Export-Csv -Path $GroupReports -Encoding UTF8 -NoTypeInformation
            Get-UnifiedGroup | Select-Object DisplayName,PrimarySmtpAddress,GroupType,RecipientTypeDetails | Export-Csv -Path $GroupReports -Encoding UTF8 -NoTypeInformation -Append
            Get-AzureADUser -All $true | Where-Object {$_.UserType -eq 'Guest'} | Export-Csv -Path $GuestReports -Encoding UTF8 -NoTypeInformation

            $SPreport = @()
            $SharePointHash.GetEnumerator() | ForEach-Object {
        	    $row = "" | Select "Site URL","Storage Used in MB"
        	    $row."Site URL" = $_.Key
        	    $row."Storage Used in MB" = $_.Value
        	    $SPreport += $row
            }
            $SPreport | Export-Csv -Path $SharePointReports -NoTypeInformation -Encoding UTF8
            
            $ODreport = @()
            $OneDriveHash.GetEnumerator() | ForEach-Object {
        	    $row = "" | Select "Owner","Storage Used in MB"
        	    $row."Owner" = $_.Key
        	    $row."Storage Used in MB" = $_.Value
        	    $ODreport += $row
            }
            $ODreport | Export-Csv -Path $OneDriveReports -NoTypeInformation -Encoding UTF8
        }
        
        if ($response -eq 1) {
            Write-Host("No report will be generated, exiting script.")
        }
    } until ($response -eq 1 -or $response -eq 0)

    Disconnect-AzureAD -Confirm:$false
    Disconnect-ExchangeOnline -Confirm:$false
    Disconnect-SPOService

    Stop-Transcript
}