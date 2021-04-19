<#
.DESCRIPTION

See the readme.md file for comprehensive details on how this is strung together

You"ll need the ExchangeOnlineManagement, SharePoint, MSonline and AzureADPreview modules for this script to run, if they are not isntalled they will be automatically installed for you.

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

    #$ErrorActionPreference = "SilentlyContinue"

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
    		Import-Module -Name $Module -AllowClobber
    	}
    	else {
    		Write-Host($Module + " is already installed.") -ForegroundColor Green
    	}
    }

    $CurrentTime = Get-Date -UFormat %T
    $CurrentTime = $CurrentTime.ToString()
    $FolderPath = "C:\Innit\"
    $OrganizationName = Read-Host("Organization name (The bit before .onmicrosoft)")
    $SPOurl = "https://" + $OrganizationName + "-admin.sharepoint.com"
    $LogPath = $FolderPath + $OrganizationName + "_" + $CurrentTime + ".txt"

    if (!($FolderPath)) {
        New-Item -Path "C:\" -Name "Innit" -ItemType Directory
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
            Connect-MsolService -Credential $Creds
            Connect-SPOService -Url $SPOurl -Credential $Creds
            Connect-AzureAD -Credential $Creds
        }
    } until ($response -eq 1 -or $response -eq 0)


    $Users = Get-Mailbox -RecipientTypeDetails UserMailbox

    $LicensedUsers = (Get-MsolUser | where {$_.IsLicensed -eq $true}).Count
    Write-Host("Your organization currently has " + $LicensedUsers + " Licensed users") -ForegroundColor Cyan
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

    Disconnect-AzureAD
    Disconnect-ExchangeOnline

    Stop-Transcript
}