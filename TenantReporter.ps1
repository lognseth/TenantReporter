<#
.DESCRIPTION

See the readme.md file for comprehensive details on how this is strung together

You'll need the ExchangeOnlineManagement, SharePoint, MSonline and AzureADPreview modules for this script to run, if they are not isntalled they will be automatically installed for you.

.NOTES 
    Name:           TenantReporter
    Version:        1.0
    Author:         Mikael Lognseth @ Innit Cloud Solutions AS
    Creation Date:  15.04.2021
    Purpose/Change: Initial development
#>


$ErrorActionPreference = "SilentlyContinue"

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
                        @{Name = 'isAdmin'; Expression = {if ($SkipAdminCheck) {Write-Output "-"} else {if ($AdminUsers -match $_.UserPrincipalName) {Write-Output $true} else {Write-Output $false}}}}, `
                        @{Name = 'MFAEnabled'; Expression={if ($_.StrongAuthenticationMethods) {Write-Output $true} else {Write-Output $false}}}
                              
                } catch {
                    $Object = [pscustomobject]@{
                        DisplayName       = '_NotSynced'
                        UserPrincipalName = $User
                        isAdmin           = '-'
                        MFAEnabled        = '-' 
                    }
                    Write-Output $Object
                }
            }
        } else {
            $AllUsers = Get-MsolUser -MaxResults $MaxResults | Where-Object {$_.IsLicensed -eq $isLicensed} | select DisplayName, UserPrincipalName, `
                @{Name = 'isAdmin'; Expression = {if ($SkipAdminCheck) {Write-Output "-"} else {if ($AdminUsers -match $_.UserPrincipalName) {Write-Output $true} else {Write-Output $false}}}}, `
                @{Name = 'MFAEnabled'; Expression={if ($_.StrongAuthenticationMethods) {Write-Output $true} else {Write-Output $false}}}
 
            Write-Output $AllUsers | Sort-Object isAdmin, MFAEnabled -Descending
        }
    }
    END {}
}

#Setter PSGallery til "trusted repo"
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

#Liste over relevante moduler

$Modules = @(
    "ExchangeOnlineManagement"
    "MSonline"
    "AzureADPreview"
    "Microsoft.Online.SharePoint.PowerShell"
    "Microsoft.Exchange.Management.ExoPowershellModule"
)

# Check whether or not the modules are installed already - if no, install them.
foreach ($Module in $Modules) {
    if (!(Get-InstalledModule -Name $Module)) {
        Write-Host("$Module is not installed") -ForegroundColor Yellow
        Write-Host("Installing $Module") -ForegroundColor Green
		Install-Module -Name $Module -Confirm:$false -Force
		Import-Module -Name $Module
	}
	else {
		Write-Host("$Module is already installed.") -ForegroundColor Green
	}
}


$FolderPath = "C:\Innit\"
$OrganizationName = Read-Host("Organization name (The bit before .onmicrosoft): ")
$SPOurl = "https://" + $OrganizationName + "-admin.sharepoint.com"
$LogPath = Join-Path $FolderPath + "$OrganizationName.txt"

Start-Transcript -Path $LogPath -Force

Connect-ExchangeOnline
Connect-AzureAD
Connect-MsolService
Connect-SPOService -Url $SPOurl




Stop-Transcript