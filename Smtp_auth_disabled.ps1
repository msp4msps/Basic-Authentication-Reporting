Param
(

[cmdletbinding()]
    [Parameter(Mandatory= $true, HelpMessage="Enter your ApplicationId from the Secure Application Model https://github.com/KelvinTegelaar/SecureAppModel/blob/master/Create-SecureAppModel.ps1")]
    [string]$ApplicationId,
    [Parameter(Mandatory= $true, HelpMessage="Enter your ApplicationSecret from the Secure Application Model")]
    [string]$ApplicationSecret,
    [Parameter(Mandatory= $true, HelpMessage="Enter your Partner Tenantid")]
    [string]$tenantID,
    [Parameter(Mandatory= $true, HelpMessage="Enter your refreshToken from the Secure Application Model")]
    [string]$refreshToken,
    [Parameter(Mandatory= $true, HelpMessage="Enter your Exchange refreshToken from the Secure Application Model")]
    [string]$ExchangeRefreshToken,
    [Parameter(Mandatory= $true, HelpMessage="Enter the UPN of a global admin in partner center")]
    [string]$upn

)

# Check if the MSOnline PowerShell module has already been loaded.
if ( ! ( Get-Module MSOnline) ) {
    # Check if the MSOnline PowerShell module is installed.
    if ( Get-Module -ListAvailable -Name MSOnline ) {
        Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
        Import-Module MsOnline
    } else {
        Install-Module MsOnline
    }
}

###API Permissions Needed For App Registration#####
##Microsoft Graph => Auditlog.Read.All (Delegated)##


###MICROSOFT SECRETS#####

$ApplicationId = $ApplicationId
$ApplicationSecret = $ApplicationSecret
$tenantID = $tenantID
$refreshToken = $refreshToken
$ExchangeRefreshToken = $ExchangeRefreshToken
$upn = $upn
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)
 
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID

Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken
 
$customers = Get-MsolPartnerContract -All
 
Write-Host "Found $($customers.Count) customers for $((Get-MsolCompanyInformation).displayname)." -ForegroundColor DarkGreen

#Define CSV Path 
$path = echo ([Environment]::GetFolderPath("Desktop")+"\SMTPAuthSettings")
New-Item -ItemType Directory -Force -Path $path
$SMTPAuthReport = echo ([Environment]::GetFolderPath("Desktop")+"\SMTPAuthSettings\SMTPAuthCustomerList.csv")
 
foreach ($customer in $customers) {
    #Dispaly customer name#
    Write-Host "Checking Authentication settings for $($Customer.Name)" -ForegroundColor Green
    #Establish Token for Exchange Online
    try{
    $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $customer.TenantId -ErrorAction Ignore
    }catch{write-host "This customer does not have exchange"}
    if($token){
    $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)
    $InitialDomain = Get-MsolDomain -TenantId $customer.TenantId | Where-Object {$_.IsInitial -eq $true}
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($InitialDomain)&BasicAuthToOAuthConversion=true" -Credential $credential -Authentication Basic -AllowRedirection -ErrorAction Ignore
    try{
    Import-PSSession $session -DisableNameChecking -ErrorAction Ignore
    } catch{}
    if($session){
    #Check Authsettings
    $Settings = ""
    $Settings = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
    Write-host "STMP Auth Disabled: $($Settings.SmtpClientAuthenticationDisabled)"
    if($Settings){

    $properties = @{'Company Name' = $customer.Name
	                'SMTP Disabled' = $Settings.SmtpClientAuthenticationDisabled
	        }
     
    $PropsObject = New-Object -TypeName PSObject -Property $Properties
    $PropsObject | Select-Object  "Company Name", "SMTP Disabled" | Export-CSV -Path $SMTPAuthReport -NoTypeInformation -Append
    Remove-PSSession $session
    Write-Host "Removed PS Session"
    }
   }
}
}