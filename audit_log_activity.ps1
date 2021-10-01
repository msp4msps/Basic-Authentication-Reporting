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
    [string]$refreshToken

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
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)


$path = echo ([Environment]::GetFolderPath("Desktop")+"\BasicAuth")
New-Item -ItemType Directory -Force -Path $path
$BasicAuthReport = echo ([Environment]::GetFolderPath("Desktop")+"\BasicAuth\BasicAuthCustomerList.csv")
 
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID
 
Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken
 
$customers = Get-MsolPartnerContract -All
 
Write-Host "Found $($customers.Count) customers for $((Get-MsolCompanyInformation).displayname)." -ForegroundColor DarkGreen
 
foreach ($customer in $customers) {
    #Dispaly customer name#
    Write-Host "Checking for Basic Auth in Audit Logs for $($Customer.Name)" -ForegroundColor Green
    ##Generate Access Tokens
    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
    ##Set 30 day period for audit log records
    $currentTime = Get-Date -Format "yyyy-MM-ddTHH:MM:ss"
    $ts = (Get-Date).AddDays(-30)
    $endTime = $ts.ToString("yyyy-MM-ddTHH:MM:ss")
    ##Create Filter for basic auth sign-ins
    $filters= "createdDateTime ge $($endTime)Z and createdDateTime lt $($currentTime)Z and (clientAppUsed eq 'AutoDiscover' or clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'Exchange Online PowerShell' or clientAppUsed eq 'Exchange Web Services' or clientAppUsed eq 'IMAP4' or clientAppUsed eq 'MAPI Over HTTP' or clientAppUsed eq 'Offline Address Book' or clientAppUsed eq 'Outlook Anywhere (RPC over HTTP)' or clientAppUsed eq 'Other clients' or clientAppUsed eq 'POP3' or clientAppUsed eq 'Reporting Web Services' or clientAppUsed eq 'Authenticated SMTP' or clientAppUsed eq 'Outlook Service')"
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?api-version=beta&filter=$($filters)"
    try{
    ##Try to make call to test if tenant has P1 licensing
    $signIns = (Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object userDisplayName, clientAppUsed
    }catch{"This client does not have a Azure AD P1 subscription or the app registration does not have the necessary permissions"
    write-host $_}
    #Remove duplicate records
    $getUnique = $signIns | Sort-Object -Unique -Property clientAppUsed
    if($getUnique){
    forEach($object in $getUnique){
     Write-Host "Basic Auth discovered: $($object.clientAppUsed)" -ForegroundColor Yellow
     $user = $object.userDisplayName
     $basicAuth = $object.clientAppUsed
     $properties = @{'Company Name' = $customer.Name
		            'Basic Auth Used' = $basicAuth
	                'UserDisplayName' = $user      
	        }
        
    
        $PropsObject = New-Object -TypeName PSObject -Property $Properties
        $PropsObject | Select-Object  "Company Name", "Basic Auth Used", "UserDisplayName" | Export-CSV -Path $BasicAuthReport -NoTypeInformation -Append     
    }
}
       
}