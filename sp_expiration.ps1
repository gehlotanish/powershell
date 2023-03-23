param(
    $daysLogon = 19
  
    [Parameter (Mandatory = $true,
        HelpMessage = "Enter the number of days to warn of credential expiry")]
    [string] $ExpiresInDays
)


Import-Module AzureAD


function email_error() {
    param(
        $err1
    )
    # Default email variables
    $EmailFrom = ""
    $EmailTo = @("")
    $EmailSubject = ""
    $SMTPserver = ""
    $script_time = Get-Date
    $emailBody = "<html><body><br>
    <font color='FF0000'>Run at $script_time</font><br /><br />
    <p>$err1</p>"
 
    # Default sendmail parameters
    $sendMailParameters = @{
        From       = $EmailFrom
        To         = $EmailTo
        Subject    = $EmailSubject
        Body       = $emailBody
        SMTPServer = $SMTPserver
        BodyAsHTML = $True
    }
    # Send the email
    Send-MailMessage @sendMailParameters
}

# try { 
#     $var = Get-AzureADTenantDetail 
#    } 
#    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] { 
#     Connect-AzureAD
#    }
$days = 0

$ServicePrincipals = Get-AzureADServicePrincipal -All $true | Where-Object { ($_.ServicePrincipalType -ne "ManagedIdentity") }
$message = ""
Write-Host "Checking for certificates that expire within $days days"
$count = 0
$expiredcount = 0
$expiredcountp = 0
foreach ($App in $ServicePrincipals) {
    #$AppID = ""
    #Write-Host "----" ($App.DisplayName) "---------------------------------------------------------------------"
    #Write-Host $App.PasswordCredentials
    #Write-Host $App.KeyCredentials
    $countp += 1
    foreach ($PassCredential in $App.PasswordCredentials) {
        if ( ($PassCredential.EndDate -lt (Get-Date).AddDays($days)) ) {
            Write-Host "(Password)    App - " $App.DisplayName " Object Id " ($App.ObjectId) " Password Expiration Date: " $PassCredential.EndDate -Foreground red            
            $expiredcountp += 1
            $message += "(Password)&emsp;&nbsp;" + $App.DisplayName + "&emsp;Object Id&emsp;" + $App.ObjectId + "&emsp;Password Expiration Date:" + $PassCredential.EndDate + "<br>"
        }
    }
    if (($App.KeyCredentials).Count -gt 0) { 
        #Write-Host "----" ($App.DisplayName) "---------------------------------------------------------------------"   
        $exp_certs = @()
        $nexp_certs = @()
        #Write-Host "KeyCredentials:" $App.KeyCredentials
        foreach ($KeyCredential in $App.KeyCredentials) {
            #Write-hOST "KeyCredential:" $KeyCredential
            if ( ($KeyCredential.EndDate -lt (Get-Date).AddDays($days)) ) { 
                #if (($App.ObjectId) -ne $AppID) {
                if (($KeyCredential.Usage -eq 'Verify')) {
                    # Expired/expiring crtificate
                    #Write-Host "App - " ($App.ObjectId) " Certificate Name: " ($App.DisplayName) " - Expiration Date: " $KeyCredential.EndDate -Foreground red
                    #$AppID = ($App.ObjectId)
                    $exp_certs += ($App.DisplayName) + "&emsp;Expiration Date:&emsp;" + ($KeyCredential.EndDate)
                    #Write-Host "Expired " ($KeyCredential)
                }
            }
            else {
                # Valid certificate
                #Write-Host "App - " ($App.ObjectId) " Certificate Name: " ($App.DisplayName) " - Expiration Date: " $KeyCredential.EndDate -Foreground green
                $nexp_certs += ($App.DisplayName) + " Expiration Date:" + ($KeyCredential.EndDate)
                #Write-Host "NotExpired " ($nexp_certs.count)
            }
            $count = $count + 1
        }
        if (($exp_certs.Count -gt 0) -and ($nexp_certs.Count -lt 1)) {
            #Write-Host "Expireeeeeed " ($exp_certs.count)
            $expiredcount = $expiredcount + 1
            foreach ($cert in $exp_certs) {
                Write-Host "(Certificate) App - " $App.DisplayName " Object Id " ($App.ObjectId) " Certificate Name: " ($cert)  -Foreground red
                $message += "(Certificate)&emsp;" + $App.DisplayName + "&emsp;Object Id&emsp;" + ($App.ObjectId) + " Certificate Name: " + $cert + "<br>"
            }
        }
    }
}
Write-Host "There are $expiredcount Keys (of $count checked) due to expire or expired."
Write-Host "There are $expiredcountp passwords (of $countp checked) due to expire or expired." 

$message += "<br>There are $expiredcount Keys (of $count checked) due to expire or expired.<br>"
$message += "There are $expiredcountp passwords (of $countp checked) due to expire or expired.<br>"

$Query = 'AADServicePrincipalSignInLogs
| where TimeGenerated > ago(365d)
| where ResultType == "0"
| summarize arg_max(TimeGenerated, *) by AppId
| project TimeGenerated, ServicePrincipalName,ServicePrincipalId, ["Days Since Last Logon"]=datetime_diff("day", now(),TimeGenerated)
| where ["Days Since Last Logon"] >= 1 | sort by ["Days Since Last Logon"] desc'

$WorkspaceId = '946198b7-1da7-4c87-8fff-65d53e37361e'

$ResultList = Invoke-AzOperationalInsightsQuery -WorkspaceID $WorkspaceId -Query $Query -ErrorAction Stop | select -ExpandProperty Results | select ServicePrincipalName, ServicePrincipalId, 'Days Since Last Logon' | Where-Object { $_ }

#$ResultList[0].ServicePrincipalName
$message += "<br><br>Service Principals with " + $daysLogon + " Days since Last logon<br>"
foreach ($sp in $ResultList) {
    if ([int]$sp.'Days Since Last Logon' -gt $daysLogon) {
        Write-Host $sp.ServicePrincipalName $sp.'Days Since Last Logon'
        $message += "Days:" + $sp.'Days Since Last Logon' + "&emsp;Service Principal&emsp;" + $sp.ServicePrincipalName + "&emsp;ID&emsp;" + $sp.ServicePrincipalId + "<br>"
    }
}

# Expiration

Write-Host 'Gathering necessary information...'
$applications = Get-AzADApplication
$servicePrincipals = Get-AzADServicePrincipal

$appWithCredentials = @()
$appWithCredentials += $applications | Sort-Object -Property DisplayName | % {
    $application = $_
    $sp = $servicePrincipals | ? ApplicationId -eq $application.ApplicationId
    Write-Verbose ('Fetching information for application {0}' -f $application.DisplayName)
    $application | Get-AzADAppCredential -ErrorAction SilentlyContinue | Select-Object -Property @{Name = 'DisplayName'; Expression = { $application.DisplayName } }, @{Name = 'ObjectId'; Expression = { $application.Id } }, @{Name = 'ApplicationId'; Expression = { $application.ApplicationId } }, @{Name = 'KeyId'; Expression = { $_.KeyId } }, @{Name = 'Type'; Expression = { $_.Type } }, @{Name = 'StartDate'; Expression = { $_.StartDate -as [datetime] } }, @{Name = 'EndDate'; Expression = { $_.EndDate -as [datetime] } }
}

Write-Host 'Validating expiration data...'
$today = (Get-Date).ToUniversalTime()
$limitDate = $today.AddDays($ExpiresInDays)
$appWithCredentials | Sort-Object EndDate | % {
    if ($_.EndDate -lt $today) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Expired'
    }
    elseif ($_.EndDate -le $limitDate) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'ExpiringSoon'
    }
    else {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Valid'
    }
}

$ExpiringAppCredentials = $appWithCredentials | ? { $_.Status -eq 'Expired' -or $_.Status -eq 'ExpiringSoon' } | Sort-Object -Property DisplayName
$ExpiringAppCredentialsString = $ExpiringAppCredentials | Out-String


email_error -err1 "$message"
