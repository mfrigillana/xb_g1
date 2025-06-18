##################################
# WebRTC Phone Provisioning with Queue Assignment
# 
# This script is intended to run from within an Azure Automation Runbook.  It queries Genesys CLoud 
# for Users, determines if each has a WebRTC phone assigned, and either assigns or creates one as needed.
# There are Azure Active Directory integrations to cover mapping from AAD Office Location to Genesys Cloud Site, since 
# the Genesys SCIM integration doesn't support syncing Office Location.
##################################

$sep = "**********************************"

##################################
# Update values in this section as appropriate for the environment
##################################
$cloudenv = 'usw2.pure.cloud' # 'usw2.pure.cloud' or 'mypurecloud.com', etc.
$credenv = 'qa' #Set to 'qa' or 'prod' depending on which environment we're connecting to
$azureaccountid = 'xxxxxxxxx' #GUID of the Managed Identity impersonation account
$defaultsite = 'NORTHAMERICA'
#Mappings from Azure AD User location to Genesys Cloud Site for the WebRTC phone.
$locationmap = $(
    @{name = "Amsterdam"; cloudlocation = "EUROPE"; },
    @{name = "Budapest"; cloudlocation = "EUROPE"; },
    @{name = "Field (Australia)"; cloudlocation = "AUSTRALIA"; },
    @{name = "Field (Germany)"; cloudlocation = "EUROPE"; },        
    @{name = "Field (Hungary)"; cloudlocation = "EUROPE"; },        
    @{name = "Field (Ireland)"; cloudlocation = "EUROPE"; },        
    @{name = "Field (Netherlands)"; cloudlocation = "EUROPE"; },        
    @{name = "Field (UK)"; cloudlocation = "EUROPE"; },        
    @{name = "Dublin"; cloudlocation = "EUROPE"; },        
    @{name = "Sao Paulo"; cloudlocation = "SOUTHAMERICA"; },        
    @{name = "Singapore"; cloudlocation = "AUSTRALIA"; },        
    @{name = "Sydney, Australia"; cloudlocation = "AUSTRALIA"; },        
    @{name = "Theaterstr. 6, Dresden"; cloudlocation = "EUROPE"; }        
)

#Azure AD connection, comment out before -Identity to run locally
try {
    Write-Output "Connecting to Azure AD"
    Connect-AzAccount -Identity -Account $azureaccountid | Out-Null
}
catch {
    Write-Output "Failed to connect to Azure AD, aborting provisioning run"
    Write-Output $_
    Write-Error "Failed to connect to Azure AD, aborting provisioning run"
    Write-Error $_
    Exit 1
}

##################################
# No edits below here
##################################

#Get clientid and clientsecret from Azure Keyvault.  We store both QA and Prod values in the same vault
#ex. clientid-prod and clientsecret-prod
try {
    Write-Output "Getting clientid and clientsecret from Azure Keyvault"
    $clientid = Get-AzKeyVaultSecret -VaultName "genesyscloud-prov" -Name "clientid-$($credenv)" -AsPlainText
    $clientsecret = Get-AzKeyVaultSecret -VaultName "genesyscloud-prov" -Name "clientsecret-$($credenv)" -AsPlainText
    Write-Output "Client ID: ($($clientid))"
}
catch {
    Write-Output "Failed to get Azure Keyvautl entries for Genesys credentials.  Aborting."
    Write-Output $_
    Write-Error "Failed to get Azure Keyvautl entries for Genesys credentials.  Aborting."
    Write-Error $_
    Exit 1
}

$pair = "$($clientid):$($clientsecret)"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)

#Get Genesys Cloud OAuth token
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Basic $base64")
$headers.Add("Content-Type", "application/x-www-form-urlencoded")
$body = "grant_type=client_credentials"

Write-Output "Logging in to Genesys Cloud API"
try {
    $response = Invoke-RestMethod "https://login.$cloudenv/oauth/token" -Method 'POST' -Headers $headers -Body $body
}
catch {
    Write-Output "Failed to log in to Genesys Cloud API.  Aborting."
    Write-Output $_
    Write-Error "Failed to log in to Genesys Cloud API.  Aborting."
    Write-Error $_	
    Exit 1
}

#set bearer based on returned access token
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer $($response.access_token)")

#get user list
Write-Output $sep
Write-Output "Getting User List with Stations"
$users = Invoke-RestMethod "https://api.$cloudenv/api/v2/users?pageSize=250&expand=station" -Method 'GET' -Headers $headers

#add users to separate collection, in case we have more pages to fetch
$userlist = [System.Collections.ArrayList]::new()
foreach ($u in $users.entities) {
    $userlist.add($u) | Out-Null
}

#see if we have additional pages of users, if so, get them all
if ($false -eq [string]::IsNullOrEmpty($users.nextUri)) {
    Write-Output "User list has multiple pages ($($users.pageCount))"       
    $selfUri = $users.selfUri
    $nextUri = $users.nextUri
    $lastUri = $users.lastUri
    while ($selfUri -ne $lastUri) {
        Write-Output "Getting next page of users ($($users.pageNumber + 1))"
        $users = Invoke-RestMethod "https://api.$($cloudenv)$($nextUri)" -Method 'GET' -Headers $headers
        
        #add additional users to collection
        foreach ($u in $users.entities) {
            $userlist.add($u) | Out-Null
        }
        $selfUri = $users.selfUri
        $nextUri = $users.nextUri
    }
}

#Parse list of users that that do not have DefaultStation set to a phone
$toprovision = [System.Collections.ArrayList]::New()
foreach ($u in $userlist) {
    if (!$u.station.defaultStation) {
        $toprovision.add($u) | Out-Null
    }
}

if ($toprovision.count -lt 1) {
    Write-Output "No users need a WebRTC phone.  Exiting."
    Exit 0
}
else {
    Write-Output "Phones to provision: $($toprovision.count)"
}
#get site list.  Note, we expect a default site to be called "NORTHAMERICA" unless changed above.
$sitelist = Invoke-RestMethod "https://api.$($cloudenv)/api/v2/telephony/providers/edges/sites" -Method 'GET' -Headers $headers
if (!$sitelist.entities) {
    Write-Error "No Sites found defined, exiting"
    Exit 1
}
else {
    $sitelist = $sitelist.entities
}

#get edge group list, we should only have one, but we need the GUID for it
$edgegrouplist = Invoke-RestMethod "https://api.$($cloudenv)/api/v2/telephony/providers/edges/edgegroups" -Method 'GET' -Headers $headers
if ($edgegrouplist.entities) {
    $edgegroupid = $edgegrouplist.entities[0].id
    #Write-Output "Edge Group ID: $($edgegroupid)"
}
else {
    Write-Error "No edge group found, exiting"
    Exit 1
}

#get phone base settings list and ID for WebRTC entry
$phonebasesettingslist = Invoke-RestMethod "https://api.$($cloudenv)/api/v2/telephony/providers/edges/phonebasesettings?name=WebRTC" -Method 'GET' -Headers $headers
if ($phonebasesettingslist.entities) {
    $phonebasesettingsid = $null
    $webrtc = $phonebasesettingslist.entities | Where-Object -Property Name -Match "WebRTC"
    if ($webrtc) {
        $phonebasesettingsid = $webrtc.id
        #Write-Output "Phone Base Settings ID: $9$phonebasesettingsid)"
    }
    else {
        Write-Error "No WebRTC config found in Phone Base Settings"
        Exit 1
    }
}
else {
    Write-Error "No phone base settings found, exiting"
    Exit 1
}

#get line base settings list and ID for WebRTC entry
$linebasesettingslist = Invoke-RestMethod "https://api.$cloudenv/api/v2/telephony/providers/edges/linebasesettings" -Method 'GET' -Headers $headers
if ($linebasesettingslist.entities.count -gt 0) {
    $line = $linebasesettingslist.entities | Where-Object Name -Match "WebRTC"

    if ($line) {
        $linebasesettingsid = $line.id
        #Write-Output "Line Base Settings ID: $($linebasesettingsid)"
    }
    else {
        Write-Error "No line config found for Line Base Settings 'WebRTC'"
        Exit 1
    }
}
else {
    Write-Error "No line base settings found, exiting"
    Exit 1
}

#add the webrtc softphones
$headers.Add("Content-Type", "application/json")

foreach ($u in $toprovision) {
    Write-Output $sep
    $email = $u.email
    #try to find an existing WebRTC phone based on user ID first
    Write-Output "$($email): Check for existing WebRTC phone"
    $alreadyexists = $false
    $phonelookupresp = Invoke-RestMethod "https://api.$cloudenv/api/v2/telephony/providers/edges/phones?webRtcUser.id=$($u.id)" -Method 'GET' -Headers $headers

    if ($phonelookupresp.total -gt 0) {
        $webrtcid = $phonelookupresp.entities[0].Lines[0].id
        Write-Output "$($email): phone exists ($($webrtcid)), but not set as a default."
        $alreadyexists = $true
    }
    
    #phone doesn't already exist, create one
    if ($false -eq $alreadyexists) {
        Write-Output "$($email): WebRTC phone doesn't exist, creating one."
        Write-Output "$($email): Looking up User in AD to map WebRTC Site"
        $user = Get-AzAdUser -Filter "mail eq '$($email)'"        
        if ($user) {
            #User found, map them
            $location = $user.OfficeLocation
            $mappedlocation = $locationmap | Where-Object -Property Name -eq $location
            if ($mappedlocation) {                
                $site = $sitelist | Where-Object -Property Name -eq $mappedlocation.cloudlocation
                Write-Output "$($email): Site mapped to ($($site.name))"
                $siteid = $site.id
            }
            else {
                $site = $sitelist | Where-Object -Property Name -eq $defaultsite
                Write-Output "$($email): Site not mapped, using default ($($defaultsite))"
                $siteid = $site.id
            }

        }
        else {
            Write-Output "$($email): User not found in AD (local user?).  Using default ($($defaultsite))."
            $site = $sitelist | Where-Object -Property Name -eq $defaultsite
            $siteid = $site.id
        }
        #build WebRTC request payload
        $body = [PSCustomObject]@{
            name              = "$($u.name) WebRTC";
            edgeGroup         = @{ id = $edgegroupid };
            site              = @{ id = $siteid };
            phoneBaseSettings = @{ id = $phonebasesettingsid };
            webRtcUser        = @{ id = $u.id };
            lines             = @(
                @{
                    name             = "$($u.name) WebRTC";
                    lineBaseSettings = @{ id = $linebasesettingsid }
                }
            )
        }
        $phonejson = $body | ConvertTo-Json -depth 8
    
        $phoneresp = Invoke-RestMethod "https://api.$cloudenv/api/v2/telephony/providers/edges/phones" -Method 'POST' -Headers $headers -Body $phonejson -ErrorAction SilentlyContinue
        $webrtcid = $phoneresp.Lines[0].id
    }

    #update each user's Default Station
    Write-Output "$($u.email): Set default station to $($webrtcid)"
    $response = Invoke-RestMethod "https://api.$cloudenv/api/v2/users/$($u.id)/station/defaultstation/$($webrtcid)" -Method 'PUT' -Headers $headers
    Write-Output $sep
}




### Select import style - add or replace
$prompt = "Would you like to keep user's existing queues, or completely replace user's existing queues?" + "`n" + "Input a number to proceed" + "`n" + "`n" + "1 = Add to Existing" + "`n" + "2 = Replace Existing"
$queueSelection = Read-Host -Prompt $prompt

Switch ($queueSelection)
    {
        1 {
                $queueStyle = "add"
           }

        2 {
                $queueStyle = "replace"
           }
        default {
                Write-Output "**Invalid selection. Please try again."
                pause
                exit
        }
    }



### Select CSV location
try {
        $csv = Read-Host -Prompt "What is the exact location of your CSV?"
        $Users = Import-Csv $csv
}
catch {
        Write-Output "**Error parsing CSV file. Please try again."
        pause
        exit
}




### Get Queue list
Write-Output "Retrieving Org Queue List..."
[array]$queueList = @()
$queuePage = 1
$queuePageMore = $true
while ($queuePageMore -eq $true) {
        $fullPatchURL = $APIURL + "/api/v2/routing/queues?pageSize=50&sortOrder=asc&pageNumber=" + $queuePage
        try {
                $rawQueueResults = Invoke-WebRequest -Uri $fullPatchURL -Method Get -Headers $tokendHeader -ContentType application/json -TimeoutSec 60
        }
        catch {
                Write-Output "**Error or timeout retrieving org Skill information. Please try again."
                pause
                exit
        }
        
        $queueResults = $rawQueueResults | ConvertFrom-Json
        $queueList += $queueResults.entities
        if ($queuePage -eq $queueResults.pageCount) {
                $queuePageMore = $false
        }
        $queuePage = $queuePage + 1
        Start-Sleep -Milliseconds 500
}



### Create Queue list of raw values
[array]$queueListArray = @()
foreach ($que in $queueList){
        $queueListArray += @{
                name = $que.name
                id = $que.id
        }
}



$badUserList = @()
$badQueueList = @()
$failedUserList = @()
### Loop through user list
foreach ($u in $Users){
        $searchBody = @{
                sortOrder = "ASC"
                sortBy = ""
                pageSize = 100
                pageNumber = 1
                query = @(
                @{
                        fields = @("email")
                        value = $u.email
                        operator = "OR"
                        type = "QUERY_STRING"
                }
                        )
        }
        $fullSearchURL = $APIURL + "/api/v2/users/search"
        $searchBodyJson = ConvertTo-Json -InputObject $searchBody -Depth 4
        $rawSearchResults = Invoke-WebRequest -Uri $fullSearchURL -Method Post -Headers $tokendHeader -Body $searchBodyJson -ContentType application/json -TimeoutSec 60
        $searchResults = $rawSearchResults | ConvertFrom-Json


        ### If no user found, skip
        if ($searchResults.total -lt 1){
                $badUserList += $u.email
                continue
        }



        ### Build queue array
        $queuesTemp = $u.queues.replace(' ,',',')
        $queuesTemp = $queuesTemp.replace(', ',',')
        [array]$queueArray = $queuesTemp -Split(",")



        $queuesToAdd = @()
        ### Loop through queue array
        foreach ($queueUser in $queueArray){
#                $tempArray = $r -Split(":")
#                $skill = $tempArray[0].Trim()
#                [int]$proficiency = $tempArray[1]
                


                ### Check if queue exists in org
                $queueFound = $false
                foreach ($queueCheck in $queueListArray){
                        if ($queueUser -eq $queueCheck.name){
                                $queueId = $queueCheck.id
                                $queueFound = $true
                                break
                        }
                }


                if ($queueFound -eq $true){
                        $queuesToAdd += $queueId
                }
                else {
                        $badQueueList += $queueUser
                        $failedUserList += $u.email
                }

                Clear-Variable -name queueArray
                Clear-Variable -name queuesTemp
        }




        ### Build API Calls
        if ($queuesToAdd.count -lt 1){
                continue
        }
        else {
                Write-Output "Adding Queues to Users"
                $queuesAlreadyDeleted = $false
                foreach ($qta in $queuesToAdd) {
                        if ($queueStyle -eq "add"){
                                $fullpatchURL = $APIURL + "/api/v2/routing/queues/" + $qta + "/members?delete=false"
                                [array]$patchBody = @{
                                        id = ($searchResults.results).id
                                }
                                $patchBody = ConvertTo-Json -InputObject $patchBody -Depth 3

                                try {
                                        Invoke-WebRequest -Uri $fullpatchURL -Method Post -Headers $tokendHeader -Body $patchBody -ContentType application/json
                                }
                                catch {
                                        $failedUserList += $u.email
                                }
                                Clear-Variable -name patchBody
                                        
                        }
                        elseif ($queueStyle -eq "replace"){
                                if ($queuesAlreadyDeleted -eq $false) {
                                        ### Get list of user's current queues
                                        $fullpatchURL = $APIURL + "/api/v2/users/" + ($searchResults.results).id + "/queues?pageSize=500"
                                        try {
                                                $userCurrentQueueResultsRaw = Invoke-WebRequest -Uri $fullpatchURL -Method Get -Headers $tokendHeader -ContentType application/json -TimeoutSec 60
                                                $userCurrentQueueResults = $userCurrentQueueResultsRaw | ConvertFrom-Json
                                                $userCurrentQueueResults = $userCurrentQueueResults.entities
                                                Start-Sleep -Milliseconds 500
                                        }
                                        catch {
                                                $failedUserList += $u.email
                                        }
                                        ### Remove user from current queues
                                        foreach ($qtd in $userCurrentQueueResults) {
                                                $fullpatchURL = $APIURL + "/api/v2/routing/queues/" + $qtd.id + "/members?delete=true"
                                                [array]$patchBody = @{
                                                        id = ($searchResults.results).id
                                                }
                                                $patchBody = ConvertTo-Json -InputObject $patchBody -Depth 3

                                                try {
                                                        Invoke-WebRequest -Uri $fullpatchURL -Method Post -Headers $tokendHeader -Body $patchBody -ContentType application/json
                                                }
                                                catch {
                                                        $failedUserList += $u.email
                                                }
                                                Clear-Variable -name patchBody
                                                Start-Sleep -Milliseconds 500
                                        }
                                        $queuesAlreadyDeleted = $true
                                        pause
                                }

                                ### Add user to new queues
                                $fullpatchURL = $APIURL + "/api/v2/routing/queues/" + $qta + "/members?delete=false"
                                [array]$patchBody = @{
                                        id = ($searchResults.results).id
                                }
                                $patchBody = ConvertTo-Json -InputObject $patchBody -Depth 3

                                try {
                                        Invoke-WebRequest -Uri $fullpatchURL -Method Post -Headers $tokendHeader -Body $patchBody -ContentType application/json
                                }
                                catch {
                                        $failedUserList += $u.email
                                }
                                Clear-Variable -name patchBody
                                Start-Sleep -Milliseconds 500
                        }
                }
        }
        Clear-Variable -name queuesToAdd

}




$badQueueList = $badQueueList | select -Unique
$badUserList = $badUserList | select -Unique


Write-Output `n`n
if ($badUserList.Count -gt 0){
        Write-Output "***List of Users Not Found***" $badUserList
}
if ($badQueueList.Count -gt 0){
        Write-Output "***List of Queues Not Found***" $badQueueList
}
if ($failedUserList -gt 0){
        Write-Output "***List of Users Failed to Update***" $failedUserList
}
Write-Output "`n`n~~Complete~~`n" 
pause

