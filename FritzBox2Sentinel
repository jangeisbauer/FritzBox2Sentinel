# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# FritzBox2Sentinel | FritzBox Event Logs To Azure Sentinel
#
# Jan Geisbauer (@janvonkirchheim)
#
# Connects to your fritzbox (https://avm.de/produkte/fritzbox/), reads the Eventlog, extracts EventTime, IPv4, IPv6 
# and then sends everything zu Azure Sentinel.
#
# You need to provide:
#  - Workspace Primary Key
#  - Workspace ID
#  - secureString location for your fritzbox password ConvertFrom-SecureString (read-host -AsSecureString -Prompt "Passwort ") >SecureString.fb
#
# Happy Hunting!
#
# With great help from this code:
# - https://www.ip-phone-forum.de/threads/ereignisprotokoll-der-fritz-box-auf-linux-server-sichern.280328/page-5 & https://gist.github.com/joasch/e48738417ec1efcc963a96bbb3f34cba 
# - https://gist.github.com/joasch/e48738417ec1efcc963a96bbb3f34cba
# - https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Vars
$PrimaryKey="yourPrimKey"
$WorkspaceID="yourID"
$secureString = ".\securestring.fb"

# connect to fritzbox, login and get the the events 
function md5($text){
$md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
$md5.ComputeHash([Text.Encoding]::utf8.getbytes($text))|%{$HC=''}{$HC+=$_.tostring("x2")}{$HC}
}
$Password=get-content $secureString|ConvertTo-SecureString
$user="fbevents"
$hostfb="http://fritz.box"
$page_login=  "/login_sid.lua"
$page_events=  "/query.lua?mq_log=logger:status/log&sid="
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$pass=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Ptr)
$R1 = Invoke-WebRequest ($hostfb+$page_login)
$Challenge=([xml]$R1).sessioninfo.challenge
$Code1=$Challenge+"-"+$Pass 
$Code2=[char[]]$Code1|%{$Code2=""}{$Code2+=$_+[Char]0}{$Code2}
$Response= "response=" + $Challenge + "-" + $(md5($Code2))
$Response+="&username="+$user 
$R2=Invoke-WebRequest -Uri ($hostfb+$page_login) -Method Post -Body $Response
$SID=([xml]($R2.Content)).ChildNodes.sid
$URievents=    $hostfb+$page_events+$SID
$events=Invoke-WebRequest -Uri $URievents  

# log analytics data collector api 
Function Get-LogAnalyticsSignature {
    [cmdletbinding()]
    Param (
        $customerId,
        $sharedKey,
        $date,
        $contentLength,
        $method,
        $contentType,
        $resource
    )
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}
Function Export-LogAnalytics {
    [cmdletbinding()]
    Param(
        $customerId,
        $sharedKey,
        $object,
        $logType,
        $TimeStampField
    )
    $bodyAsJson = ConvertTo-Json $object
    $body = [System.Text.Encoding]::UTF8.GetBytes($bodyAsJson)

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length

    $signatureArguments = @{
        CustomerId = $customerId
        SharedKey = $sharedKey
        Date = $rfc1123date
        ContentLength = $contentLength
        Method = $method
        ContentType = $contentType
        Resource = $resource
    }

    $signature = Get-LogAnalyticsSignature @signatureArguments
    
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# preparing the events to match sentinel db fields / extracting ipv4, ipv6 and datetime 
$fritzEvents=@()
foreach($line in ($events.Content | ConvertFrom-Json).mq_log)
{
    $eventDate=[regex]::Matches($line, '\d\d\.\d\d\.\d\d \d\d:\d\d:\d\d')[0].Value
    $ipv6=[regex]::Matches($line[0], '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')[0].Value
    $ipv4=[regex]::Matches($line[0], '((?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d))')[0].Value
    if($eventDate -ne "")
    {
        $eventLine = $line[0].replace($eventDate,"")
    }
    $fritzEvents += [PSCustomObject]@{
        eventDate = $eventDate
        eventMessage = $eventLine
        IPv4 = $ipv4
        IPv6 = $ipv6
    }
}

# prepare sending
$logAnalyticsParams = @{
    CustomerId = $WorkspaceID
    SharedKey = $PrimaryKey
    TimeStampField = "eventDate"
    LogType = "fritzbox"
}

# send data to sentinel
Export-LogAnalytics @logAnalyticsParams $fritzEvents
