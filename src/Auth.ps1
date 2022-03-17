<#
  ╓──────────────────────────────────────────────────────────────────────────────────────
  ║   PowerShell FedEx Module
  ╙──────────────────────────────────────────────────────────────────────────────────────
 #>



Function Get-FedExAuthenticationToken{
    [CmdletBinding(SupportsShouldProcess)]
    param(       
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Force")]
        [switch]$Force
    ) 

    $UserCredz = Get-AppCredentials (Get-FedExUserCredentialID)
    $AppCredz = Get-AppCredentials (Get-FedExAppCredentialID)
    $ClientID = $AppCredz.UserName
    $ClientSecret = $AppCredz.GetNetworkCredential().Password    
        $RegPath = Get-FedExModuleRegistryPath
        if( $RegPath -eq "" ) { throw "not in module"; return ;}
        Write-Verbose "look in $RegPath"
        $Exists = $False
        if($Force -eq $False) {
            $Exists = Get-RegistryValue -Path "$RegPath" -Name 'access_token'    
        }
        if($Exists){
            $NowTime = Get-Date 
            $NowTimeSeconds = ConvertTo-CTime($NowTime)
            $TimeExpiredSeconds = Get-RegistryValue -Path "$RegPath" -Name 'expiration_time'
        
            $Diff = $NowTimeSeconds-$TimeExpiredSeconds
            Write-Verbose "NowTimeSeconds $NowTimeSeconds, TimeExpiredSeconds $TimeExpiredSeconds, Diff $Diff"
            $Token = Get-RegistryValue -Path "$RegPath" -Name 'access_token'
            if($Diff -lt 0){
                $UpdateWhen = 1 - $Diff 
                Write-Verbose "Use existing $Token, Update in $UpdateWhen seconds"
                return $Token
            }
        }else{
            Write-Verbose "$RegPath access_token DOEAN EXISTS"    
        }
        [String]$Url = "https://apis-sandbox.fedex.com/oauth/token"
        $HeadersData = @{
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        $BodyData = @{
            grant_type      = 'client_credentials'
            client_id       = $ClientID
            client_secret   = $ClientSecret
            username        = $UserCredz.UserName
            password        = $UserCredz.GetNetworkCredential().Password    
        }
        $Params = @{
            Uri             = $Url
            Body            = $BodyData
            UserAgent       = Get-FedExModuleUserAgent
            Headers         = $HeadersData
            Method          = 'POST'
            UseBasicParsing = $true
        }      


    $ExpiresInSecs = 60
    Write-Verbose "Invoke-WebRequest Url: $Url"
    Write-Verbose "Params = $Params"
    $Response = Invoke-RestMethod @Params
    $Token = $Response.access_token
    Write-Verbose "Invoke-RestMethod Token: $Token"
    [DateTime]$NowTime = Get-Date
    [DateTime]$ExpirationTime = $NowTime.AddSeconds($ExpiresInSecs)

    $NowTimeSeconds = ConvertTo-CTime($NowTime)
    $ExpirationTimeSeconds = ConvertTo-CTime($ExpirationTime)
       
    $Null=New-Item -Path $RegPath -ItemType Directory -Force
    $Null = Set-RegistryValue -Path "$RegPath" -Name 'access_token' -Value $Token 
    $Null = Set-RegistryValue -Path "$RegPath" -Name 'created_on' -Value $NowTimeSeconds
    $Null = Set-RegistryValue -Path "$RegPath" -Name 'expiration_time' -Value $ExpirationTimeSeconds
    return $Token
}

# Custom wrapper for Invoke-RestMethod.
Function Invoke-ValidatePostal{
    [CmdletBinding(SupportsShouldProcess)]
    param(       
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Force")]
        [string]$PostalCode,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Force")]
        [ValidateSet('AB','BC','MB','NB','NL','NT','NS','NU','ON','PE','QC','SK','YT')]
        [string]$Province,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Force")]
        [ValidateSet('US','CA')]
        [string]$Country,
        [DateTime]$ShipDate
    ) 
        [String]$Guid = (New-Guid).Guid
        [String]$Url = 'https://apis-sandbox.fedex.com/country/v1/postal/validate'
        $AuStr = 'bearer ' + (Get-FedExAuthenticationToken -Force)
        $HeadersData = @{
            #"x-customer-transaction-id" = "$Guid"
            "content-type" = "application/json"
            Authorization = $AuStr
        }
        #    string Specify the date on which the package is to be shipped. 
        #    The specified date should not be the current date or any date, 10 days after the current date. 
        #    The date format must be YYYY-MM-DD.
        $BodyData = @{
            carrierCode  = 'FDXG'
            countryCode  = "$Country"
            stateOrProvinceCode  = "$Province"
            postalCode  = "$PostalCode"
            shipDate    = '2022-02-14'
            username    = $UserCredz.UserName
            password    = $UserCredz.GetNetworkCredential().Password
        }
        $Params = @{
            Uri             = $Url
            Body            = $BodyData
            UserAgent       = Get-FedExModuleUserAgent
            Headers         = $HeadersData
            Method          = 'GET'
            UseBasicParsing = $true
        }      


    Invoke-RestMethod @Params
}
