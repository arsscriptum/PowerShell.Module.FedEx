

# You use the /api/submit endpoint, but set kind to crosspost instead of link, and the fullname of the original post as crosspost_fullname.



function New-RedditCrossPost{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [ValidateNotNullOrEmpty()]
        [String]$Original,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [ValidateNotNullOrEmpty()]
        [String]$NewUrl
    )   
        $UserCredz = Get-AppCredentials (Get-RedditUserCredentialID)
        $AppCredz = Get-AppCredentials (Get-RedditAppCredentialID)
        $User = $UserCredz.UserName
        $base = 'https://oauth.reddit.com'
        $AuStr = 'bearer ' + (Get-RedditAuthenticationToken)
        [String]$Url = "$base/api/submit"
        $HeadersData = @{
            Authorization = $AuStr
            user        = $Username
        }
        $BodyData = @{
            grant_type  = 'password'
            username    = $UserCredz.UserName
            password    = $UserCredz.GetNetworkCredential().Password    
            crosspost_fullname = $Original
            link = $NewUrl
            kind = 'crosspost'
        }
        $Params = @{
            Uri             = $Url
            Body            = $BodyData
            UserAgent       = Get-RedditModuleUserAgent
            Headers         = $HeadersData
            Method          = 'POST'
            UseBasicParsing = $true
        }      

      
        Write-Verbose "Invoke-WebRequest Url: $Url"
        Write-Verbose "Params = $Params"
        $Response = (Invoke-WebRequest @Params).Content
        $ResponseJson = $Response | ConvertFrom-Json
        Write-Verbose "Invoke-WebRequest Response: $Response"
        $Response
}


function Get-RedditSearchSubreddits{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [switch]$Exact,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [switch]$Mature
    )   
        $UserCredz = Get-AppCredentials (Get-RedditUserCredentialID)
        $AppCredz = Get-AppCredentials (Get-RedditAppCredentialID)
        $User = $UserCredz.UserName
        $base = 'https://oauth.reddit.com'
        $AuStr = 'bearer ' + (Get-RedditAuthenticationToken)
        $ExactStr = 'false'
        $MatureStr = 'true'
        [String]$RequestUrl = "https://oauth.reddit.com/api/search_subreddits?query=$Name&exact=$ExactStr&include_over_18=$MatureStr"    

        $HeadersData = @{
            Authorization = $AuStr
            user          = $Username
        }
        $BodyData = @{
            grant_type  = 'password'
            username    = $UserCredz.UserName
            password    = $UserCredz.GetNetworkCredential().Password    
            user = $Username
        }
        $Params = @{
            Uri             = $RequestUrl
            Body            = $BodyData
            UserAgent       = Get-RedditModuleUserAgent
            Headers         = $HeadersData
            Method          = 'POST'
            UseBasicParsing = $true
        }
        Write-Host -n -f Cyan "REDDIT SEARCH "      
        Write-Host -f DarkCyan "Searching SubReddit with name like $Name..."
        Write-Verbose "Invoke-WebRequest Url: $Url"
        Write-Verbose "Params = $Params"
        $Response = (Invoke-WebRequest @Params).Content
        $ResponseJson = $Response | ConvertFrom-Json
        Write-Verbose "Invoke-WebRequest Response: $Response"
        $ResponseJson.subreddits.Name
}

function Get-SubredditInfo{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )   
        $UserCredz = Get-AppCredentials (Get-RedditUserCredentialID)
        $AppCredz = Get-AppCredentials (Get-RedditAppCredentialID)
        $User = $UserCredz.UserName
        $base = 'https://oauth.reddit.com'
        $AuStr = 'bearer ' + (Get-RedditAuthenticationToken)

        [String]$RequestUrl = "https://oauth.reddit.com/r/$Name/about"    

        $HeadersData = @{
            Authorization = $AuStr
            user          = $Username
        }
        $BodyData = @{
            grant_type  = 'password'
            username    = $UserCredz.UserName
            password    = $UserCredz.GetNetworkCredential().Password    
            user = $Username
        }
        $Params = @{
            Uri             = $RequestUrl
            Body            = $BodyData
            UserAgent       = Get-RedditModuleUserAgent
            Headers         = $HeadersData
            Method          = 'GET'
            UseBasicParsing = $true
        }
        Write-Host -n -f Cyan "REDDIT SEARCH "      
        Write-Host -f DarkCyan "Searching SubReddit with name like $Name..."
        Write-Verbose "Invoke-WebRequest Url: $Url"
        Write-Verbose "Params = $Params"
        $Response = (Invoke-WebRequest @Params).Content
        $ResponseJson = $Response | ConvertFrom-Json
        Write-Verbose "Invoke-WebRequest Response: $Response"
        $ResponseJson
}
function Get-RedditUserAvailable{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [ValidateNotNullOrEmpty()]
        [String]$Username     
    )   
        $UserCredz = Get-AppCredentials (Get-RedditUserCredentialID)
        $AppCredz = Get-AppCredentials (Get-RedditAppCredentialID)
        $User = $UserCredz.UserName
        $base = 'https://oauth.reddit.com'
        $AuStr = 'bearer ' + (Get-RedditAuthenticationToken)
        [String]$Url = "$base/api/username_available"
        $HeadersData = @{
            Authorization = $AuStr
            user        = $Username
        }
        $BodyData = @{
            grant_type  = 'password'
            username    = $UserCredz.UserName
            password    = $UserCredz.GetNetworkCredential().Password    
            user = $Username
        }
        $Params = @{
            Uri             = $Url
            Body            = $BodyData
            UserAgent       = Get-RedditModuleUserAgent
            Headers         = $HeadersData
            Method          = 'GET'
            UseBasicParsing = $true
        }      


        $P = $Params | ConvertTo-Json
        Write-Verbose "Invoke-WebRequest Url: $Url P = $P"
        $ResponseJson = (Invoke-WebRequest @Params).Content
        $ResponseList = $ResponseJson | ConvertFrom-Json | Out-String
        write-host -f DarkRed "=================================="
        write-host -f DarkYellow "ResponseJson: $ResponseJson"
        write-host -f DarkCyan "--------------"
        write-host -f DarkYellow "ResponseList: $ResponseList"    
        write-host -f DarkRed "=================================="    
        Write-Verbose "Invoke-WebRequest Response: $Response"
}