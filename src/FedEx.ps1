<#
  ╓──────────────────────────────────────────────────────────────────────────────────────
  ║   PowerShell FedEx Module
  ╙──────────────────────────────────────────────────────────────────────────────────────
 #>



function Script:AutoUpdateProgress {        # NOEXPORT
    Write-Progress -Activity $Script:ProgressTitle -Status $Script:ProgressMessage -PercentComplete (($Script:StepNumber / $Script:TotalSteps) * 100)
    if($Script:StepNumber -lt $Script:TotalSteps){$Script:StepNumber++}
}

function Get-AuthorizationHeader { # NOEXPORT
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [PSCredential]
        [System.Management.Automation.CredentialAttribute()]$Credential
    )
    
    process {
        'Basic {0}' -f (
            [System.Convert]::ToBase64String(
                [System.Text.Encoding]::ASCII.GetBytes(
                    ('{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password)
                )# End [System.Text.Encoding]::ASCII.GetBytes(
            )# End [System.Convert]::ToBase64String(
        )# End 'Basic {0}' -f
    }# End process
}# End Get-AuthorizationHeader

function Get-FedExUrl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present", Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$Action     
    )
    $baseoauth = 'https://oauth.reddit.com/'
    $base = 'https://www.reddit.com/'
    $result=''
    switch ( $Action )
    {
        'auth'   { $result = $base + 'api/v1/access_token' }
        'me'     { $result = $baseoauth + 'api/v1/me'    }
        'comments'  { $result = $baseoauth + 'user/cybercastor/comments'    }
        'auth4'  { $result = '' }
        'auth5'  { $result = ''  }
        'auth6'  { $result = ''    }
        'auth7'  { $result = ''  }
        default { throw "invalid action"  }
    }

    return $result
}

function Get-FedExUserCredentialID { 
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [String]$Id
    )
    $Credz = 'Fedex.Shipping.Account.Test'


    return $Credz
}

function Get-FedExAppCredentialID { 
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [String]$Id
    )
    $Credz = 'PowerShell.Module.Fedex'
     
    return $Credz
}

function Test-FedExLog{ 
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    $Path = Get-FedExModuleRegistryPath
    Write-MOk "Path is $Path"
    Write-ChannelMessage "Path is $Path"
    Write-ChannelResult "Path is $Path"
}

function Get-FedExModuleUserAgent { 
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    $ModuleName = ($ExecutionContext.SessionState).Module
    $Agent = "User-Agent $ModuleName. Custom Module."
   
    return $Agent
}

function Get-FedExModuleRegistryPath { 
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    if( $ExecutionContext -eq $null ) { throw "not in module"; return "" ; }
    $ModuleName = ($ExecutionContext.SessionState).Module
    $Path = "$ENV:OrganizationHKCU\$ModuleName\FedEx.com"
   
    return $Path
}

function Set-FedExAppSecret {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [ValidateNotNullOrEmpty()]
        [String]$Token,        
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Overwrite if present")]
        [switch]$Force      
    )
    $RegPath = Get-FedExModuleRegistryPath
    if( $RegPath -eq "" ) { throw "not in module"; return ;}
    $TokenPresent = Test-RegistryValue -Path "$RegPath" -Entry 'access_token'
    
    if( $TokenPresent ){ 
        Write-Verbose "Token already configured"
        if($Force -eq $False){
            return;
        }
    }
    $ret = New-RegistryValue -Path "$RegPath" -Name 'access_token' -Value $Token -Type 'string'
    return $ret
}

function Get-FedExAppSecret {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    $RegPath = Get-FedExModuleRegistryPath
    $TokenPresent = Test-RegistryValue -Path "$RegPath" -Entry 'access_token'
    if( $TokenPresent -eq $true ) {
        $Token = Get-RegistryValue -Path "$RegPath" -Entry 'access_token'
        return $Token
    }
    if( $Env:FEDEX_ACCESSTOKEN -ne $null ) { return $Env:FEDEX_ACCESSTOKEN  }
    return $null
}

function Set-FedExDefaultUsername {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Git Username")]
        [String]$User      
    )
    $RegPath = Get-FedExModuleRegistryPath
    $ok = Set-RegistryValue  "$RegPath" "default_username" "$User"
    [environment]::SetEnvironmentVariable('DEFAULT_FEDEX_USERNAME',"$User",'User')
    return $ok
}

<#
    RedditDefaultUsername
    New-ItemProperty -Path "$ENV:OrganizationHKCU\Reddit.com" -Name 'default_username' -Value 'codecastor'
 #>
function Get-FedExDefaultUsername {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    $RegPath = Get-FedExModuleRegistryPath
    $User = (Get-ItemProperty -Path "$RegPath" -Name 'default_username' -ErrorAction Ignore).default_username
    if( $User -ne $null ) { return $User  }
    if( $Env:DEFAULT_GIT_USERNAME -ne $null ) { return $Env:DEFAULT_GIT_USERNAME ; }    
    if( $Env:USERNAME -ne $null ) { return $Env:USERNAME ; }
    return $null
}


function Get-FedExServer {      
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    $RegPath = Get-FedExModuleRegistryPath
    $Server = (Get-ItemProperty -Path "$RegPath" -Name 'hostname' -ErrorAction Ignore).hostname
    if( $Server -ne $null ) { return $Server }
     
    if( $Env:DEFAULT_FEDEX_SERVER -ne $null ) { return $Env:DEFAULT_FEDEX_SERVER  }
    return $null
}

function Set-FedExDefaultServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Git Username")]
        [String]$Hostname      
    )
    $RegPath = Get-FedExModuleRegistryPath
    $ok = Set-RegistryValue  "$RegPath" "hostname" "$Hostname"
    [environment]::SetEnvironmentVariable('DEFAULT_FEDEX_SERVER',"$Hostname",'User')
    return $ok
}


