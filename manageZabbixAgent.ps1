<# 
	.Synopsis
		installs and configures zabbix agent
	.Description
		installs and configures zabbix agent	
	.Parameter modulePath
		Path where psbbix module is located. It can be get from https://github.com/herrbpl/psbbix-zabbix-api 
	.Example
		New-ZabbixSession 10.10.10.10
		Connect to Zabbix server
	.Example
		Connect-Zabbix -IPAddress 10.10.10.10 -noSSL
		Connect to Zabbix server with noSSL (http)
	.Example
		Connect-Zabbix -User admin -Password zabbix -IPAddress zabbix.domain.net
		Connect to Zabbix server
	#>

# http://stackoverflow.com/questions/3736188/enum-like-switch-parameter-in-powershell
# https://blogs.technet.microsoft.com/heyscriptingguy/2011/06/30/use-parameter-sets-to-simplify-powershell-commands/

Param(
  [Parameter(ParameterSetName='Status')]  
  [switch]$Status,

  [Parameter(ParameterSetName='Stop')]  
  [switch]$Stop,

  [Parameter(ParameterSetName='Start')]  
  [switch]$Start,

  [Parameter(ParameterSetName='Uninstall')]  
  [switch]$Uninstall,

  [Parameter(ParameterSetName='Install')]  
  [switch]$Install,


  [Parameter(ParameterSetName='Install')]
  [String]$ZabbixHost,
  
  [Parameter(ParameterSetName='Install')]
  [String]$ZabbixDir,

  [Parameter(ParameterSetName='Install')]
  [String]$ZabbixInstallDir,

  [Parameter(ParameterSetName='Install')]
  [string]$ZabbixAgentName, 

  [Parameter(ParameterSetName='Install')]
  [switch]$ZabbixRegisterAgent, 

  [Parameter(Mandatory=$False,ParameterSetName='Install')][string]$GroupID,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true,ParameterSetName='Install')][array]$Groups,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true,ParameterSetName='Install')][array]$TemplateID,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true,ParameterSetName='Install')][array]$Templates,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true,ParameterSetName='Install')][switch]$MonitorByDNSName,

  [Parameter(ParameterSetName='Install')]
  [string]$Username, 

  [Parameter(ParameterSetName='Install')]
  [string]$PasswordFilePath, 

  [Parameter(ParameterSetName='Install')]
  [string]$Password, 

  [Parameter(ParameterSetName='Install')]
  [System.Management.Automation.PSCredential]$PSCredential,

  [string]$ModulePath
)


Function Import-Module-pssbix {
    Param(
        [string]$modulePath
    )

    # Load zabbix module
    if (Get-Module -Name psbbix) {
        Write-Verbose "psbbix module already loaded"
        return $true
    } else {
        Write-Verbose "psbbix module not loaded, loading"

        # Load module
        if ($modulePath -ne "" -and (Test-Path $modulePath)) {
            #Write-Host "Module exist"
            import-module $modulePath
            return $true
        } elseif (Get-Module -ListAvailable -Name psbbix) {
            #Write-Host "Module exist"
            import-module psbbix
            return $true
        } else {

            # Try loading from current directory
            $tempModulePath = (Split-Path $script:MyInvocation.MyCommand.Path) + "\psbbix.psm1"
            if ($tempModulePath -ne "" -and (Test-Path $tempModulePath)) {
                import-module $tempModulePath
                return $true
            } else {
                Write-Error "Cannot load module, cannot find module psbbix!"
                return $false
            }
        }
    }
    return $false
}

if ($false -eq (Import-Module-pssbix -modulePath $ModulePath)) {
    write-error "Could not load psbbix module. Exiting"
    exit 1
}

# Status

if ($Status -eq $true) {

    $zabbixversion = Get-ZabbixAgentVersion

    if ($zabbixversion -ne $null) {
        $zabbixstatus = Get-ZabbixAgentServiceStatus
        if ($zabbixstatus -ne $null) {
            $zabbixversion = "$zabbixversion : $zabbixstatus"
        } else {
            $zabbixversion = "$zabbixversion : unknown"
        }
    } else {
        "Not installed!"
    }

    $zabbixversion
    exit 0
}


# Stop

if ($Stop -eq $true) {

    Stop-ZabbixAgent
    
    exit 0
}


# Start

if ($Start -eq $true) {

    Start-ZabbixAgent
    
    exit 0
}


# Uninstall

if ($Uninstall -eq $true) {

    Uninstall-ZabbixAgent
    
    exit 0
}


# Install

if ($Install -eq $true) {

    # Parameters check       

    if ($ZabbixHost -eq $null -or $ZabbixHost -eq "") {        
        throw "ZabbixHost parameter is required for installation"
    }

    if ($ZabbixDir -eq $null -or $ZabbixDir -eq "") {        
        throw "ZabbixDir parameter is required for installation"
    }

    if ($ZabbixInstallDir -eq $null -or $ZabbixInstallDir -eq "") {        
        throw "ZabbixInstallDir parameter is required for installation"
    }
    
    if ($ZabbixRegisterAgent -eq $true) {


        $ipdata = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | ? {$_.DefaultIPGateway -ne $null } | select IPAddress,DNSDomain
        $ip = $ipdata.IPAddress[0]

        $objIPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()

        $fqdn = $(
            if (($objIPProperties.DomainName -eq $null)) {
            "{0}" -f $objIPProperties.HostName
            }
            else {
            "{0}.{1}" -f $objIPProperties.HostName, $objIPProperties.DomainName
            }
        )


        if ($ZabbixAgentName -eq $null -or $ZabbixAgentName -eq "") {
            # throw "-ZabbixRegisterAgent parameter expects -ZabbixAgentName to be present"                    
            $ZabbixAgentName = $fqdn
        }

        $cred = Get-ZabbixCreditentials -Username $Username -Password $Password -PasswordFilePath $PasswordFilePath -PSCredential $PSCredential
        
        New-ZabbixSession -PSCredential $cred -IPAddress $ZabbixHost 


        

        if ($MonitorByDNSName) {

            New-ZabbixHost @zabSessionParams -HostName $ZabbixAgentName -IP $ip -DNSName $fqdn -MonitorByDNSName  -GroupID $GroupID -TemplateID $TemplateID -status 0
        } else {
            New-ZabbixHost @zabSessionParams -HostName $ZabbixAgentName -IP $ip -DNSName $fqdn -GroupID $GroupID -TemplateID $TemplateID -status 0
        }

    }

    # If no aggent name is given, then we need to retrieve it.
    if ($ZabbixAgentName -eq $null -or $ZabbixAgentName -eq "") {

        # credidentials
        # http://stackoverflow.com/questions/6239647/using-powershell-credentials-without-being-prompted-for-a-password
        $cred = Get-ZabbixCreditentials -Username $Username -Password $Password -PasswordFilePath $PasswordFilePath -PSCredential $PSCredential
        
        New-ZabbixSession -PSCredential $cred -IPAddress $ZabbixHost 
        $ZabbixAgentName = Get-ZabbixAgentHostname @zabSessionParams

    } 

    if ($ZabbixAgentName -eq $null -or $ZabbixAgentName -eq "") {
        throw "Unable to determine ZabbixAgentName."
    }

    Install-ZabbixAgent -zabbixHost $ZabbixHost -zabbixDir $ZabbixDir -zabbixInstallDir $ZabbixInstallDir -zabbixAgentName $ZabbixAgentName -Upgrade
    exit 0   
}

# SIG # Begin signature block
# MIINNwYJKoZIhvcNAQcCoIINKDCCDSQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZoxSPzOrxTqT2oFwyw8/5ubI
# cKmgggqTMIIFFzCCA/+gAwIBAgITLQAAAvZBJVsiSnHa3wAAAAAC9jANBgkqhkiG
# 9w0BAQsFADBWMRQwEgYKCZImiZPyLGQBGRYEc2lzZTEZMBcGCgmSJomT8ixkARkW
# CW50c2VydmVyMjEjMCEGA1UEAxMaQVMgVGFsbGlubmEgVmVzaSBPbmxpbmUgQ0Ew
# HhcNMTYwMzE0MTIzMDQyWhcNMjEwMzEzMTIzMDQyWjBxMRQwEgYKCZImiZPyLGQB
# GRYEc2lzZTEZMBcGCgmSJomT8ixkARkWCW50c2VydmVyMjEOMAwGA1UECxMFVFZF
# U0kxFzAVBgNVBAsTDkFkbWluaXN0cmF0b3JzMRUwEwYDVQQDEwxBRE0gU2lpbSBB
# dXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7JxaBQP70kdl9wu5K
# FTIxSVMFXYauJy/jWXKARXTC3ntzHvz1tFIhySL0+8XedvlcXKEtlscLokMiqbfE
# 2U6EMi5WrDnwQDk+PjEw7szlBWMBrwwwnYrHveZyFuMLQWHDmfMvCmXip76+Gdm0
# XFt0Tl37BmhDd9SMIcGbtecrgzxMXMJBqTYMkXyvSdzH+WAQQyxiSrogji+RpUeE
# AeWuilclec6suByym38mQa79Qw8wPD8qaw237gpkmqF9Jb5L84eU8pUnceANtDsF
# y+TyBRYRjOXNOLp59+vKMWGiU4gkWuTx5wojDz8bt/IsCtXH9tKeS8y1nya8t35W
# IsPhAgMBAAGjggHBMIIBvTA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiG6ac7
# gsXLWPGRAoO5u3qDg6dAgW2GycdThPeUPwIBZAIBAzATBgNVHSUEDDAKBggrBgEF
# BQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcD
# AzAdBgNVHQ4EFgQU6U4LGEbZy0iN05WqXEQsROBbC/swHwYDVR0jBBgwFoAUEWar
# MjEMiM2zLWYVrFQgFOCyF1EwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NhLm50
# c2VydmVyMi5zaXNlL3BraS9BUyUyMFRhbGxpbm5hJTIwVmVzaSUyME9ubGluZSUy
# MENBLmNybDB3BggrBgEFBQcBAQRrMGkwZwYIKwYBBQUHMAKGW2h0dHA6Ly9jYS5u
# dHNlcnZlcjIuc2lzZS9wa2kvTG9naXN0aWMubnRzZXJ2ZXIyLnNpc2VfQVMlMjBU
# YWxsaW5uYSUyMFZlc2klMjBPbmxpbmUlMjBDQS5jcnQwKwYDVR0RBCQwIqAgBgor
# BgEEAYI3FAIDoBIMEGFkbXNpaW1AdHZlc2kuZWUwDQYJKoZIhvcNAQELBQADggEB
# AEuBQyWG2nOI4gT6JhUl3l/kWEOlP73xD9wGA2zzYnToqQSh031FWDJmRhf5nJOL
# yRerw9pyMicovBvgYraEw+duJTGPbZT20gjO3v6iBwZUyjUd6qN3Ec3lQuSAFq9f
# N6HkzTlb3jK4e71eKneqDqmbkOjFZdT1MT82moTUNvrG0s9Fo2i3qB9BrOedIjDH
# HkUDbo9v+Onz1oBA03YlV45E0Z3jGhjAf6kOMXMbNAXKfPmZ/8jtTOeHPHQHhHtZ
# B0U4tHdoyXD2MwsLrOu963kTV//A4MrtB0ZZZNAPlvm7Q4bXxc6WEiMGwjSRTfek
# iHA0sVJzK9NCrRgg3KPX88QwggV0MIIDXKADAgECAhM+AAAAAl0Bz4yIla0tAAAA
# AAACMA0GCSqGSIb3DQEBDQUAMCMxITAfBgNVBAMTGEFTIFRhbGxpbm5hIFZlc2kg
# Um9vdCBDQTAeFw0xNTA5MDExNTIwMzNaFw0yNTA5MDExNTMwMzNaMFYxFDASBgoJ
# kiaJk/IsZAEZFgRzaXNlMRkwFwYKCZImiZPyLGQBGRYJbnRzZXJ2ZXIyMSMwIQYD
# VQQDExpBUyBUYWxsaW5uYSBWZXNpIE9ubGluZSBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAK7G17xMJSMfMHWGQtHe7x+kAzg9aWRF1AQ6BSDr3aoQ
# oCjd/u67VLbRFVQBi76bOxvzD/1A4BJUBsgoEsC+FXIaEwsbazt8UtS7/S7FL2b3
# uI3a7DYgqRGX+2xqZDOioPM9JE3NND5Vq5heZlhixn4LfneAlEATwjaLUsaEUaDW
# rsV90panoC9ErKhdvSf4D8/rQWjCiutIDEh44Qy6/yslUUQ/U+wLsV21FPjXF5Lj
# /fzTuWoHfK6kGDeik1mSzuMU4cGc7Ndn1fNWoCXJofj5MkXmO7T8Z6pt0TuemGTq
# 24eF9iBtT1vZ993h6ko3gLWhc064PRb4WiuUovA9F9kCAwEAAaOCAWwwggFoMBAG
# CSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBQRZqsyMQyIzbMtZhWsVCAU4LIXUTCB
# hgYDVR0gBH8wfTB7BggqAwSLL0NZBTBvMDoGCCsGAQUFBwICMC4eLABMAGUAZwBh
# AGwAIABQAG8AbABpAGMAeQAgAFMAdABhAHQAZQBtAGUAbgB0MDEGCCsGAQUFBwIB
# FiVodHRwOi8vQ0EubnRzZXJ2ZXIyLnNpc2UvcGtpL2Nwcy50eHQAMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFP5bMk121+Q3aJo4TLcCxf2u6/UlMFIGA1UdHwRLMEkwR6BF
# oEOGQWh0dHA6Ly9jYS5udHNlcnZlcjIuc2lzZS9wa2kvQVMlMjBUYWxsaW5uYSUy
# MFZlc2klMjBSb290JTIwQ0EuY3JsMA0GCSqGSIb3DQEBDQUAA4ICAQA72eZ7MwNC
# TMvELWsS8GvG6mQWZt+vP8POIvWZRx9rKd5Rtx8Uul5tQVYKEPgqyAX8S6M7bQBz
# kPXNVwXAdui7JpDr5afLYQ0Z1Vt3OeULWUT2Yh3/bS258Li6AL//r2jLzHSCKocy
# 81sLyyiwOLX7T2cKjUMBoxEViLUxaokeApNyumbrC0LshOeiugZlYuWEPTP07MdK
# VumehJRe9ZJy791AdRw7M8S/E38e6BdlSgNbqPQy8tBGUqG9+J8MXwPK5de8IGXr
# fBt4iPauVeDdVKAjEtTg9IMxzUnHsoRr5s3NQi2NfdVE5pVs6lFsD/BEdmkIMNtu
# +oAx02n7NxO+ysRF7I3vjuIb3ba+lTzybXziBWRUnXmL/s3og/ZAMgECjx9dFQ05
# GkauggbQ5EbjMW2uoJLTEg/Q1T/uCGmXgWdc/9OihI4W90mpwSOgapFuLNF8lhAY
# NxuKdvIA2KNqnnwti96L5LwkffM/Si1JTSSM+kq77tn4OdfSgJdqnnOfmc7HkwBo
# gpWR4iROaFMQaOTfaISian4QiLBKA+4NhE5NCzP0LmDuntNKuBTQbjupr0sOyKvh
# 65aZStbU2kmAfUK9kDRqRaGR/IwD4oWpvP/xnq/UzZXOhiPrHC6m3p2WtAdSlk92
# epzTA8dzmq6mq3CDT1O3x1RMFY4HBHHKgzGCAg4wggIKAgEBMG0wVjEUMBIGCgmS
# JomT8ixkARkWBHNpc2UxGTAXBgoJkiaJk/IsZAEZFgludHNlcnZlcjIxIzAhBgNV
# BAMTGkFTIFRhbGxpbm5hIFZlc2kgT25saW5lIENBAhMtAAAC9kElWyJKcdrfAAAA
# AAL2MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMCMGCSqGSIb3DQEJBDEWBBScR5l3LL8Z4+rXZgFNe0o2atjYqTANBgkqhkiG
# 9w0BAQEFAASCAQBx96scsMWpiXF3fuO20yzRd25UR7QHnNmzID8fgKneDwScrwr4
# FOwqcjjFMXiRGC3knGVSxN8KtnNChjpmzT7hF40Z3t8OrgZk3CxgXlCLYrUGrr98
# 1Iz38Aa1Qgbisn/U0OoFPqP/oHF2eluOtWLE5k6t7S05agyGgit3BYsw6tMKU0Fy
# 3fhJtO6sFoUvOvJZH/OzflA3jOLdp9u0XJfPsFx1zA4werIfTC1HFK/t3RZgw3Pt
# 8cB4TEXkOaXJdJ+1vJ+5+bpBHwx4m7PjGDL3ZydDqWFDcgveD9NsPa26ijqDqYP9
# M+MqlA6cSf52AEMTTXUngS/RSg8HYVrZmpxq
# SIG # End signature block
