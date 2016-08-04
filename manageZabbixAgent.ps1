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
Param(
  [Parameter(Mandatory=$True)][String]$zabbixHost,
  [Parameter(Mandatory=$True)][String]$zabbixDir,
  [Parameter(Mandatory=$True)][String]$zabbixInstallDir,
  [string]$modulePath,
  [string]$Username, 
  [string]$passwordFilePath, 
  [string]$Password, 
  [System.Management.Automation.PSCredential]$PSCredential
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

if ($false -eq (Import-Module-pssbix -modulePath $modulePath)) {
    write-error "Could not load psbbix module. Exiting"
    exit 1
}

# credidentials
# http://stackoverflow.com/questions/6239647/using-powershell-credentials-without-being-prompted-for-a-password

$cred = $null

if ($PSCredential -ne $null) {
    
    write-host "Using provided Creditentials"
    $cred = $PSCredential

} else {
    $spassword = $null

    if  ($passwordFilePath -ne "" )  {
        if (-not (Test-Path $passwordFilePath))  {
            Write-Error "Could not find file $passwordFilePath"
            exit 1
        }
        Try {
           $spassword = cat $passwordFilePath | convertto-securestring -ErrorAction Stop
        }
        Catch {
            Write-Error "Secure seting can only be opened by account that created it!"
            write-error "Cannot proceed without opening password file. Create one using read-host -assecurestring | convertfrom-securestring | out-file filename"
            exit 1
        } 
        
    } else {
        if ($Password -ne "") {
            $spassword = ConvertTo-SecureString $Password -AsPlainText -Force
        } else {
            Write-Error "Either -PSCredential or (-Username and -Password | -passwordFilePath ) must be specified!"
            exit
        }
    }

    if ($Username -eq "") {
        Write-Error "Either -PSCredential or (-Username and -Password | -passwordFilePath ) must be specified!"
        exit
    }
    
    $cred = new-object -typename System.Management.Automation.PSCredential `
         -argumentlist $Username, $spassword
}


# Now check if host is regiestered in zabbix server. We do so by looking for dns name of host in zabbix hosts interfaces.

New-ZabbixSession -PSCredential $cred -IPAddress $zabbixHost
$agentname = Get-ZabbixAgentHostname @zabSessionParams

write-host "Found zabbix host: $agentname" -f Yellow




$izv = Get-ZabbixAgentVersion

if ($izv -eq $null) {
  write-host "Zabbix Agent not installed!"
} else {
  Write-Host "Zabbix agent installed: $izv"
}



