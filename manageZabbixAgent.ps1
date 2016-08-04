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
    

    # If no aggent name is given, then we need to retrieve it.
    if ($ZabbixAgentName -eq $null -or $ZabbixAgentName -eq "") {

        # credidentials
        # http://stackoverflow.com/questions/6239647/using-powershell-credentials-without-being-prompted-for-a-password
        $cred = $null

        if ($PSCredential -ne $null) {
            Write-Verbose "Using provided Creditentials"
            $cred = $PSCredential

        } else {
            $spassword = $null

            if  ($passwordFilePath -ne $null -and $passwordFilePath -ne "" )  {
                if (-not (Test-Path $passwordFilePath))  {
                    throw "Could not find file $passwordFilePath"
                    exit 1
                }
                Try {
                   $spassword = cat $passwordFilePath | convertto-securestring -ErrorAction Stop
                }
                Catch {
                    
                    throw "Cannot proceed without opening password file. Create one using read-host -assecurestring | convertfrom-securestring | out-file filename"                    
                } 
        
            } else {
                if ($Password -ne $null -and $Password -ne "") {
                    $spassword = ConvertTo-SecureString $Password -AsPlainText -Force
                } else {
                    throw "Either -PSCredential or (-Username and -Password | -PasswordFilePath ) must be specified!"                    
                }
            }

            if ($Username -eq "") {
                throw "Either -PSCredential or (-Username and -Password | -passwordFilePath ) must be specified!"                
            }
    
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Username, $spassword


        }

        New-ZabbixSession -PSCredential $cred -IPAddress $ZabbixHost 
        $ZabbixAgentName = Get-ZabbixAgentHostname @zabSessionParams

    } 

    if ($ZabbixAgentName -eq $null -or $ZabbixAgentName -eq "") {
        throw "Unable to determine ZabbixAgentName."
    }

    Install-ZabbixAgent -zabbixHost $ZabbixHost -zabbixDir $ZabbixDir -zabbixInstallDir $ZabbixInstallDir -zabbixAgentName $ZabbixAgentName -Upgrade

}
