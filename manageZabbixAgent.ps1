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


# Load zabbix module
if (Get-Module -Name psbbix) {
    Write-Host "Module loaded"
} else {
    Write-Host "Module not loaded, loading"

    # Load module
    if ($modulePath -ne "" -and (Test-Path $modulePath)) {
        Write-Host "Module exist"
        import-module $modulePath
    } elseif (Get-Module -ListAvailable -Name psbbix) {
        Write-Host "Module exist"
        import-module psbbix
    } else {
        Write-Error "Cannot load module, cannot find module psbbix!"
        exit 1
    }
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


# Get local machine information
$computername = $env:COMPUTERNAME

$ipdata = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | ? {$_.DefaultIPGateway -ne $null } | select IPAddress,DNSDomain
$ip = $ipdata.IPAddress

$dnsdomain = $ipdata.DNSDomain

#$ip
#$dnsdomain



$objIPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()

$fqdn = $(
    if (($objIPProperties.DomainName -eq $null)) {
    "{0}" -f $objIPProperties.HostName
    }
    else {
    "{0}.{1}" -f $objIPProperties.HostName, $objIPProperties.DomainName
    }
)

write-host $fqdn2 -ForegroundColor Yellow

# Now check if host is regiestered in zabbix server. We do so by looking for dns name of host in zabbix hosts interfaces.

New-ZabbixSession -PSCredential $cred -IPAddress zabbix02.ntserver2.sise

$zabbixhosts = Get-ZabbixHost @zabSessionParams  | select host, 
    @{Name="dns"; Expression={$_.Interfaces.dns}}, 
    @{Name="useip"; Expression={$_.Interfaces.useip}},
    @{Name="ip"; Expression={$_.Interfaces.ip}},
    @{Name="port"; Expression={$_.Interfaces.port}},
    @{Name="interfaceid"; Expression={$_.Interfaces.interfaceid}}

$hostbyfqdn = $zabbixhosts | ? {$_.port -match 10050} | ? {$_.useip -match 0} | ? {$_.dns -eq $fqdn} | select host

$hostbycomputername = $zabbixhosts | ? {$_.port -match 10050} | ? {$_.useip -match 0} | ? {$_.dns -eq $computername } | select host

$hostbyip = $zabbixhosts | ? {$_.port -match 10050} | ? {$_.useip -match 0} | ? {$_.ip -eq $ip} |  select host

$agentname = $null


# check 
if ($hostbyfqdn.host -ne $null) { $agentname = $hostbyfqdn.host }
if ($hostbycomputername.host -ne $null) {          
    
    if ( ($agentname -ne $null) -and ($hostbycomputername.host -ne $agentname) ) {
        
        Write-Error "Multiple names matched! Please install Zabbix agent manually a"
        exit 1
    }
    $agentname = $hostbycomputername.host
}



if ($hostbyip.host -ne $null) {
    if (($agentname -ne $null) -and  ($hostbyip.host -ne $agentname)) {
        Write-Error "Multiple names matched! Please install Zabbix agent manually b"
        exit 1
    }
    $agentname = $hostbyip.host
}

write-host "Found zabbix host: $agentname" -f Yellow


function installed_ZabbixAgentExecutablePath {
    $installpath = Get-WmiObject win32_service | ?{$_.Name -like '*Zabbix Agent*'} | select Name, DisplayName, @{Name="Path"; Expression={$_.PathName.split('"')[1]}} 
    if ($installpath -eq $null) {
       return
    }
    $installpath.Path
}


function installed_ZabbixAgentVersion {

    #http://stackoverflow.com/questions/8761888/powershell-capturing-standard-out-and-error-with-start-process

    $installpath = installed_ZabbixAgentExecutablePath
    write-verbose "Zabbix Agent path $installpath" 

    $version = $null

    if ($installpath -ne $null) {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $installpath
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = "-t agent.version"
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $p.WaitForExit()
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()

        if ($p.ExitCode -ne 0) {
            write-host "Error occured when executing $installpath"
            Write-Host $stderr -ForegroundColor Red
            return $null
        }

        if ($stdout.Contains("agent.version")) {
            $version = $stdout.Split("|")[1].Split("]")[0]    
        }        
    }
    return $version

}


function stop_ZabbixAgent {
    $installpath = installed_ZabbixAgentExecutablePath
    if ($installpath -ne $null) {
        Start-Process -FilePath $installpath -ArgumentList "-x" -NoNewWindow
        Start-Sleep -Seconds 2
    }

}

function uninstall_ZabbixAgent {

    stop_ZabbixAgent

    $installpath = installed_ZabbixAgentExecutablePath
    if ($installpath -ne $null) {
        Start-Process -FilePath $installpath -ArgumentList "-d" -NoNewWindow
        Start-Sleep -Seconds 2
    }
   
}



$izv = installed_ZabbixAgentVersion

if ($izv -eq $null) {
  write-host "Zabbix Agent not installed!"
} else {
  Write-Host "Zabbix agent installed: $izv"
}



