# Load additional libraries
Push-Location $psScriptRoot
. .\epoch-time-convert.ps1
. .\zabbix-db-size-calc.ps1
Pop-Location

function Remove-EmptyLines {
	<#
	.Synopsis
		Remove empty lines from file, string or variable
	.Description
		Remove empty lines from file, string or variable
	.Example
		Remove-EmptyLines -in (gc c:\file.txt)
	.Example
		$var | Remove-EmptyLines
	.Example
		help -ex Remove-EmptyLines | Remove-EmptyLines 
	.Example
		gc c:\*.txt | rmel
	.Example
		Get-ClipBoard | rmel
	.Example
		dir | oss | rmel
	#>
	
	[cmdletbinding()]
    [Alias("rmel")]
    param ([Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true)][array]$in)
	
	process {
		if (!$psboundparameters.count) {
			help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines
			return
		}
		
		$in.split("`r`n") | ? {$_.trim() -ne ""}
	}
}

Function Write-MissingParamsMessage {
	Write-Host "`nMissing parameters!`n" -f red
	sleep 1
	Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines
}

Function Get-ZabbixHelp {
	<# 
	.Synopsis
		Get fast help for most useful examples for every function with no empty lines
	.Description
		Get fast help for most useful examples for every function with no empty lines
	.Example
		Get-ZabbixHelp -list
		Get list of all module functions, like gcm -module psbbix
	.Example
		Get-ZabbixHelp -alias
		Get list of all aliases in the module
	.Example
		gzh host
		Get examples for all zabbixhost commands
	.Example
		gzh hostinterface -p interface
		Get all examples for Get/Set/New/Remove-ZabbixHostInterface with pattern "interface"
	.Example
		gzh hostinterface -p interface -short
		Get all examples for Get/Set/New/Remove-ZabbixHostInterface with pattern "interface", print only matches
	.Example
		gzh host -p "copy|clone" -short
		Get examples with copy or clone 
	.Example
		gzh -zverb set
		Get examples of all Set commands
	.Example
        gzh -zverb get
        Get examples of all Get commands
	.Example
		gzh -zverb get hostinterface 
		Get examples for Get-ZabbixHostInterface
    .Example
		gzh user set
		Get examples for Set-ZabbixUser
    .Example
		gzh host -p step
		Find step by step guides
    .Example
		gzh item -p "cassandra|entropy"
		Get help for cassandra items if you're using my cassandra cluster template
	#>
    
    [CmdletBinding()]
    [Alias("gzh")]
    Param ($znoun,$zverb,[switch]$list,$pattern,[switch]$short,[switch]$alias)
    
	if (!(get-module "Find-String")) {Write-Host "`nInstall module Find-String from Powershell Gallery: install-module find-string -force. Unless this function won't work properly.`n" -f yellow; return }
	if (!$psboundparameters.count) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines; return}

    if ($list) {dir function:\*-zabbix* | select name | sort name}
	elseif ($alias) {gcm -Module psbbix | %{gal -Definition $_.name -ea 0}}
    elseif (!$znoun -and $pattern -and $short) {gzh | %{foreach ($i in $_) {$i | Select-String -Pattern $pattern -AllMatches | Out-ColorMatchInfo -onlyShowMatches}}}
    elseif (!$znoun -and $pattern -and !$short) {gzh | out-string | Select-String -Pattern $pattern -AllMatches | Out-ColorMatchInfo -onlyShowMatches}
    elseif ($znoun -and $pattern -and !$short) {gzh $znoun | out-string | Select-String -Pattern $pattern -AllMatches | Out-ColorMatchInfo -onlyShowMatches}
    elseif ($znoun -and $pattern -and $short) {gzh $znoun | %{foreach ($i in $_) {$i | Select-String -Pattern $pattern -AllMatches | Out-ColorMatchInfo -onlyShowMatches}}}
    elseif ($zverb -and !$znoun) {dir function:\$zverb-zabbix* | %{write-host $_.Name -f yellow; get-help -ex $_.Name | out-string | Remove-EmptyLines}}
    elseif ($znoun -and !$zverb) {dir function:\*zabbix$znoun | %{write-host $_.Name -f yellow; get-help -ex $_.Name | out-string | Remove-EmptyLines}}
    elseif ($zverb -and $znoun) {dir function:\$zverb-zabbix$znoun | %{write-host $_.Name -f yellow; get-help -ex $_.Name | out-string | Remove-EmptyLines}}
    else {dir function:\*zabbix* | %{write-host $_.Name -f yellow; get-help -ex $_.Name | out-string | Remove-EmptyLines}}
}

Function New-ZabbixSession {
	<# 
	.Synopsis
		Create new Zabbix session
	.Description
		Create new Zabbix session
	.Parameter PSCredential
		Credential
	.Parameter IPAddress
		Accept IP address or domain name
	.Parameter noSSL
		Connect to Zabbix server with plain http
	.Example
		New-ZabbixSession 10.10.10.10
		Connect to Zabbix server
	.Example
		Connect-Zabbix 10.10.10.10
		Connect to Zabbix server
	.Example
		Connect-Zabbix -IPAddress 10.10.10.10 -noSSL
		Connect to Zabbix server with noSSL (http)
	.Example
		Connect-Zabbix -User admin -Password zabbix -IPAddress zabbix.domain.net
		Connect to Zabbix server
	.Example
		Connect-Zabbix -IPAddress zabbix.domain.net -URLCustomPath ""
		Connect to Zabbix server with custom frontend install https://zabbix.domain.net, instead of default https://zabbix.domain.net/zabbix
	#>
    
	[CmdletBinding()]
    [Alias("Connect-Zabbix","czab")]
	Param (
        [Parameter(Mandatory=$True)][string]$IPAddress,
		[Parameter(Mandatory=$True)][PSCredential]$PSCredential,
		[Parameter(Mandatory=$False)]$URLCustomPath="zabbix",
        [Switch]$useSSL,
		[switch]$noSSL
    )
    
	# if (!$psboundparameters.count) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines; return}

	$Body = @{
	    jsonrpc = "2.0"
	    method = "user.login"
	    params = @{
		    user = $PSCredential.UserName
		    password = $PSCredential.GetNetworkCredential().Password
	    }
	    id = 1
	    auth = $null
    }

    $BodyJSON = ConvertTo-Json $Body
	write-verbose $BodyJSON
	if ($PSVersionTable.PSEdition -ne "core") {
		if (!(test-connection $IPAddress -Quiet -Count 1)) {write-host "$IPAddress is not available.`n" -f red; return}
	}
    
	if ($noSSL) {
		write-warning "You're going to connect via insecure HTTP protocol. Consider to use HTTPS."
		$Protocol="http"
	}
	elseif ($useSSL) {
		$Protocol="https"
	}	
	else {
		$Protocol="https"
	}
	
    # $URL = $Protocol+"://$IPAddress/zabbix"
    $URL = $Protocol+"://$IPAddress/$URLCustomPath"
    try {
		if (!$global:zabSession -or !$global:zabSession.session) {
		$global:zabSession=Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post |
			Select-Object jsonrpc,@{Name="session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
	   }
    }
    catch {
		# [void]::$_
		if ($_.exception -match "Unable to connect to the remote server") {write-host "`nNot connected! ERROR: $_`n" -f red; write-verbose $_.exception; return}
		else { 
			write-host "`nSeems SSL certificate is self signed. Trying with no SSL validation..." -f yellow
			if (($PSVersionTable.PSEdition -eq "core") -and !($PSDefaultParameterValues.keys -eq "Invoke-RestMethod:SkipCertificateCheck")) {$PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)}
			else {
				write-host "`nWARNING: `nNo SSL validation setting in Windows Powershell is session wide.`nAs a result in this powershell session Invoke-Webrequest and Invoke-RestMethod may not work with regular websites: ex. iwr google.com`nUse new Powershell session for this purpose.`n" -f yellow
				[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
			}
			$global:zabSession=Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post |
				Select-Object jsonrpc,@{Name="session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
		}
    } 
	
    if ($zabSession.session) {
		$global:zabSessionParams = [ordered]@{jsonrpc=$zabSession.jsonrpc;session=$zabSession.session;id=$zabSession.id;url=$zabSession.URL}
		write-host "`nConnected to $IPAddress." -f green
        write-host "Zabbix Server version: " -f green -nonewline
        Get-ZabbixVersion
        ""
		write-host 'Usage: Get-ZabbixHelp -list' -f yellow
		write-host 'Usage: Get-ZabbixHelp -alias' -f yellow
        ""
	} 
	else {
		write-host "`nERROR: Not connected. Try again." -f red; $zabsession
		if ($PSCredential.UserName -match "@|\\") {write-warning "`nYou have used domain user name format $($PSCredential.UserName). `nThis is not always supported in Zabbix configuration. Please ask your Zabbix admin for help.`n`n"}
	}
}

Function Get-ZabbixSession {
	<# 
	.Synopsis
		Get Zabbix session
	.Description
		Get Zabbix session
	.Example
		Get-ZabbixSession
		Get Zabbix session
	.Example
		Get-ZabbixConnection
		Get Zabbix session
	#>
	
	[CmdletBinding()]
    [Alias("Get-ZabbixConnection","gzconn","gzsess")]
    param ()
	
    if (!($global:zabSession -and $global:zabSessionParams)) {
        write-host "`nDisconnected form Zabbix Server!`n" -f red; return
    }
    elseif ($global:zabSession -and $global:zabSessionParams -and !($ZabbixVersion=Get-ZabbixVersion)) {
		write-host "`nZabbix session params are OK (use -verbose for details). Check whether Zabbix Server is online. In case of certificate error try new powershell session.`n" -f red; write-verbose "$($zabSession | select *)"; return	
	}
	elseif ($global:zabSession -and $global:zabSessionParams -and ($ZabbixVersion=Get-ZabbixVersion)) {
		$zabSession | select *, @{n="ZabbixVer";e={$ZabbixVersion}}
    }
	else {write-host "`nDisconnected form Zabbix Server!`n" -f red; return}
}

Function Remove-ZabbixSession {
	<# 
	.Synopsis
		Remove Zabbix session
	.Description
		Remove Zabbix session
	.Example
		Disconnect-Zabbix
		Disconnect from Zabbix server
	.Example
		Remove-Zabbixsession
		Disconnect from Zabbix server
	#>
	
	[CmdletBinding()]
    [Alias("Disconnect-Zabbix","rzsess","dzsess")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )

	# if (!$psboundparameters.count -and !$global:zabSessionParams) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines; return}
	if (!$psboundparameters.count -and !$global:zabSessionParams) {Write-Host "`nDisconnected from Zabbix Server!`n" -f red; return}

	if (Get-ZabbixSession) {
		$Body = @{
			method = "user.logout"
			jsonrpc = $jsonrpc
			params = @{}
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result | out-null} else {$a.error}
		
		$global:zabSession = ""
		$global:zabSessionParams = ""
		
		if (!(Get-ZabbixVersion)) {}
	}
	else {Get-ZabbixSession}
}

Function Get-ZabbixVersion {
	<# 
	.Synopsis
		Get Zabbix server version
	.Description
		Get Zabbix server version
	.Example
		Get-ZabbixVersion
		Get Zabbix server version
	.Example
		Get-ZabbixVersion
		Get Zabbix server version
	#>
    
	[CmdletBinding()]
	[Alias("gzver")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$params=@(),
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	if (!($global:zabSession -or $global:zabSessionParams)) {write-host "`nDisconnected from Zabbix Server!`n" -f red; return}
	else {
		$Body = @{
			method = "apiinfo.version"
			jsonrpc = $jsonrpc
			id = $id
			params = $params
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {return $a.result} else {$a.error}
		}
		catch {Write-Host "`nERROR: $_." -f red}
	}
}

Function Get-ZabbixHost {
	<# 
	.Synopsis
		Get hosts
	.Description
		Get hosts
	.Parameter HostName
		To filter by HostName of the host (case sensitive)
	.Parameter HostID
		To filter by HostID of the host
	.Example
		Get-ZabbixHost
		Get all hosts
	.Example  
		Get-ZabbixHost -HostName SomeHost
		Get host by name (case sensitive)
	.Example
		Get-ZabbixHost | ? name -match host | select hostid,host,status,available,httptests
		Get host(s) by name match (case insensitive)
    .Example
        Get-ZabbixHost | ? name -match host | select -ExpandProperty interfaces -Property name | sort name
        Get hosts' interfaces by host name match (case insensitive)        
	.Example
		Get-ZabbixHost  | ? name -match host | Get-ZabbixTemplate | select templateid,name -Unique
		Get templates by name match (case insensitive)
	.Example
		Get-ZabbixHost | ? status -eq 1 | select hostid,name
		Get only disabled hosts
	.Example
		Get-ZabbixHost -sortby name | ? name -match host | select hostid,host,status -ExpandProperty httptests
		Get host(s) by name match (case insensitive), sort by name. Possible values are: hostid, host, name (default), status
	.Example
		Get-ZabbixHost | ? name -match HostName | select name,*error* | ft -a
		Get all errors for hosts
	.Example
		Get-ZabbixHost | ? name -match HostName | select name,*jmx* | ft -a
		Get info regarding JMX connections for hosts
	.Example
		Get-ZabbixHost | ? name -match "" | ? jmx_available -match 1 | select hostid,name,jmx_available
		Get host(s) with JMX interface(s) active
	.Example
		Get-ZabbixHost | ? parentTemplates -match "jmx" | select hostid,name,available,jmx_available
		Get host(s) with JMX Templates and get their connection status
	.Example
		Get-ZabbixHost | ? status -eq 0 | ? available -eq 0 | select hostid,name,status,available,jmx_available | ft -a
		Get hosts, which are enabled, but unreachable
	.Example
		Get-ZabbixHost -GroupID (Get-ZabbixGroup -GroupName "groupName").groupid | ? httpTests | select hostid,host,status,available,httptests | sort host | ft -a
		Get host(s) by host group, match name "GroupName" (case sensitive)
	.Example
		Get-ZabbixHost -hostname HostName | Get-ZabbixItem -WebItems -ItemKey web.test.error -ea silent | select name,key_,lastclock
		Get web tests items for the host (HostName is case sensitive)
	.Example
		(Get-ZabbixHost | ? name -match host).parentTemplates.name
		Get templates, linked to the host by hostname match (case insensitive) 
	.Example
		Get-ZabbixHost | ? name -match hostName | select host -ExpandProperty parentTemplates
		Get templates, linked to the host(s)
	.Example
		Get-ZabbixHost | ? parentTemplates -match "jmx" | select name -Unique
		Get hosts with templates, by template name match
	.Example
		Get-ZabbixHost -HostName HostName | Get-ZabbixItem -WebItems -ItemKey web.test.error -ea silent | select name,key_,@{n='lastclock';e={convertFrom-epoch $_.lastclock}}
		Get Items for the host. Item lastclock (last time it happened in UTC)
	.Example
		Get-ZabbixHost -hostname HostName | Get-ZabbixHttpTest -ea silent | select httptestid,name,steps
		Get host (case sensitive) and it's HttpTests
    .Example
        Get-ZabbixHost -hostname HostName | Get-ZabbixHttpTest -ea silent | select -ExpandProperty steps | ft -a
        Get host (case sensitive) and it's HttpTests
    .Example
        Get-ZabbixHost | ? name -match hostName | select host -ExpandProperty interfaces | ? port -match 10050
        Get interfaces for the host(s)    
    .Example
		Get-ZabbixHost | ? name -match hostname | Get-ZabbixHostInterface | ? port -match 10050 | ft -a
		Get interfaces for the host(s)	
	.Example
		Get-ZabbixHost | ? name -match hostsName | %{$n=$_.name; Get-ZabbixHostInterface -HostID $_.hostid} | select @{n="name";e={$n}},hostid,interfaceid,ip,port | sort name | ft -a
		Get interface(s) for the host(s)
	#>
	
	[CmdletBinding()]
	[Alias("gzhst")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)]$HostName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HttpTestID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$SortBy="name",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}
		# if (!$psboundparameters.count -and !$global:zabSessionParams) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "host.get"
			params = @{
				output = "extend"
				selectGroups = @(
					"groupid",
					"name"
				)
				selectParentTemplates = @(
					"templateid",
					"name"
				)
				selectInterfaces = @(
					"interfaceid",
					"ip",
					"port"
				)
				selectHttpTests = @(
					"httptestid",
					"name",
					"steps"
				)
				selectTriggers = @(
					"triggerid",
					"description"
				)
				selectApplications = @(
					"applicationid"
					"name"
				)
				selectGraphs = @(
					"graphid"
					"name"
				)
				selectMacros = @(
					"hostmacroid"
					"macro"
					"value"
				)
				selectScreens = @(
					"screenid"
					"name"
				)
				selectInventory = @(
					"name"
					"type"
					"os"
				)
				hostids = $HostID
				groupids = $GroupID
				httptestid = $HttpTestID
				filter = @{
					host = $HostName
				}
				sortfield = $SortBy
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixHost {
	<# 
	.Synopsis
		Set/update host settings
	.Description
		Set/update host settings
	.Parameter HostID
		HostID
	.Parameter HostName
		Host name
	.Parameter HostVisibleName
		Host visible name: Default: host property value
	.Parameter HostDescription
		Description of the host
	.Parameter status
		Status and function of the host: Possible values are: 0 - (default) monitored host; 1 - unmonitored host
	.Parameter InventoryMode
		InventoryMode: Possible values are: -1 - disabled; 0 - (default) manual; 1 - automatic
	.Parameter IpmiAuthtype
		IPMI: IpmiAuthtype: IPMI authentication algorithm: Possible values are: -1 - (default) default; 0 - none; 1 - MD2; 2 - MD5 4 - straight; 5 - OEM; 6 - RMCP+
	.Parameter IpmiUsername
		IPMI: IpmiUsername: IPMI username
	.Parameter IpmiPassword
		IPMI: IpmiPassword: IPMI password
	.Parameter IpmiPrivilege
		IPMI: IpmiPrivilege: IPMI privilege level: Possible values are: 1 - callback; 2 - (default) user; 3 - operator; 4 - admin; 5 - OEM
	.Parameter GroupID
		GroupID of host group
	.Example
		Get-ZabbixHost | ? name -eq "host" | Set-ZabbixHost -status 0
		Enable host (-status 0)
	.Example
		(1..9) | %{(Get-ZabbixHost | ? name -eq "host0$_") | Set-ZabbixHost -status 1}
		Disable multiple hosts (-status 1)
	.Example
		Get-ZabbixHost | ? name -match "hostName" | Set-ZabbixHost -status 0
		Enable multiple hosts
	.Example
		Get-ZabbixHost | ? name -match hostName | Set-ZabbixHost -GroupID 14,16 -status 0
		Set HostGroups for the host(s) and enable it
	.Example
		Get-ZabbixHost | ? name -eq hostName | Set-ZabbixHost -removeTemplates -WhatIf
		WhatIf on delete and clear of all templates from the host
	.Example
		Get-ZabbixHost | ? name -eq hostName | Set-ZabbixHost -removeTemplates
		Remove and clear all linked templates from the host
	.Example
		Get-ZabbixHost | ? name -eq hostName | Set-ZabbixHost -TemplateID (Get-ZabbixTemplate | ? name -eq "TemplateFromCurrentHost").templateid
		Replace linked templates on the host with new ones (not clear the old ones)
	.Example
		Get-ZabbixHost | ? name -eq hostName | Set-ZabbixHost -removeTemplates -TemplateID (Get-ZabbixTemplate | ? name -eq "TemplateFromCurrentHost").templateid -WhatIf
		WhatIf on remove and clear linked templates from the host
	.Example
		Get-ZabbixHost -HostName HostName | Set-ZabbixHost -removeTemplates -TemplateID (Get-ZabbixHost -HostName "HostName").parentTemplates.templateid
		Unlink(remove) and clear templates from the host (case sensitive)
	.Example
		$templateID=(Get-ZabbixTemplate -HostID (Get-ZabbixHost | ? name -match hostname).hostid).templateid
		Store existing templateIDs
		$templateID+=(Get-ZabbixTemplate | ? name -match "newTemplate").templateid
		Add new templateIDs
		Get-ZabbixHost | ? name -match hosts | Set-ZabbixHost -TemplateID $templateID 
		Link(add) additional template(s) to already existing ones, step by step
	.Example
		$templateID=((Get-ZabbixHost | ? name -eq hostName).parentTemplates.templateid)+((Get-ZabbixTemplate | ? name -match mysql).templateid)
		Get-ZabbixHost | ? name -ew hostName | Set-ZabbixHost -TemplateID $templateID 
		Add new template to existing ones (not replace)
	.Example
		Get-ZabbixHost -HostName HostName | Set-ZabbixHost -TemplateID (Get-ZabbixHost -HostName SourceHost).parentTemplates.templateid
		Link(replace existing) new templates to the host, according config of other host (case sensitive)
	.Example
		(1..9) | %{Get-ZabbixHost -HostName "Host0$_" | Set-ZabbixHost -TemplateID ((Get-ZabbixHost | ? name -match "sourcehost").parenttemplates.templateid)}
		Link(replace existing) new templates to multiple hosts, according config of the other host
	#>	 
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("szhst")]
	Param (
        [Alias("host")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostName,
		# Visible name of the host. Default: host property value.
		[Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostVisibleName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$GroupID,
        [Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$groups,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$interfaceID,
        [Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$interfaces,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$TemplateID,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$parentTemplates,
		# [Alias("parentTemplates")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$templates,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$templates,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]$Inventory,
		[Alias("description")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostDescription,
		# Host inventory population mode: Possible values are: -1 - disabled; 0 - (default) manual; 1 - automatic.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$InventoryMode,
		# IPMI authentication algorithm: Possible values are: -1 - (default) default; 0 - none; 1 - MD2; 2 - MD5; 4 - straight; 5 - OEM; 6 - RMCP+
		[Alias("ipmi_authtype")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$IpmiAuthtype,
		[Alias("ipmi_username")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$IpmiUsername,
		[Alias("ipmi_password")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$IpmiPassword,
		# IPMI privilege level: Possible values are: 1 - callback; 2 - (default) user; 3 - operator; 4 - admin; 5 - OEM.
		[Alias("ipmi_privilege")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$IpmiPrivilege,
		# [array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$HttpTestID,
		# Status and function of the host: Possible values are: 0 - (default) monitored host; 1 - unmonitored host
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$ProxyHostID,
		[switch]$removeTemplates,

		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		if ($TemplateID -eq 0) {$TemplateID=""}

		# if ($TemplateID.count -gt 9) {write-host "`nOnly up to 5 templates are allowed." -f red -b yellow; return}
		for ($i=0; $i -lt $TemplateID.length; $i++) {[array]$tmpl+=$(@{templateid = $($TemplateID[$i])})}
		for ($i=0; $i -lt $GroupID.length; $i++) {[array]$grp+=$(@{groupid = $($GroupID[$i])})}
		for ($i=0; $i -lt $interfaceID.length; $i++) {[array]$ifc+=$(@{interfaceid = $($interfaceID[$i])})}
		
		$Body = @{
			method = "host.update"
			params = @{
				hostid = $HostID
				status = $status
				host = $HostName
				name = $HostVisibleName
				ipmi_authtype = $IpmiAuthtype
				ipmi_username = $IpmiUsername
				ipmi_password = $IpmiPassword
				ipmi_privilege = $IpmiPrivilege
				description = $HostDescription
				inventory_mode = $InventoryMode
				proxy_hostid = $ProxyHostID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if (!$TemplateID -and $removeTemplates) {$Body.params.templates_clear=$parentTemplates | select templateid}
		if ($TemplateID -and $removeTemplates) {$Body.params.templates_clear=$tmpl | ?{$_}}
		if ($TemplateID -and !$removeTemplates) {$Body.params.templates=$tmpl | ?{$_}}
		# if (!($TemplateID -and $removeTemplates)) {$Body.params.parenttemplates=$parentTemplates}
		if ($GroupID) {$Body.params.groups=$grp} else {$Body.params.groups=$groups}
		if ($interfaceID) {$Body.params.interfaces=$ifc} else {$Body.params.interfaces=($interfaces)}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		if (!$removeTemplates) {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		}
		elseif ($removeTemplates -and !$TemplateID) {
			if ([bool]$WhatIfPreference.IsPresent) {}
			if ($PSCmdlet.ShouldProcess((($parentTemplates).name -join ", "),"Unlink and clear templates from the host")) {  
				$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
				if ($a.result) {$a.result} else {$a.error}
			}
		}
		elseif ($removeTemplates -and $TemplateID) {
			if ([bool]$WhatIfPreference.IsPresent) {}
			if ($PSCmdlet.ShouldProcess(($parentTemplates | ? templateid -match (($tmpl).templateid -join "|")).name,"Unlink and clear templates")) {  
				$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
				if ($a.result) {$a.result} else {$a.error}
			}
		}
		
	}
}

Function New-ZabbixHost {
	<# 
	.Synopsis
		Create new host
	.Description
		Create new host
	.Parameter HostName
		HostName of the host as it will appear in zabbix
	.Parameter IP
		IP address of the host
	.Parameter DNSName
		Domain name of the host
	.Parameter Port
		Port to connect to the host (default 10050)
	.Parameter GroupID
		ID of the group host will belong to
	.Parameter TemplateID
		ID/IDs of the templates to link to the host
	.Parameter MonitorByDNSName
		If used, domain name of the host will used to connect
	.Example
		New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -GroupID 8,14 -TemplateID "10081","10166"
		Create new host (case sensitive), with two linked Templates and member of two HostGroups	
	.Example
		New-ZabbixHost -HostName hostName -IP 10.20.10.10 -TemplateID (Get-ZabbixTemplate | ? name -eq "Template OS Windows").templateid -GroupID (Get-ZabbixGroup | ? name -eq "HostGroup").groupid -status 1
		Create new host (case sensitive), with one linked Template, member of one HostGroup and disabled (-status 1)
	.Example
		New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -TemplateID ((Get-ZabbixTemplate | ? name -match "Template OS Windows|Template OS Windows - Ext") -notmatch "Template OS Windows - Backup").templateid -GroupID (Get-ZabbixHostGroup | ? name -match "HostGroup1|HostGroup2").groupid -status 1 
		Create new host (case sensitive), with two linked Templates, member of two HostGroups and disabled (-status 1)
	.Example
		New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID (Get-ZabbixHost | ? name -match "host").parentTemplates.templateid -status 0
		Create new host (case sensitive), with multiple attached Templates and enable it (-status 0)
	.Example
		New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID (Get-ZabbixHost | ? name -match "host").parentTemplates.templateid -status 1
		Create new host (case sensitive), with multiple attached Templates and leave it disabled (-status 1)
	.Example
		New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -TemplateID ((Get-ZabbixTemplate | ? name -match "Template OS Windows") -notmatch "Template OS Windows - Backup").templateid -verbose -GroupID (Get-ZabbixGroup | ? name -match "HostGroup1|HostGroup2").groupid -status 1 -DNSName NewHost.example.com -MonitorByDNSName
		Create new host with FQDN and set monitoring according DNS and not IP
	.Example
		Import-Csv c:\new-servers.csv | %{New-ZabbixHost -HostName $_.$Hostname -IP $_.IP -TemplateID "10081","10166" -GroupID 8,14}
		Mass create new hosts
	.Example
		Import-Csv c:\new-servers.csv | %{New-ZabbixHost -HostName $_.Hostname -IP $_.IP -GroupID $_.GroupID -TemplateID $_.TemplateID -status $_.status}
		Mass create new hosts
	.Example
		New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -GroupID (Get-ZabbixHost | ? name -eq "SourceHost").groups.groupid -TemplateID (Get-ZabbixHost | ? name -eq "SourceHost" | Get-ZabbixTemplate | ? name -match os).templateid -status 1 -verbose 
		Clone HostGroups and Templates from other host
	.Example
		Get-ZabbixHost | ? name -match SourceHost | New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -status 1
		Partially clone host (templates and groups will be copied from the source host)
	.Example
		Get-ZabbixHost | ? name -eq SourceHost | Get-ZabbixApplication | New-ZabbixApplication -HostID (Get-ZabbixHost | ? name -match newHost).hostid
		Clone Application(s) from host to host
	#>
	
	[CmdletBinding()]
	[Alias("nzhst")]
	Param (
        [Parameter(Mandatory=$True)][string]$HostName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][string]$IP,
		[string]$DNSName,
		[Switch]$MonitorByDNSName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Port = 10050,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$ProxyHostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$templates,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$interfaces,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$parentTemplates,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URL=($global:zabSessionParams.url)
    )

    process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}
		# if (!$psboundparameters.count -and !$global:zabSessionParams) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		Switch ($MonitorByDNSName.IsPresent) {
			$False {$ByDNSName = 1} # = ByIP
			$True {$ByDNSName = 0} # = ByDomainName
		}
		
		for ($i=0; $i -lt $TemplateID.length; $i++) {[array]$tmpl+=$(@{templateid = $($TemplateID[$i])})}
		for ($i=0; $i -lt $GroupID.length; $i++) {[array]$grp+=$(@{groupid = $($GroupID[$i])})}
		
		$Body = @{
			method = "host.create"
			params = @{
				host = $HostName
				interfaces = @{
					type = 1
					main = 1
					useip = $ByDNSName
					ip = $IP
					dns = $DNSName
					port = $Port
				}
				status = $Status
				proxy_hostid = $ProxyHostID
			}
			
			jsonrpc = $jsonrpc
			auth = $session
			id = $id
		}

		if ($GroupID) {$Body.params.groups=$grp} elseif ($groups) {$Body.params.groups=$groups}
		if ($TemplateID -and ($TemplateID -ne 0)) {$Body.params.templates=$tmpl} elseif ($parentTemplates) {$Body.params.templates=$parentTemplates | select templateid}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {
			$a.result
			if ($psboundparameters.interfaces) {
				write-host "Replacing the IP address in cloned interfaces..." -f green
				Get-ZabbixHost -HostName $HostName | Get-ZabbixHostInterface | %{Set-ZabbixHostInterface -InterfaceID $_.interfaceid -IP $IP -Port $_.port -HostID $_.hostid -main $_.main}
			}
		} else {$a.error}
	}
}

Function Remove-ZabbixHost {
	<# 
	.Synopsis
		Delete/Remove selected host
	.Description
		Delete/Remove selected host
	.Parameter HostID
		To filter by ID/IDs
	.Example 
		Remove-ZabbixHost -HostID (Get-ZabbixHost | ? name -match "RetiredHosts").hostid -WhatIf
		Remove host(s) by name match (case insensitive) (check only: -WhatIf)
     .Example 
		Remove-ZabbixHost -HostID (Get-ZabbixHost | ? name -match "RetiredHosts").hostid
		Remove host(s) by name match (case insensitive)
	.Example
		Remove-ZabbixHost -HostID "10001","10002" 
		Remove hosts by IDs
	.Example
		Remove-ZabbixHost -HostID (Get-ZabbixHost -HostName HostRetired).hostid
		Remove single host by name (exact match, case sensitive)
	.Example
		Get-ZabbixHost | ? name -eq HostName | Remove-ZabbixHost -WhatIf
		Remove hosts (check only: -WhatIf)
     .Example
		Get-ZabbixHost | ? name -eq HostName | Remove-ZabbixHost
		Remove host
	.Example
		Get-ZabbixHost | ? name -match HostName0[1-8] | Remove-ZabbixHost
		Remove multiple hosts 
	.Example
		Get-ZabbixHost | Remove-ZabbixHost
		Will delete ALL hosts from Zabbix 
	#>
	
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("Delete-ZabbixHost","rzhst","dzhst")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Name,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
    process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "host.delete"
			params = @($HostID)
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Name,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
 }

 Function Copy-ZabbixHost {
	<# 
	.Synopsis
		Copy/clone host
	.Description
		Copy/clone host
	.Parameter HostName
		HostName of the host as it will display on zabbix
	.Parameter IP
		IP address to supervise the host
	.Parameter DNSName
		Domain name to supervise the host
	.Parameter Port
		Port to supervise the host
	.Parameter GroupID
		ID of the group where add the host
	.Parameter TemplateID
		ID/IDs of the templates to add to the host
	.Parameter MonitorByDNSName
		If used, domain name of the host will used to contact it
	.Example
		Get-ZabbixHost -HostName SourceHost | Copy-ZabbixHost -HostName NewHost -IP 10.20.10.10
		Full copy of the host with new Hostname and IP
	.Example
		Get-ZabbixHost | ? name -eq sourceHost | Copy-ZabbixHost -HostName NewHost -IP 10.20.10.10
		Full clone of the host with new Hostname and IP
	.Example
		Get-ZabbixHost | ? name -eq SourceHost | Copy-ZabbixHost -HostName NewHost -IP 10.20.10.10 -status 1
		Full clone of the host with new Hostname and IP with status 1 (disabled)
	.Example
		Import-Csv c:\new-servers.csv | %{Get-ZabbixHost | ? name -eq SourceHost | Clone-ZabbixHost -HostName $_.Hostname -IP $_.IP}
		Mass clone new hosts
	#>
	
	[CmdletBinding()]
	[Alias("Clone-ZabbixHost","czhst")]
	Param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$false)][string]$HostName,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][string]$IP,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Port = 10050,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$interfaces,
		[Alias("parentTemplates")][Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$templates,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$status,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$groups,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][string]$GroupID,
        [Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$httpTests,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][int]$ProxyHostID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )

	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "host.create"
			params = @{
				host = $HostName
				# interfaces = $interfaces
				interfaces = (Get-ZabbixHostInterface -HostID $hostid | select * -ExcludeProperty hostid,interfaceid,bulk)
				templates = ($templates | select templateid)
				groups = ($groups | select groupid)
				# proxy_hostid = $ProxyHostID
				status = $Status
			}
			
			jsonrpc = $jsonrpc
			auth = $session
			id = $id
		}

		# if ($IP) {$Body.params.interfaces = }
		if ($httpTests) {$Body.params.httptests = ($httpTests | select httptestid)}
		if ($ProxyHostID) {$Body.params.proxy_hostid = $ProxyHostID}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		#$a.result.hostids
		if ($a.result) {
			$a.result
				write-verbose " --> Going to replace the IP address in cloned interfaces..."
				Get-ZabbixHost -HostName $HostName | Get-ZabbixHostInterface | Set-ZabbixHostInterface -IP $IP
		} else {$a.error}
	}
}

Function Get-ZabbixTemplate {
	<# 
	.Synopsis
		Get templates
	.Description
		Get templates
	.Parameter TemplateName
		To filter by name of the template (case sensitive)
	.Parameter TemplateID
		To filter by id of the template
	.Example
		Get-ZabbixTemplate
		Get all templates 
	.Example
		Get-ZabbixTemplate | select name,hosts
		Get templates and hosts
	.Example
		Get-ZabbixTemplate -TemplateName "Template OS Windows"
		Get template by name (case sensitive)
	.Example
		Get-ZabbixTemplate | ? name -match OS | select templateid,name -Unique
		Get template by name (case insensitive)
	.Example
		Get-ZabbixTemplate | ? {$_.hosts.host -match "host"} | select templateid,name
		Get templates linked to host by hostname
	.Example
		Get-ZabbixTemplate | ? name -eq "Template OS Linux" | select -ExpandProperty hosts | select host,jmx_available,*error* | ft -a
		Get hosts status per template
	.Example
		Get-ZabbixTemplate "Template OS Linux" | select -pv templ | select -ExpandProperty hosts | select @{n='Template';e={$templ.name}},Name,Status,Error
		Get hosts status per template
	.Example
		Get-ZabbixHost | ? name -match hostName | Get-ZabbixTemplate | select name
		Get templates for host
	#>
    
	[CmdletBinding()]
	[Alias("gzt")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$hostids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$parentTemplates,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
   
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "template.get"
			params = @{
				output = "extend"
				selectHosts = "extend"
				selectTemplates = "extend"
				selectParentTemplates = "extend"
				selectGroups = "extend"
				selectHttpTests = "extend"
				selectItems = "extend"
				selectTriggers = "extend"
				selectApplications = "extend"
				selectMacros = "extend"
				selectScreens = "extend"
				filter = @{
					host = $TemplateName
				}
				# templateids = $TemplateID
				hostids = $HostID
			}
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function New-ZabbixTemplate {
	<# 
	.Synopsis
		Create new template
	.Description
		Create new template
	.Parameter TemplateHostName
		(Required) Template hostname: Technical name of the template
	.Parameter TemplateName
		Template name: Visible name of the host, Default: host property value
	.Parameter Description
		Description of the template
	.Parameter groups
		(Required) Host groups to add the template to, Default: HostGroup=1 (Templates)
	.Parameter templates
		Templates to be linked to the template
	.Parameter hosts
		Hosts to link the template to
	.Example
		New-ZabbixTemplate -TemplateHostName "newTemplateName" -GroupID ((Get-ZabbixHostGroup | ? name -match Templates).groupid) -HostID (Get-ZabbixHost | ? name -match hostName).hostid -templates (Get-ZabbixTemplate | ? name -eq "TemplateName" ).templateid
		Create new template 
	.Example
		Get-ZabbixTemplate | ? name -eq "Template OS Linux" | New-ZabbixTemplate -TemplateHostName "Template OS Linux - Clone" -TemplateDescription "description"
		Clone template (partially: groups, linked templates and hosts)
	.Example
		New-ZabbixTemplate -TemplateHostName "newTemplateName"
		Create new template
	#>
    
	[CmdletBinding()]
	[Alias("nzt")]
	Param (
		[Alias("host")][Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$TemplateHostName,
		# [Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$TemplateVisibleName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$TemplateDescription,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$HostID,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$groups,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$templates,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$hosts,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$parentTemplates,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$screens,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$applications,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$triggers,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$httpTests,
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$macros,
		# [switch]$AddToDefaultTemplateGroup,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		write-verbose ("groups: " + $groups.length)
		write-verbose ("hosts:  " + $hosts.length)
		write-verbose ("templates:  " + $templates.length)

		if (!$GroupID -and !$groups) {$GroupID=1} 

		for ($i=0; $i -lt $GroupID.length; $i++) {[array]$grp+=$(@{groupid = $($GroupID[$i])})}
		for ($i=0; $i -lt $HostID.length; $i++) {[array]$hst+=$(@{hostid = $($HostID[$i])})}
		for ($i=0; $i -lt $TemplateID.length; $i++) {[array]$tmpl+=$(@{templateid = $($TemplateID[$i])})}
		# for ($i=0; $i -lt $macros.length; $i++) {[array]$mcr+=$(@{macroid = $($macros[$i])})}
		
		$Body = @{
			method = "template.create"
			params = @{
				host = $TemplateHostName
				# name = $TemplateVisibleName
				description = $TemplateDescription
				groups = if ($GroupID) {@($grp)} else {$groups}
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if ($HostID) {$Body.params.hosts=@($hst)} elseif ($hosts) {$Body.params.hosts=$hosts | select hostid}
		if ($TemplateID) {$Body.params.templates=@($tmpl)} elseif ($parentTemplates) {$Body.params.templates=$parentTemplates | select templateid}
		# if ($parentTemplates) {$Body.params.parentTemplates=$parentTemplates | select tmplateid}
		# if ($screens) {$Body.params.screens=$screens}
		# if ($applications) {$Body.params.applications=$applications}
		# if ($httpTests) {$Body.params.httpTests=$httpTests}
		# if ($triggers) {$Body.params.httpTests=$triggers}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		#$a.result | Select-Object Name,TemplateID,@{Name="HostsMembers";Expression={$_.hosts.hostid}}
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Set-ZabbixTemplate {
	<# 
	.Synopsis
		Update template
	.Description
		Update template
	.Parameter TemplateID
		Template ID
	.Parameter TemplateHostName
		TemplateHostName: Technical name of the template
	.Parameter TemplateVisibleName
		TemplateVisibleName: Visible name of the template
	.Parameter TemplateDescription
		TemplateDescription: Description of the template
	.Example
		Get-ZabbixTemplate | ? host -match oldTemplateName | Set-ZabbixTemplate -TemplateHostName "newTemplateName"
		Update template host name
	.Example
		Get-ZabbixTemplate | ? name -match oldTemplateName | Set-ZabbixTemplate -TemplateVisibleName "newTemplateName"
		Update template visible name
	.Example
		Set-ZabbixTemplate -TemplateVisibleName newTemplateName -TemplateID 10404
		Update template visible name
	.Example
		Get-ZabbixTemplate | ? name -eq templateName | Set-ZabbixTemplate -TemplateVisibleName VisibleTemplateName -groups 24,25 -hosts (Get-ZabbixHost | ? name -match host).hostid  -Verbose -templates (Get-ZabbixTemplate | ? name -eq "Template App HTTP Service" ).templateid
		Replace values in the template
	.Example
		$addTempID=(Get-ZabbixTemplate | ? host -eq currentTemplate).parenttemplates.templateid
		$addTempID+=((Get-ZabbixTemplate | ? name -match FTP).templateid)
		$addGrpID=(Get-ZabbixTemplate | ? host -eq currentTemplate).groups.groupid
		$addGrpID+=(Get-ZabbixHostGroup | ? name -match hostGroup).groupid
		Get-ZabbixTemplate | ? name -eq currentTemplate | Set-ZabbixTemplate -GroupsID $addTempID -TemplatesID $addGrpID -TemplateDescription "TemplateDescription"
		This will add new values to already existing ones, i.e add, and not replace
	#>
    
	[CmdletBinding()]
	[Alias("szt")]
	Param (
		[Alias("host")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName)][string]$TemplateHostName,
		[Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName)][string]$TemplateVisibleName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName)][string]$TemplateDescription,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$GroupsID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$TemplatesID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HostsID,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$groups,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$templates,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$hosts,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		write-verbose ("groups: " + $groups.length)
		write-verbose ("hosts:  " + $hosts.length)
		write-verbose ("templates:  " + $templates.length)

		for ($i=0; $i -lt $groupsID.length; $i++) {[array]$grp+=$(@{groupid = $($groupsID[$i])})}
		for ($i=0; $i -lt $hostsID.length; $i++) {[array]$hst+=$(@{hostid = $($hostsID[$i])})}
		for ($i=0; $i -lt $templatesID.length; $i++) {[array]$tmpl+=$(@{templateid = $($templatesID[$i])})}

		$Body = @{
			method = "template.update"
			params = @{
				host = $TemplateHostName
				templateid = $TemplateID
				name = $TemplateVisibleName
				description = $TemplateDescription
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if ($groupsID) {$Body.params.groups=@($grp)} else {if ($groups) {$Body.params.groups=$groups}}
		if ($hostsID) {$Body.params.hosts=@($hst)} else {if ($hosts) {$Body.params.hosts=$hosts}}
		if ($templatesID) {$Body.params.templates=@($tmpl)} else {if ($templates) {$Body.params.templates=$templates} }

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixTemplate {
	<# 
	.Synopsis
		Remove template
	.Description
		Remove template
	.Example
		Get-ZabbixTemplate | ? name -match templateName | Remove-ZabbixTemplate
		Remove template
	.Example
		gzt | ? name -match templateName | Remove-ZabbixTemplate
		Remove templates
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzt","dzt","Delete-ZabbixTemplate")]
	Param (
        [Alias("Name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "template.delete"
			params = @($TemplateID)
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($TemplateName,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		#$a.result | Select-Object Name,TemplateID,@{Name="HostsMembers";Expression={$_.hosts.hostid}}
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixHostGroup {
	<#
	.Synopsis
		Get host group
	.Description
		Get host group
	.Parameter GroupName
		Filter by name of the group
	.Parameter GroupID
		Filter by id of the group
	.Example
		Get-ZabbixHostGroup
		Get host groups
	.Example
		(Get-ZabbixHostGroup -GroupName somegroup).hosts
		Get hosts from host group (case sensitive)
	.Example
		(Get-ZabbixHostGroup | ? name -match somegroup).hosts
		Get host group and hosts (case insensitive)
	.Example
		Get-ZabbixHostGroup | ? name -match somegroup | select name -ExpandProperty hosts | sort host | ft -a
		Get host group and it's hosts
	.Example
		Get-ZabbixHostGroup -GroupID 10001 | select name -ExpandProperty hosts
		Get group and it's hosts
	.Example
		Get-ZabbixHostGroup | ? name -match templates | select -ExpandProperty templates
		Get group of templates	
	#>

	[CmdletBinding()]
	[Alias("gzhg","Get-ZabbixGroup")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)]$GroupName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)]$GroupID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )

	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "hostgroup.get"
			params = @{
				output = "extend"
				selectHosts = @(
					"hostid",
					"host"
				)
				selectTemplates =  @(
					"templateid",
					"name"
				)
				filter = @{
					name = $GroupName
				}
				groupids = $GroupID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON

		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixHostGroup {
	<# 
	.Synopsis
		Set host group
	.Description
		Set host group
	.Parameter GroupName
		To filter by name of the group
	.Parameter GroupID
		To filter by id of the group
	.Example
		Get-ZabbixHostGroup | ? name -eq oldName | Set-ZabbixHostGroup -name newName
		Rename host group 
	#>
    
	[CmdletBinding()]
	[Alias("szhg","Set-ZabbixGroup")]
	Param (
        [Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$GroupName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$GroupID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "hostgroup.update"
			params = @{
				groupid = $GroupID
				name = $GroupName
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function New-ZabbixHostGroup {
	<# 
	.Synopsis
		Create host group
	.Description
		Create host group
	.Parameter GroupName
		To filter by name of the group
	.Parameter GroupID
		To filter by id of the group
	.Example
		New-ZabbixHostGroup -Name newHostGroupName
		Create new host group 
	#>
    
	[CmdletBinding()]
	[Alias("nzhg")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Name,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "hostgroup.create"
			params = @{	
				name = $Name
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixHostGroup {
	<# 
	.Synopsis
		Remove host group
	.Description
		Remove host group
	.Parameter GroupName
		To filter by name of the group
	.Parameter GroupID
		To filter by id of the group
	.Example
		Get-ZabbixHostGroup | ? name -eq hostGroupName | Remove-ZabbixHostGroup -WhatIf
		WhatIf on remove host group (case insensitive)
	.Example
		Get-ZabbixHostGroup ExactGroupName | Remove-ZabbixHostGroup
		Remove host group (case sensitive)
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzhg")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$GroupID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "hostgroup.delete"
			params = @($GroupID)	

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Name,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Set-ZabbixHostGroupRemoveHosts {
	<# 
	.Synopsis
		Set host group: remove hosts from multiple groups 
	.Description
		Set host group: remove hosts from multiple groups
	.Parameter GroupName
		To filter by name of the group
	.Parameter GroupID
		To filter by id of the group
	.Example
		Get-ZabbixHostGroup | ? name -eq hostGroup | select groupid -ExpandProperty hosts | ? host -match hostsToRemove | Set-ZabbixHostGroupRemoveHosts
		Remove hosts from the host group
	.Example
		Get-ZabbixHostGroup | ? name -eq hostGroup | Set-ZabbixHostGroupRemoveHosts -HostID (Get-ZabbixHost | ? name -match hostsToRemove).hostid
		Remove hosts from the host group 
	.Example
		Set-ZabbixHostGroupRemoveHosts -GroupID ( Get-ZabbixHostGroup | ? name -match "hostGroup-0[1-6]").groupid -HostID (Get-ZabbixHost | ? name -match "hostname-10[1-9]").hostid -hostName (Get-ZabbixHost | ? name -match "hostname-10[1-9]").name -verbose
		Remove hosts from the host groups with extra verbosity and validation
	.Example
		Get-ZabbixHost | ? name -match hostsToRemove | Set-ZabbixHostGroupRemoveHosts -GroupID (Get-ZabbixHostGroup | ? name -match hostGroup).groupid
		Get-ZabbixHostGroup -GroupID 25 | select -ExpandProperty hosts
		Get-ZabbixHostGroup | select groupid,name,hosts
		1.Remove hosts from the host group 2.Validate the change 3.Validate the change
	.Example 
		Set-ZabbixHostGroupRemoveHosts -GroupID 25 -TemplateID (Get-ZabbixTemplate | ? name -match "template1|template2").templateid
		Remove templates from host group
	.Example
		Set-ZabbixHostGroupRemoveHosts -GroupID 25 -TemplateID (Get-ZabbixTemplate | ? name -match "template1|template2").templateid -HostID (Get-ZabbixHost | ? name -match "host").hostid
		Get-ZabbixHostGroup -GroupID 25
		1.Remove hosts and templates from the host group 2.Validate the change
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("szhgrh")]
	Param (
        [Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$GroupName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$TemplateID,
		[Alias("host")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$HostName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "hostgroup.massremove"
			params = @{
				groupids = @($GroupID)
				# hostids = @($HostID)
				# templateids = @($TemplateID)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if ($HostID) {$Body.params.hostids=@($HostID)}
		if ($TemplateID) {$Body.params.templateids=@($TemplateID)}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			if ([bool]$WhatIfPreference.IsPresent) {}

			if ($PSCmdlet.ShouldProcess((@($HostID)+@($hostName)+(@($TemplateID))),"Delete")) {  
				$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
				if ($a.result) {$a.result} else {$a.error}
			}
		}
		catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixHostGroupAddHosts {
	<# 
	.Synopsis
		Set host group: add hosts to multiple groups 
	.Description
		Set host group: add hosts to multiple groups
	.Parameter GroupName
		To filter by name of the group
	.Parameter GroupID
		To filter by id of the group
	.Example
		Get-ZabbixHostGroup | ? name -eq hostGroup | Set-ZabbixHostGroupAddHosts -HostID (Get-ZabbixHost | ? name -match "host").hostid
		Add hosts to the host group
	.Example
		Get-ZabbixHostGroup | ? name -match hostGroups | Set-ZabbixHostGroupAddHosts -HostID (Get-ZabbixHost | ? name -match hosts).hostid
		Add hosts to multiple groups
	.Example
		Get-ZabbixHostGroup -GroupID 25 | Set-ZabbixHostGroupAddHosts -TemplateID (get-zabbixtemplate | ? name -match template1|template2).templateid
		Add templates to the host group
	#>
    
	[CmdletBinding()]
	[Alias("szhgah")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "hostgroup.massadd"
			params = @{
				groups = @($GroupID)
				# hosts = @($HostID)
				# templates = @($TemplateID)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		if ($HostID) {$Body.params.hosts=@($HostID)}
		if ($TemplateID) {$Body.params.templates=@($TemplateID)}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Get-ZabbixMaintenance {
	<# 
	.Synopsis
		Get maintenance
	.Description
		Get maintenance
	.Parameter MaintenanceName
		To filter by name of the maintenance (case sensitive)
	.Parameter MaintenanceID
		To filter by id of the maintenance
	.Example
		Get-ZabbixMaintenance | select maintenanceid,name
		Get maintenance
	.Example
		Get-ZabbixMaintenance -MaintenanceName MaintenanceName
		Get maintenance by name (case sensitive)
	.Example 
		Get-ZabbixMaintenance | ? name -match maintenance
		Get maintenance by name match (case insensitive)
    .Example
        Get-ZabbixMaintenance | ? name -match "" | select @{n="MaintenanceName";e={$_.name}} -ExpandProperty groups | ft -a
        Get maintenance by name match (case insensitive)   
	.Example
		Get-ZabbixMaintenance -MaintenanceID 10123
		Get maintenance by ID
	.Example
        Get-ZabbixMaintenance | select maintenanceid,name,@{n="Active_since(UTC-5)";e={(convertFrom-epoch $_.active_since).addhours(-5)}},@{n="Active_till(UTC-5)";e={(convertFrom-epoch $_.active_till).addhours(-5)}},@{n="TimeperiodStart(UTC-5)";e={(convertfrom-epoch $_.timeperiods.start_date).addhours(-5)}},@{n="Duration(hours)";e={$_.timeperiods.period/3600}} | ft -a
        Get maintenance and it's timeperiod
	.Example
		(Get-ZabbixMaintenance -MaintenanceName MaintenanceName).timeperiods
		Get timeperiods from maintenance (case sensitive)
    .Example
        Get-ZabbixMaintenance | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | ft -a
        Get timeperiods from maintenance
	.Example
        Get-ZabbixMaintenance | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | select MaintenanceName,timeperiodid,timeperiod_type,@{n="start_date(UTC)";e={convertfrom-epoch $_.start_date}},@{n="period(Hours)";e={$_.period/3600}} | ft -a
        Get timeperiods maintenance and timeperiods (Time in UTC)
    .Example
		(Get-ZabbixMaintenance -MaintenanceName MaintenanceName).hosts.host
		Get hosts from maintenance (case sensitive)
	.Example
		(Get-ZabbixMaintenance -MaintenanceName MaintenanceName).hostid  
		Get HostIDs of hosts from maintenance (case sensitive)
	.Example
		Get-ZabbixMaintenance | ? name -match maintenance | select Name,@{n="TimeperiodStart";e={(convertfrom-epoch $_.timeperiods.start_date).addhours(-5)}},@{n="Duration(hours)";e={$_.timeperiods.period/3600}}
		Get timeperiods from maintenance (case insensitive), display name, timeperiod (according UTC-5) and duration
	#>
    
	[CmdletBinding()]
	[Alias("gzm")]
	Param (
        $MaintenanceName,
        $MaintenanceID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "maintenance.get"
			params = @{
				output = "extend"
				selectGroups = "extend"
				selectHosts = "extend"
				selectTimeperiods = "extend"
				filter = @{
					name = $MaintenanceName
				}
				maintenanceids = $MaintenanceID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Remove-ZabbixMaintenance {
	<# 
	.Synopsis
		Remove maintenance
	.Description
		Remove maintenance
	.Parameter MaintenanceID
		To filter by ID/IDs of the maintenance
	.Example
		Remove-ZabbixMaintenance -MaintenanceID "3","4" 
		Remove maintenance by IDs
	.Example
		Remove-ZabbixMaintenance -MaintenanceID (Get-ZabbixMaintenance | ? name -match "Maintenance|Name").maintenanceid -WhatIf
		Remove multiple maintenances (check only: -WhatIf)
    .Example
		Remove-ZabbixMaintenance -MaintenanceID (Get-ZabbixMaintenance | ? name -match "Maintenance|Name").maintenanceid
		Remove multiple maintenances
	.Example
		Get-ZabbixMaintenance | ? name -eq name | Remove-ZabbixMaintenance
		Remove single maintenance by name
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzm")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$Name,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$MaintenanceID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
     
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "maintenance.delete"
			params = @($MaintenanceID)
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Name,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
 }

Function New-ZabbixMaintenance {
	<# 
	.Synopsis
		Create new maintenance
	.Description
		Create new maintenance
	.Parameter MaintenanceName
		Maintenance name (case sensitive)
	.Parameter MaintenanceDescription
		Maintenance Description
	.Parameter ActiveSince
		Maintenance start time (epoch time format)
	.Parameter ActiveTill
		Maintenance end time (epoch time format)
	.Parameter MaintenanceType
		Maintenance maintenance type (0 - (default) with data collection;  1 - without data collection)
	.Parameter TimeperiodType
		Maintenance TimeperiodType (0 - (default) one time only; 2 - daily;  3 - weekly;  4 - monthly)
	.Parameter TimeperiodStartDate
		Maintenance timeperiod's start date. Required only for one time periods. Default: current date (epoch time format)
	.Parameter TimeperiodPeriod
		Maintenance timeperiod's period/duration (seconds)	
	.Example
		New-ZabbixMaintenance -HostID (Get-ZabbixHost | ? name -match "hosts").hostid -MaintenanceName "NewMaintenance" -ActiveSince (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) -ActiveTill (convertTo-epoch ((get-date).addhours(7)).ToUniversalTime()) -TimeperiodPeriod (4*3600)
		Create new maintenance for few hosts (time will be according Zabbix server time). Maintenance will be active for 7 hours from now, with Period 4 hours, which will start immediately 
	.Example
		New-ZabbixMaintenance -HostID "10109","10110","10111","10112","10113","10114" -MaintenanceName NewMaintenanceName -MaintenanceDescription NewMaintenanceDescription -ActiveSince 1432584300 -ActiveTill 1432605900 -TimeperiodStartTime 1432584300 -TimeperiodPeriod 25200
		Create new maintenance (time (epoch format) will be according your PC (client) local time). Name and Description are case sensitive 
	.Example
		New-ZabbixMaintenance -HostID (Get-ZabbixHost | ? name -match otherhost).hostid -MaintenanceName NewMaintenanceName -MaintenanceDescription NewMaintenanceDescription -ActiveSince (convertTo-epoch (get-date -date "05/25/2015 07:05")) -ActiveTill (convertTo-epoch (get-date -date "05/25/2015 17:05")) -TimeperiodPeriod (7*3600) -TimeperiodStartDate (convertTo-epoch (get-date -date "05/25/2015 09:05"))
		Create new, future maintenance (case sensitive) (time will be sent in UTC). Will be set on Zabbix server according it's local time. 
	.Example
		$hosts=Get-Zabbixhost | ? name -match "host|anotherhost"
		$groups=(Get-ZabbixGroup | ? name -match "group")
		New-ZabbixMaintenance -HostID $hosts.hostid -GroupID $groups.groupid -MaintenanceName "NewMaintenanceName" -ActiveSince (convertTo-epoch (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) -ActiveTill (convertTo-epoch ((get-date).addhours(+4)).ToUniversalTime()) -TimeperiodPeriod (3*3600)
		Create new maintenance for few hosts (time will be according current Zabbix server time). Maintenance Active from now for 4 hours, and Period with duration of 3 hours, starting immediately
	#>

	[CmdletBinding()]
	[Alias("nzm")]
	Param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$False)][string]$MaintenanceName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$MaintenanceDescription,
		# Type of maintenance.  Possible values:  0 - (default) with data collection;  1 - without data collection. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$MaintenanceType,
		# epoch time
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$False)]$ActiveSince,
		# epoch time
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$False)]$ActiveTill,
		# Possible values: 0 - (default) one time only;  2 - daily;  3 - weekly;  4 - monthly. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimePeriodType=0,
		# Time of day when the maintenance starts in seconds.  Required for daily, weekly and monthly periods. (epoch time)
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodStartTime,
		# Date when the maintenance period must come into effect.  Required only for one time periods. Default: current date. (epoch time)
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)]$TimeperiodStartDate,
		# Duration of the maintenance period in seconds. Default: 3600 (epoch time)
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodPeriod,
		# For daily and weekly periods every defines day or week intervals at which the maintenance must come into effect. 
		# For monthly periods every defines the week of the month when the maintenance must come into effect. 
		# Possible values:  1 - first week;  2 - second week;  3 - third week;  4 - fourth week;  5 - last week.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodEvery,
		# Day of the month when the maintenance must come into effect
		# Required only for monthly time periods
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodDay,
		# Days of the week when the maintenance must come into effect
		# Days are stored in binary form with each bit representing the corresponding day. For example, 4 equals 100 in binary and means, that maintenance will be enabled on Wednesday
		# Used for weekly and monthly time periods. Required only for weekly time periods
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodDayOfWeek,
		# Months when the maintenance must come into effect
		# Months are stored in binary form with each bit representing the corresponding month. For example, 5 equals 101 in binary and means, that maintenance will be enabled in January and March
		# Required only for monthly time periods
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodMonth,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url),
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string[]]$Tags
		
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		if (!($GroupID -or $HostID)) {write-host "`nYou need to provide GroupID or HostID as parameter`n" -f red; return}
		
		if ($GroupID) {
			$Body = @{
				method = "maintenance.create"
				params = @{
					name = $MaintenanceName
					description = $MaintenanceDescription
					active_since = $ActiveSince
					active_till = $ActiveTill
					maintenance_type = $MaintenanceType
					timeperiods = @(
						@{
							timeperiod_type = $TimeperiodType
							start_date = $TimeperiodStartDate
							period = $TimeperiodPeriod
							
							start_time = $TimeperiodStartTime
							month = $TimeperiodMonth
							dayofweek = $TimeperiodDayOfWeek
							day = $TimeperiodDay
						}
					)
					groupids = @($GroupID)
				}
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		if ($HostID) {
			$Body = @{
				method = "maintenance.create"
				params = @{
					name = $MaintenanceName
					description = $MaintenanceDescription
					active_since = $ActiveSince
					active_till = $ActiveTill
					maintenance_type = $MaintenanceType
					timeperiods = @(
						@{
							timeperiod_type = $TimeperiodType
							start_date = $TimeperiodStartDate
							period = $TimeperiodPeriod
							
							every = $TimeperiodEvery
							start_time = $TimeperiodStartTime
							month = $TimeperiodMonth
							dayofweek = $TimeperiodDayOfWeek
							day = $TimeperiodDay
						}
					)
					hostids = @($HostID)
				}
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}

		if($Tags){
			$formattedTags = Foreach ($tag in $Tags)
            {
                $split = $tag.split(':')
                @{
                    tag      = $split[0]
                    operator = 0
                    value    = $split[-1]
                }
			}
			$Body.params.tags = $formattedTags
		}
		
		$BodyJSON = ConvertTo-Json $Body -Depth 4
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
 }

 Function Set-ZabbixMaintenance {
	<# 
	.Synopsis
		Set/update maintenance settings
	.Description
		Set/update maintenance settings
	.Parameter MaintenanceName
		Maintenance name (case sensitive)
	.Parameter MaintenanceDescription
		Maintenance Description
	.Parameter ActiveSince
		Maintenance start time (epoch time format)
	.Parameter ActiveTill
		Maintenance end time (epoch time format)
	.Parameter MaintenanceType
		Maintenance maintenance type (0 - (default) with data collection;  1 - without data collection)
	.Parameter TimeperiodType
		Maintenance TimeperiodType (0 - (default) one time only; 2 - daily;  3 - weekly;  4 - monthly)
	.Parameter TimeperiodStartDate
		Maintenance timeperiod's start date. Required only for one time periods. Default: current date (epoch time format)
	.Parameter TimeperiodPeriod
		Maintenance timeperiod's period/duration (seconds)	
	.Example
		Get-ZabbixMaintenance -MaintenanceName 'MaintenanceName' | Set-ZabbixMaintenance -GroupID (Get-ZabbixHostGroup | ? name -eq 'HostGroupName').groupid -TimeperiodPeriod 44400 -HostID (Get-ZabbixHost | ? name -match host).hostid
		Will replace ZabbixHostGroup, hosts and set new duration for selected maintenance (MaintenanceName is case sensitive)
	.Example
		Get-ZabbixMaintenance | ? name -eq 'MaintenanceName' | Set-ZabbixMaintenance -GroupID (Get-ZabbixHostGroup | ? name -match 'homeGroup').groupid -verbose -TimeperiodPeriod 44400 -HostID (Get-ZabbixHost | ? name -match host).hostid
		Same as above (MaintenanceName is case insensitive)
	.Example
		Get-ZabbixMaintenance | ? name -match 'maintenance' | Set-ZabbixMaintenance -GroupID (Get-ZabbixHostGroup | ? name -match 'Name1|Name2').groupid -TimeperiodPeriod 44400 -HostID (Get-ZabbixHost | ? name -match host).hostid
		Replace ZabbixHostGroups, hosts, duration in multiple maintenances 
	#>

	[CmdletBinding()]
	[Alias("szm")]
	Param (
		[Alias("name")][Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$MaintenanceName,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$MaintenanceID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HostID,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$groups,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$hosts,
		[Parameter(DontShow,Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$timeperiods,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$MaintenanceDescription,
		#Type of maintenance.  Possible values:  0 - (default) with data collection;  1 - without data collection. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$MaintenanceType,
		#epoch time
		[Alias("active_since")][Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]$ActiveSince,
		#epoch time
		[Alias("active_till")][Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]$ActiveTill,
		#epoch time
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$TimeperiodPeriod,
		#Possible values: 0 - (default) one time only;  2 - daily;  3 - weekly;  4 - monthly. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$TimePeriodType=0,
		#Time of day when the maintenance starts in seconds.  Required for daily, weekly and monthly periods. (epoch time)
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$TimeperiodStartTime,
		#Date when the maintenance period must come into effect.  Required only for one time periods. Default: current date. (epoch time)
		# [Alias("timeperiods.start_date")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromRemainingArguments=$true)]$TimeperiodStartDate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]$TimeperiodStartDate,
		#For daily and weekly periods every defines day or week intervals at which the maintenance must come into effect. 
		#For monthly periods every defines the week of the month when the maintenance must come into effect. 
		#Possible values:  1 - first week;  2 - second week;  3 - third week;  4 - fourth week;  5 - last week.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$TimeperiodEvery,
		# Day of the month when the maintenance must come into effect
		# Required only for monthly time periods
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodDay,
		# Days of the week when the maintenance must come into effect
		# Days are stored in binary form with each bit representing the corresponding day. For example, 4 equals 100 in binary and means, that maintenance will be enabled on Wednesday
		# Used for weekly and monthly time periods. Required only for weekly time periods
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodDayOfWeek,
		# Months when the maintenance must come into effect
		# Months are stored in binary form with each bit representing the corresponding month. For example, 5 equals 101 in binary and means, that maintenance will be enabled in January and March
		# Required only for monthly time periods
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][int]$TimeperiodMonth,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		# for ($i=0; $i -lt $GroupID.length; $i++) {[array]$grp+=$(@{GroupID = $($TemplateID[$i])})}
		# for ($i=0; $i -lt $HostID.length; $i++) {[array]$hst+=$(@{HostID = $($HostID[$i])})}
		# for ($i=0; $i -lt $TemplateID.length; $i++) {[array]$tmpl+=$(@{templateid = $($TemplateID[$i])})}
		
		if ($hosts -and !$HostID) {$HostID=($hosts).hostid}
		if ($groups -and !$GroupID) {$GroupID=($groups).groupid}
		if ($timeperiods -and !$TimeperiodType) {$TimeperiodType=($timeperiods).timeperiod_type}
		if ($timeperiods -and !$TimeperiodStartDate) {$TimeperiodStartDate=($timeperiods).start_date}
		if ($timeperiods -and !$TimeperiodStartTime) {$TimeperiodStartTime=($timeperiods).start_time}
		if ($timeperiods -and !$TimeperiodPeriod) {$TimeperiodPeriod=($timeperiods).period}
		if ($timeperiods -and !$TimeperiodMonth) {$TimeperiodMonth=($timeperiods).month}
		if ($timeperiods -and !$TimeperiodDayOfWeek) {$TimeperiodDayOfWeek=($timeperiods).dayofweek}
		if ($timeperiods -and !$TimeperiodDay) {$TimeperiodDay=($timeperiods).day}
		if ($timeperiods -and !$TimeperiodEvery) {$TimeperiodEvery=($timeperiods).every}

		$Body = @{
			method = "maintenance.update"
			params = @{
				name = $MaintenanceName
				maintenanceid = $MaintenanceID
				description = $MaintenanceDescription
				active_since = $ActiveSince
				active_till = $ActiveTill
				maintenance_type = $MaintenanceType
				timeperiods = @(
					@{
						timeperiod_type = $TimeperiodType
						start_date = $TimeperiodStartDate
						period = $TimeperiodPeriod
						
						every = $TimeperiodEvery
						start_time = $TimeperiodStartTime
						month = $TimeperiodMonth
						dayofweek = $TimeperiodDayOfWeek
						day = $TimeperiodDay
					}
				)
				groupids = $GroupID
				# groups = $GroupID
				hostids = $HostID
				# timeperiods = $timeperiods
				# timeperiods = @($timep)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body -Depth 4
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
 }

 Function Get-ZabbixHttpTest {
	<# 
	.Synopsis
		Get web/http test
	.Description
		Get web/http test
	.Parameter HttpTestName
		To filter by name of the http test
	.Example
		Get-ZabbixHttpTest
		Get web/http tests
	.Example
		Get-ZabbixHttpTest | select name -Unique
		Get web/http tests
	.Example
		Get-ZabbixHttpTest | ? name -match httpTest | select httptestid,name
		Get web/http test by name match (case insensitive)
	.Example
		Get-ZabbixHttpTest | ? name -match httpTest | select steps | select -first 1 | fl *
		Get web/http test by name match, first occurrence
	.Example
		Get-ZabbixHttpTest | ? name -like "test*Name" | ? {$_.hosts.host -match "Template name"}) | select name,@{e={$_.steps.url}},@{n='host';e={$_.hosts.host}} -Unique | sort host
		Get web/http test by name (case insensitive)
	.Example
		Get-ZabbixHttpTest -HttpTestID 96
		Get web/http test by ID
	.Example
		(Get-ZabbixHttpTest -HttpTestName HttpTestName).hosts.host 
		Get hosts with web/http test by name match (case sensitive) 
	.Example 
		Get-ZabbixHttpTest -HostID (Get-ZabbixHost | ? name -match host).hostid | select host -ExpandProperty steps | ft -a
		Get web/http tests by hostname match (case insensitive)
	.Example
		Get-ZabbixTemplate | ? name -eq "Template Name" | get-ZabbixHttpTest | select -ExpandProperty steps | ft -a
		Get web/http tests by template name 
	.Example 
		Get-ZabbixHost | ? name -match host | Get-ZabbixHttpTest | select -ExpandProperty steps
		Get web/http tests for hostname match
	.Example
		Get-ZabbixHost | ? name -match host -pv hsts | Get-ZabbixHttpTest | select -ExpandProperty steps | select  @{n='Server';e={$hsts.host}},name,httpstepid,httptestid,no,url,timeout,required,status_codes,follow_redirects | ft -a
		Get web/http tests for hostname match
	.Example
		Get-ZabbixHttpTest -HostID (Get-ZabbixHost | ? name -eq hostname).hostid | ? name -match "httpTest" | fl httptestid,name,steps
		Get web/http test for host by name (case insensitive), and filter web/http test by test name match (case insensitive)
	.Example
		Get-ZabbixHttpTest -HostID (Get-ZabbixHost | ? name -eq hostname).hostid | ? name -match "httpTest" | select -ExpandProperty steps
		Get web/http test for host by name (case insensitive), and filter web/http test by test name match (case insensitive)
	.Example
		Get-ZabbixHttpTest -HttpTestName SomeHTTPTest | select -Unique 
		Get web/http test by name (case sensitive)
	.Example
		Get-ZabbixHttpTest -HttpTestName HTTPTestName | select name,@{n="host";e={$_.hosts.host}}
		Get web/http test by name (case sensitive) and hosts it is assigned to
	.Example
		(Get-ZabbixHttpTest | ? name -eq "HTTPTestName").hosts.host | sort
		Get hosts by web/http test's name (case insensitive)
	.Example	
		(Get-ZabbixHttpTest | ? name -eq "httpTestName").hosts.host | ? {$_ -notmatch "template"} | sort
		Get only hosts by web/http test name, sorted (templates (not hosts) are sorted out)
	.Example
		Get-ZabbixHttpTest | ? name -match httpTestName | select name, @{n="required";e={$_.steps.required}} -Unique
		Get web/http test name and field required
	.Example
		Get-ZabbixHttpTest | ? name -match httpTestName | select name, @{n="url";e={$_.steps.url}} -Unique
		Get web/http test name and field url
	#>
    
	[CmdletBinding()]
	[Alias("gzhttp")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HttpTestID,
		$HttpTestName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )

	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		if (!$hostid) {
			$Body = @{
				method = "httptest.get"
				params = @{
					output = "extend"
					selectHosts = "extend"
					selectSteps = "extend"
					httptestids = $HttpTestID
					templateids = $TemplateID
					filter = @{
						name = $HttpTestName
					}
				}
				
				selectHosts = @(
					"hostid",
					"name"
				)
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		if ($HostID) {
			$Body = @{
				method = "httptest.get"
				params = @{
					output = "extend"
					selectHosts = "extend"
					selectSteps = "extend"
					httptestids = $HttpTestID
					hostids = @($hostid)
					filter = @{
						name = $HttpTestName
					}
				}
				
				selectHosts = @(
					"hostid",
					"name"
				)
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function New-ZabbixHttpTest {
	<# 
	.Synopsis
		Create web/http test
	.Description
		Create web/http test
	.Parameter HttpTestName
		web/http test name
	.Example
		New-ZabbixHttpTest -HttpTestName NewHttpTest -HttpTestStepURL "http://{HOST.CONN}:30555/health-check/do" -HttpTestStepRequired "version" -HostID (Get-ZabbixHost -HostName HostName).hostid
		Create new web/http test for server/template
	.Example
		Get-ZabbixTemplate | ? name -eq "Template Name" | Get-ZabbixHttpTest | ? name -match httpTestSource | New-ZabbixHttpTest -HttpTestName NewHttpName
		Clone web/http test in template
	#>
    
	[CmdletBinding()]
	[Alias("nzhttp")]
	Param (
        $HttpTestID,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$HostID,
        $HttpTestStepRequired,
		[Parameter(ValueFromPipelineByPropertyName=$true)][array]$StatusCodes=200,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$Timeout=15,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$delay,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$retries,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$Steps,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$applicationid,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$TemplateID,
		$HttpTestStepName,
		[Parameter(Mandatory=$True)]$HttpTestName,
		#[Parameter(Mandatory=$True)]$HttpTestStepURL,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )

	process {
	
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		if ($steps) {
			$Body = @{
				method = "httptest.create"
				params = @{
					name = $HttpTestName
					hostid = $HostID
					templateid = $TemplateID
					applicationid = $applicationid
					status = $status
					steps = $steps
				}
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		else {
			$Body = @{
				method = "httptest.create"
				params = @{
					name = $HttpTestName
					hostid = $HostID
					templateid = $TemplateID
					applicationid = $applicationid
					status = $status
					delay = $delay
					retries = $retries
					steps = @(
						@{
							name = $HttpTestStepName
							url = $HttpTestStepURL
							status_codes = $StatusCodes
							required = $HttpTestStepRequired
							follow_redirects = 1
							timeout = $Timeout
						}
					) 
				}
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Set-ZabbixHttpTest {
	<# 
	.Synopsis
		Set/Update web/http test
	.Description
		Set/Update web/http test
	.Parameter HttpTestName
		web/http test name
	.Example
		Set-ZabbixHttpTest -HttpTestID (Get-ZabbixHttpTest -HttpTestName TestOldName ).httptestid -HttpTestName "testNewName" -status 0
		Enable (-status 0) web/http test and rename it (case sensitive)  
	.Example
		Get-ZabbixHttpTest -HttpTestName httpTest | Set-ZabbixHttpTest -status 1
		Disable web/http test (-status 1) 
	.Example
		Set-ZabbixHttpTest -HttpTestID (Get-ZabbixHttpTest -HttpTestName testName).httptestid -UpdateSteps -HttpTestStepName (Get-ZabbixHttpTest -HttpTestName testName).steps.name -HttpTestStepURL (Get-ZabbixHttpTest -HttpTestName SourceHttpTestName).steps.url
		Replace test steps' URL by other URL, taken from "othertest"  
	.Example
		Set-ZabbixHttpTest -HttpTestID (Get-ZabbixHttpTest | ? name -like "test*Name" | ? {$_.hosts.host -match "Template"}).httptestid -UpdateSteps -HttpTestStepName "NewTestName" -HttpTestStepURL "http://10.20.10.10:30555/health-check/do"
		Edit web/http test, update name and test url
	#>

	[CmdletBinding()]
	[Alias("szhttp")]
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]$HttpTestID,
		[Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$HttpTestName,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$HttpTestStepURL,
		$HostID,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$HttpTestStepName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$HttpTestStepRequired,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$delay=60,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$retries=1,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$timeout=15,
		[switch]$UpdateSteps,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		if ($UpdateSteps) 
		{
			$Body = @{
				method = "httptest.update"
				params = @{
					httptestid = $HttpTestID
					status = $status
					name = $HttpTestName
					steps = @(
						@{
							name = $HttpTestStepName
							url = $HttpTestStepURL
							status_codes = 200
							required = $HttpTestStepRequired
							follow_redirects = 1
							timeout = $timeout
						}
					) 
				}
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		else 
		{
			$Body = @{
			method = "httptest.update"
			params = @{
				httptestid = $HttpTestID
				status = $status
				name = $HttpTestName
				retries = $retries
				delay = $delay
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}
		}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixHttpTest {
	<# 
	.Synopsis
		Delete web/http test
	.Description
		Delete web/http test
	.Parameter HttpTestName
		web/http test name
	.Example
		Remove-ZabbixHttpTest -HttpTestID (Get-ZabbixTemplate | ? name -eq "Template Name" | Get-ZabbixHttpTest | ? name -match httpTests).httptestid
		Delete web/http tests
	.Example
		Get-ZabbixTemplate | ? name -eq "Template Name" | Get-ZabbixHttpTest | ? name -match httpTest | %{Remove-ZabbixHttpTest -HttpTestID $_.HttpTestID}
		Delete web/http tests 
	#>

	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzhttp")]
    Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$HttpTestID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "httptest.delete"
			params = @($HttpTestID)

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Name,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Export-ZabbixConfiguration {
	<# 
	.Synopsis
		Export configuration
	.Description
		Export configuration
	.Parameter GroupID
		GroupID: groups - (array) IDs of host groups to export.
	.Parameter HostID
		HostID - (array) IDs of hosts to export
	.Parameter TemplateID
		TemplateID - (array) IDs of templates to export.
	.Parameter Format
		Format: XML (default) or JSON. 
	.Example
		Export-ZabbixConfig -HostID (Get-ZabbixHost | ? name -match host).hostid
		Export hosts configuration
	.Example
		Export-ZabbixConfig -HostID (Get-ZabbixHost | ? name -match host).hostid | clip
		Capture to clipboard exported hosts configuration
	.Example
		Export-ZabbixConfig -HostID (Get-ZabbixHost | ? name -match host).hostid | Set-Content c:\zabbix-hosts-export.xml -Encoding UTF8 -nonewline
		Export hosts configuration to xml file
	.Example
		Export-ZabbixConfig -TemplateID (Get-ZabbixTemplate | ? name -match TemplateName).templateid | Set-Content c:\zabbix-templates-export.xml -Encoding UTF8 
		Export template to xml file
	.Example
		Export-ZabbixConfig -TemplateID (Get-ZabbixHost | ? name -match windows).templateid | Set-Content c:\zabbix-templates-export.xml -Encoding UTF8 -nonewline
		Export template configuration linked to certain hosts to xml file, -nonewline saves file in Unix format (no CR)
	.Example
		Export-ZabbixConfig -HostID (Get-ZabbixHost | ? name -eq host).hostid | format-xml | Set-Content C:\zabbix-host-export-formatted-pretty.xml -Encoding UTF8
		Export host template to xml, beautify with Format-Xml (module pscx) and save to xml file
	.Example
		Get-ZabbixHost | ? name -match host -pv hst | %{Export-ZabbixConfig -HostID $_.hostid | sc c:\ZabbixExport\export-zabbix-host-$($hst.name).xml -Encoding UTF8}
		Export host configuration
	.Example
		Get-ZabbixHost | ? name -eq Host | Export-ZabbixConfig | Format-Xml | Set-Content C:\zabbix-host-export-formatted-pretty.xml -Encoding UTF8
		Export host template to xml, beautify with Format-Xml (module pscx) and save to xml file
	.Example
		diff (Get-Content c:\FirstHost.xml) (Get-content c:\SecondHost.xml)
		Compare hosts by comparing their configuration files
	.Example
		Get-ZabbixTemplate | ? name -match templateNames | Export-ZabbixConfig -Format json | sc C:\zabbix-templates-export.json
		Export templates in JSON format
	.Example
		$expHosts=Get-ZabbixHost | ? name -match hosts | Export-ZabbixConfig -Format JSON | ConvertFrom-Json
		$expHosts.zabbix_export.hosts
		Explore configuration as powershell objects, without retrieving information from the server
	#>
	[CmdletBinding()]
	[Alias("Export-ZabbixConfig","ezconf")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$ScreenID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$MapID,
		# Format XML or JSON
		[string]$Format="xml",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"	
		
		if ($HostID) {
			$Body = @{
			method = "configuration.export"
			params = @{
				options = @{
					hosts = @($HostID)
				}
			format = $format
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}

			$BodyJSON = ConvertTo-Json $Body -Depth 3
			write-verbose $BodyJSON
			
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		}
		elseif ($TemplateID) {
			$Body = @{
			method = "configuration.export"
			params = @{
				options = @{
					templates = @($TemplateID)
				}
			format = $format
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}

			$BodyJSON = ConvertTo-Json $Body -Depth 3
			write-verbose $BodyJSON
			
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		}
		elseif ($GroupID) {
			$Body = @{
			method = "configuration.export"
			params = @{
				options = @{
					groups = @($GroupID)
				}
			format = $format
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}

			$BodyJSON = ConvertTo-Json $Body -Depth 3
			write-verbose $BodyJSON
			
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		}
		elseif ($ScreenID) {
			$Body = @{
			method = "configuration.export"
			params = @{
				options = @{
					screens = @($ScreenID)
				}
			format = $format
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}

			$BodyJSON = ConvertTo-Json $Body -Depth 3
			write-verbose $BodyJSON
			
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		}
		elseif ($MapID) {
			$Body = @{
			method = "configuration.export"
			params = @{
				options = @{
					maps = @($MapID)
				}
			format = $format
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}

			$BodyJSON = ConvertTo-Json $Body -Depth 3
			write-verbose $BodyJSON
			
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		}
	}
}

function Import-ZabbixConfiguration {
	<# 
	.Synopsis
		Import configuration
	.Description
		Import configuration
	.Parameter GroupID
		GroupID: groups - (array) IDs of host groups to Import.
	.Parameter HostID
		HostID - (array) IDs of hosts to Import
	.Parameter TemplateID
		TemplateID - (array) IDs of templates to Import.
	.Parameter Format
		Format: XML (default) or JSON. 
	.Example
		Import-ZabbixConfig -Path c:\zabbix-export-hosts.xml
		Import hosts configuration
	.Example
		$inputFile = Get-Content c:\zabbix-export-hosts.xml | Out-String 
		Import-ZabbixConfig -source $inputFile
		Import hosts configuration
	.Example
		Get-ZabbixHost | ? name -match host -pv hst | %{Export-ZabbixConfig -HostID $_.hostid | sc c:\ZabbixExport\export-zabbix-host-$($hst.name).xml -Encoding UTF8}
		dir c:\ZabbixExport\* | %{Import-ZabbixConfig $_.fullname}
		Import hosts configuration
	#>
	[CmdletBinding()]
	[Alias("Import-ZabbixConfig","izconf")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][string]$Path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][string]$source,
		# Format XML or JSON
		[string]$Format="xml",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	Process {
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"	
		
		if ($Path) {
			if (Test-Path $Path) {$xmlFile = Get-Content $Path | out-string}
			# if (Test-Path $Path) {$xmlFile = Get-Content $Path}
			# if (Test-Path $Path) {[string]$xmlFile = Get-Content $Path}
		}
		elseif ($source) {$xmlFile = $source}
		else {Write-Host "`nError: Wrong path!`n" -f red; return}
		
		if (($xmlFile).count -ne 1) {Write-Host "`nBad xml file!`n" -f red; return}
		  
		$Body = @{
		method = "configuration.import"
		params = @{
			format = $format
			rules = @{
				groups = @{
					createMissing = $true
				}
				templateLinkage = @{
					createMissing = $true
				}
				applications = @{
					createMissing = $true
				}
				hosts = @{
					createMissing = $true
					updateExisting = $true
				}
				items = @{
					createMissing = $true
					updateExisting = $true
				}
				discoveryRules = @{
					createMissing = $true
					updateExisting = $true
				}
				triggers = @{
					createMissing = $true
					updateExisting = $true
				}
				graphs = @{
					createMissing = $true
					updateExisting = $true
				}
				httptests = @{
					createMissing = $true
					updateExisting = $true
				}
				valueMaps = @{
					createMissing = $true
				}
			}
			source = $xmlFile
		}
		
		jsonrpc = $jsonrpc
		id = $id
		auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {
			$a.result
			Write-Host "`nImport was successful`n" -f green
		} 
		else {$a.error}
	}
}

Function Get-ZabbixTrigger {
	<# 
	.Synopsis
		Get trigger
	.Description
		Get trigger
	.Parameter TriggerID
		To filter by ID of the trigger
	.Example
        Get-ZabbixTrigger -HostID (Get-ZabbixHost | ? name -match host).hostid | select status,description,expression
        Get triggers from host 
	.Example
		Get-ZabbixTrigger -HostID (Get-ZabbixHost | ? name -match host).hostid | ? expression -match system | select triggerid,status,state,value,expression
		Get triggers from host, matches "system" in expression line
	.Example
		Get-ZabbixTrigger -HostID (Get-ZabbixHost | ? name -match host).hostid | ? value -eq 1 | select @{n='lastchange(UTC)';e={convertFrom-epoch $_.lastchange}},triggerid,status,state,value,expression | ft -a
		Get failed triggers from host: values: 0 is OK, 1 is problem
	.Example
		Get-ZabbixTemplate | ? name -match "TemplateName" | Get-ZabbixTrigger | select status,description,expression
		Get triggers from template
	.Example
		Get-ZabbixTemplate | ? name -match "Template OS Linux" | Get-ZabbixTrigger | ? status -eq 0 | ? expression -match system | select status,description,expression
		Get triggers from template
	.Example
		Get-ZabbixTrigger -TemplateID (Get-ZabbixTemplate | ? name -match Template).templateid -ExpandDescription -ExpandExpression | ft -a status,description,expression
		Get triggers by templateid (-ExpandDescription and -ExpandExpression will show full text instead of ID only)
	.Example 
		Get-ZabbixTrigger -TemplateID (Get-ZabbixTemplate | ? name -eq "Template OS Linux").templateid | select status,description,expression
		Get list of triggers from templates
	.Example
		Get-ZabbixTrigger -ExpandDescription -ExpandExpression | ? description -match "Template" | select description,expression
		Get triggers where description match the string (-ExpandDescription and -ExpandExpression will show full text instead of ID only)
	.Example
		Get-ZabbixHost -HostName HostName | Get-ZabbixTrigger -ea silent | ? status -match 0 | ft -a status,templateid,description,expression
		Get triggers for host (status 0 == enabled, templateid 0 == assigned directly to host, not from template) 
	.Example
		Get-ZabbixHost | ? name -match host | Get-ZabbixTrigger | select description,expression | ft -a -Wrap
		Get triggers for host
	#>
    
	[CmdletBinding()]
	[Alias("gztr")]
	Param (
		[switch]$ExpandDescription,
		[switch]$ExpandExpression,
        [array]$TriggerID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "trigger.get"
			params = @{
				output = "extend"
				selectFunctions = "extend"
				selectLastEvent = "extend"
				selectGroups = "extend"
				selectHosts = "extend"
				selectDependencies = "extend"
				selectTags = "extend"
				selectDiscoveryRule = "extend"
				expandDescription = $ExpandDescription
				expandExpression = $ExpandExpression
				expandComment = $ExpandComment
				triggerids = $TriggerID
				templateids = $TemplateID
				hostids = $HostID
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixTrigger {
	<# 
	.Synopsis
		Set/Update trigger settings
	.Description
		Set/Update trigger settings
	.Parameter TriggerID
		TriggerID
	.Example
		Get-ZabbixHost -HostName HostName | Get-ZabbixTrigger -ea silent | ? status -match 0 | ? expression -match "V:,pfree" | Set-ZabbixTrigger -status 1 -Verbose
        Disable trigger
	.Example
		Get-ZabbixTrigger -TemplateID (Get-zabbixTemplate | ? name -match "Template Name").templateid | ? description -match "trigger description" | Set-ZabbixTrigger -status 1
		Disable trigger
	.Example
		Get-ZabbixHost | ? name -match server0[1-5,7] | Get-ZabbixTrigger -ea silent | ? status -match 0 | ? expression -match "uptime" | select triggerid,expression,status | Set-ZabbixTrigger -status 1
		Disable trigger on multiple hosts
	.Example
		Get-ZabbixTemplate | ? name -match "Template" | Get-ZabbixTrigger | ? description -match triggerDescription | Set-ZabbixTrigger -status 0
		Enable trigger
	#>

	[CmdletBinding()]
	[Alias("sztr")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$TriggerID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$status,
		[switch]$ExpandDescription,
		[switch]$ExpandExpression,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "trigger.update"
			params = @{
				triggerid = $TriggerID
				status = $status
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function New-ZabbixTrigger {
	<# 
	.Synopsis
		Create new trigger settings
	.Description
		Create new trigger settings
	.Parameter TriggerID
		TriggerID
	.Example
		Get-ZabbixHost -HostName HostName | Get-ZabbixTrigger -ea silent | ? status -match 0 | ? expression -match "V:,pfree" | Set-ZabbixTrigger -status 1 -Verbose
        Disable trigger
	.Example
		Get-ZabbixTrigger -TemplateID (Get-zabbixTemplate | ? name -match "Template Name").templateid | ? description -match "trigger description" | Set-ZabbixTrigger -status 1
		Disable trigger
	.Example
		Get-ZabbixHost | ? name -match server0[1-5,7] | Get-ZabbixTrigger -ea silent | ? status -match 0 | ? expression -match "uptime" | select triggerid,expression,status | Set-ZabbixTrigger -status 1
		Disable trigger on multiple hosts
	.Example
		Get-ZabbixTemplate | ? name -match "Template" | Get-ZabbixTrigger | ? description -match triggerDescription | Set-ZabbixTrigger -status 0
		Enable trigger
	#>

	[CmdletBinding()]
	[Alias("nztr")]
	Param (
        # [Parameter(ValueFromPipelineByPropertyName=$true)]$TriggerID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$TriggerDescription,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$TriggerExpression,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$triggertags,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$dependencies,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		write-verbose ("dependencies: " + $dependencies.length)

		for ($i=0; $i -lt $dependencies.length; $i++) {[array]$depnds+=$(@{triggerid = $($dependencies[$i])})}

		$Body = @{
			method = "trigger.create"
			params = @{
				description = $TriggerDescription
				expression = $TriggerExpression
				# triggerid = $TriggerID
				status = $status
				dependencies = @($depnds)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixItem { 
	<#
	.Synopsis
		Retrieve items
	.Description
		Retrieve items
	.Example
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match hostName).hostid | select name,key_,lastvalue
		Get Items for host (case insensitive)
	.Example
		Get-ZabbixItem -ItemName 'RAM Utilization (%)' -HostId (Get-ZabbixHost | ? name -match "dc1").hostid | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},status,prevvalue,@{n="lastvalue";e={[decimal][math]::Round($_.lastvalue,3)}} | sort lastvalue -desc | ft -a
		Get Items  with name 'RAM Utilization (%)' for hosts by match
	.Example
		Get-ZabbixHost | ? name -match "Hosts" | Get-ZabbixItem -ItemName 'RAM Utilization (%)' | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},status,prevvalue,@{n="lastvalue";e={[decimal][math]::Round($_.lastvalue,3)}} | sort lastvalue -desc | ft -a
		Get Items  with name 'RAM Utilization (%)' for hosts by match, same as above
	.Example
		Get-ZabbixItem -ItemName 'Memory Total' -HostId (Get-ZabbixHost | ? name -match "").hostid | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},prevvalue,@{n="lastvalue";e={[decimal][math]::round(($_.lastvalue/1gb),2)}} | sort lastvalue -desc | ft -a
		Get Items  with name 'Memory Total' for hosts by match
	.Example
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -NotMatch host | ? name -match host).hostid | ? key_ -match "Processor time" | ? key_ -notmatch "vmver" | select  @{n="lastclock";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n='CPU%';e={[int]$_.lastvalue}},name,key_ | sort 'CPU%' -desc | ft -a
		Get hosts' CPU utilization	
	.Example	
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match host).hostid | ? key_ -match "/mnt/reporter_files,[used,free]" | ? lastvalue -ne 0 | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="lastvalue";e={[decimal][math]::round(($_.lastvalue/1gb),2)}},key_,description | sort host | ft -a
		Get Items for host(s) with key_ match
	.Example	
		Get-ZabbixItem -TemplateID (Get-ZabbixTemplate | ? name -match "myTemplates").templateid | ? history -ne 7 | select @{n="Template";e={$_.hosts.name}},history,name -Unique | sort Template
		Get Items for templates, where history not 7 days
	.Example
		Get-ZabbixTemplate | ? name -match "myTemplates" | Get-ZabbixItem | select @{n="Template";e={$_.hosts.name}},key_ -Unique | sort Template
		Get item keys for templates
	.Example
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match hostName).hostid | ? key_ -match "Version|ProductName" | ? key_ -notmatch "vmver" | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},lastvalue,name,key_ | sort host,key_ | ft -a
		Get Items by host match, by key_ match/notmatch
	.Example
		Get-ZabbixHost -hostname hostName | Get-ZabbixItem -SortBy status -ItemKey pfree | select name, key_,@{n="Time(UTC)";e={convertfrom-epoch $_.lastclock}},lastvalue,status | ft -a
		Get Items (disk usage(%) information) for single host
	.Example
		Get-ZabbixHost | ? name -match "hosts" | Get-ZabbixItem -ItemName 'RAM Utilization (%)' | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},prevvalue,lastvalue | sort hostname | ft -a
		Get Items for multiple hosts by match
	.Example
		Get-ZabbixHost | ? name -match "host|host" | Get-ZabbixItem | ? key_ -match HeapMemoryUsage.used | select @{n="lastclock";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n='HeapUsed';e={[int]$_.lastvalue/1mb}},name,key_ | ft -a
		Get java heap used by hosts (JMX)
	.Example
		Get-ZabbixItem -HostId (Get-ZabbixHost @zabSessionParams | ? name -NotMatch host | ? name -match host).hostid | ? name -match "Commit|RAM Utilization" | ? name -notmatch "%" | ? key_ -notmatch "vmver" | select   @{n="lastclock";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n='RAM(GB)';e={[math]::round($_.lastvalue/1gb,2)}},name,key_ | sort host,key_ | ft -a
		Get hosts' RAM utilization
	.Example
		Get-ZabbixItem -SortBy status -ItemKey pfree -HostId (Get-ZabbixHost | ? name -match hostName).hostid | select @{n="hostname";e={$_.hosts.name}},@{n="Time(UTC)";e={convertfrom-epoch $_.lastclock}},status,key_,lastvalue,name | sort hostname,key_ | ft -a
		Get Items (disk usage(%) info) for multiple hosts
	.Example
		Get-ZabbixItem -SortBy status -ItemKey pfree -HostId (Get-ZabbixHost | ? name -match hostName).hostid | ? key_ -match "c:" | select @{n="hostname";e={$_.hosts.name}},@{n="Time(UTC)";e={convertfrom-epoch $_.lastclock}},status,key_,lastvalue,name | sort hostname,key_ | ft -a
		Get Items (disk usage info) according disk match for multiple hosts
	.Example
		(1..8) | %{Get-ZabbixHost hostName-0$_ | Get-ZabbixItem -ItemKey 'java.lang:type=Memory' | ? status -match 0 | select key_,interfaces}
		Get Items and their interface
	.Example
        (1..8) | %{Get-ZabbixHost hostName-0$_ | Get-ZabbixItem -ItemKey 'MemoryUsage.used' | ? status -match 0 | select @{n="Host";e={$_.hosts.name}},@{n="If.IP";e={$_.interfaces.ip}},@{n="If.Port";e={$_.interfaces.port}},@{n="Application";e={$_.applications.name}},key_ } | ft -a
        Get Items and interfaces
	.Example
		Get-ZabbixItem -ItemKey 'version' -ItemName "Version of zabbix_agent(d) running" -HostId (Get-ZabbixHost | ? name -notmatch "DC2").hostid | ? status -match 0 | select @{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},key_,lastvalue | sort host
		Get Zabbix agent version
	.Example
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match "hostName").hostid | ? key_ -match "version" | ? key_ -notmatch "VmVersion" | ? lastvalue -ne 0 | ? applications -match "" | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_,@{n="If.IP";e={$_.interfaces.ip}},@{n="If.Port";e={$_.interfaces.port}} | sort host | ft -a 
		Get Java application versions via JMX
	.Example
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match "hostName").hostid | ? key_ -match "HeapMemoryUsage.committed" | ? lastvalue -ne 0 | ? applications -match "application" | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_,@{n="If.IP";e={$_.interfaces.ip}},@{n="If.Port";e={$_.interfaces.port}} | sort host | ft -a
		Get JVM memory usage via JMX
	.Example
        Cassandra: Get-ZabbixItem -ItemName 'AntiEntropySessions' -HostId (Get-ZabbixHost | ? name -match "cassandraNode").hostid | select  @{n="hostname";e={$_.hosts.name}},name,@{e={(convertfrom-epoch $_.lastclock).addhours(+1)};n="Time"},@{n="lastvalue";e={[math]::round(($_.lastvalue),2)}} | sort hostname | ft -a
        Cassandra: Get-ZabbixItem -ItemName 'Compaction' -HostId (Get-ZabbixHost | ? name -match "cassandraNodes").hostid | ? name -Match "CurrentlyBlockedTasks|Pending|ActiveTasks" | select @{n="hostname";e={$_.hosts.name}},name,@{e={(convertfrom-epoch $_.lastclock).addhours(+1)};n="Time"},@{n="lastvalue";e={[math]::round(($_.lastvalue),2)}} | sort hostname,name | ft -a
        Cassandra: Get-ZabbixItem -ItemName 'disk' -HostId (Get-ZabbixHost | ? name -match "cassandraNodes").hostid | ? key_ -match "cassandra,free" | select @{n="hostname";e={$_.hosts.name}},key_,@{e={(convertfrom-epoch $_.lastclock).addhours(+1)};n="Time"},@{n="prevvalue";e={[math]::round(($_.prevvalue/1gb),2)}},@{n="lastvalue";e={[math]::round(($_.lastvalue/1gb),2)}} | sort hostname | ft -a
        Cassandra: Get-ZabbixItem -ItemName 'byte' -HostId (Get-ZabbixHost | ? name -match "cassandraNodes").hostid | select @{n="hostname";e={$_.hosts.name}},key_,@{e={(convertfrom-epoch $_.lastclock).addhours(+1)};n="Time"},@{n="prevvalue";e={[math]::round(($_.prevvalue/1gb),2)}},@{n="lastvalue";e={[math]::round(($_.lastvalue/1gb),2)}} | sort hostname | ft -a
	#>
	
	[CmdLetBinding(DefaultParameterSetName="None")]
	[Alias("gzi")]
	Param (
		[String]$SortBy="name",
		[String]$ItemKey,
		[String]$ItemName,
		[string]$Description,
		[Parameter(ParameterSetName="hostname",Mandatory=$False,ValueFromPipelineByPropertyName=$true)][String]$HostName,
		[Parameter(ParameterSetName="hostid",Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostId,
		[Parameter(ParameterSetName="hostid",Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(ParameterSetName="hostid",Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TriggerID,
		[switch]$WebItems,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "item.get"
			params = @{
				output = "extend"
				webitems=$WebItems
				triggerids = $TriggerID
				templateids = $TemplateID
				hostids = @($HostID)
				groupids = $GroupID
				
				selectInterfaces = "extend"
				selectTriggers = "extend"
				selectApplications = "extend"
				selectHosts = @(
					"hostid",
					"name"
				)
				sortfield = $sortby
				
				search = @{
					key_ = $ItemKey
					name = $ItemName
				}
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixItem {
	<# 
	.Synopsis
		Set item properties
	.Description
		Set item properties
	.Parameter status
		status: 0 (enabled), 1 (disabled)
	.Parameter TemplateID
		Get by TemplateID
	.Example
		Get-ZabbixItem -TemplateID (Get-ZabbixTemplate | ? name -match "template").templateid | Set-ZabbixItem -status 1
		Disable items in the template(s)
	.Example
		Get-ZabbixItem -TemplateID (Get-ZabbixTemplate | ? name -match "template").templateid | sort name | select itemid,name,status | ? name -match name | select -first 1 | Set-ZabbixItem -status 0 -verbose
		Enable items in the template
	.Example
		Get-ZabbixItem -TemplateID (Get-ZabbixTemplate | ? name -match "template").templateid | sort name | select itemid,name,status | ? name -match name | ? status -match 0 | Set-ZabbixItem -status 1
		Disable items in the template
	.Example
		Get-ZabbixItem -TemplateID (Get-ZabbixTemplate | ? name -match "template").templateid | sort name | ? name -match name | Set-ZabbixItem -applicationid (Get-ZabbixApplication | ? name -match "application").applicationid -verbose
		Set application(s) for the items
	.Example
		Get-ZabbixHost | ? name -match "host" | Get-ZabbixItem | ? key_ -match "key" | ? status -match 0 | select hostid,itemid,key_,status | sort hostid,key_ | Set-ZabbixItem -status 1
		Disable host items (set status to 1)
	#>
    
	[CmdletBinding()]
	[Alias("szi")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$applicationid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$status,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$itemid,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		if ($applicationid) {
			$Body = @{
			method = "item.update"
			params = @{
				itemid = $itemid
				applications = $applicationid
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}
		}
		else {
			$Body = @{
				method = "item.update"
				params = @{
					itemid = $itemid
					status = $status
				}

				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixItem {
	<# 
	.Synopsis
		Remove item
	.Description
		Remove item
	.Parameter status
		status: 0 (enabled), 1 (disabled)
	.Parameter TemplateID
		Get by TemplateID
	.Example
		Get-ZabbixHost | ? name -match "host" | Get-ZabbixItem | ? key_ -match 'key1|key2|key3' | Remove-ZabbixItem
		Delete items from the host configuration
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzi")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$applicationid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$status,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$itemid,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		if ($applicationid) {
			$Body = @{
			method = "item.delete"
			params = @{
				itemid = $itemid
				applications = $applicationid
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
			}
		}
		else {
			$Body = @{
				method = "item.delete"
				params = @{
					itemid = $itemid
				}

				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Name,"Delete")){  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixEvent { 
	<#
	.Synopsis
		Get events
	.Example
		Get-ZabbixEvent -EventID 445750
		Get Event
	.Example
		Get-ZabbixEvent -TimeFrom (convertTo-epoch (get-date).addhours(-24)) | select @{n="Time UTC";e={convertfrom-epoch $_.clock}},@{n="Server";e={$_.hosts.name}},@{n="alerts";e={$_.alerts.subject[0]}}
		Get events for last 24 hours. According UTC/GMT+0 time. TimeTill is now in UTC/GMT+0 time
	.Example
		Get-ZabbixProblem | Get-ZabbixEvent | ft -a
		Get events
	.Example
		Get-ZabbixProblem | Get-ZabbixEvent | select @{n="clock(UTC+1)";e={(convertfrom-epoch $_.clock).addhours(1)}},* | ft -a 
		Get events. Time in UTC+1 
	.Example
		Get-ZabbixEvent -TimeFrom (convertTo-epoch (get-date).addhours(-24)) -TimeTill (convertTo-epoch (get-date).addhours(0)) | select @{n="Time UTC";e={convertfrom-epoch $_.clock}},@{n="Server";e={$_.hosts.name}},@{n="alerts";e={$_.alerts.subject[0]}}
		Get events for last 24 hours
	.Example
		Get-ZabbixEvent -TimeFrom (convertTo-epoch (get-date).addhours(-24*25)) -TimeTill (convertTo-epoch (get-date).addhours(0)) | ? alerts | ? {$_.hosts.name -match "webserver" } | select @{n="Time UTC";e={convertfrom-epoch $_.clock}},@{n="Server";e={$_.hosts.name}},@{n="alerts";e={$_.alerts.subject[0]}}
		Get events for last 25 days for servers with name match webserver
	.Example
		Get-ZabbixEvent -TimeFrom (convertTo-epoch (get-date).addhours(-5)) -TimeTill (convertTo-epoch (get-date).addhours(0)) | ? alerts | ? {$_.hosts.name -match "DB" } | select eventid,@{n="Time UTC+2";e={(convertfrom-epoch $_.clock).addhours(1)}},@{n="Server";e={$_.hosts.name}},@{n="alerts";e={$_.alerts.subject[0]}} | ft -a
		Get events from 5 days ago for servers with name match "DB", and display time in UTC+1
	.Example
		Get-ZabbixEvent -TimeFrom (convertTo-epoch (get-date).AddDays(-180)) -TimeTill (convertTo-epoch (get-date).AddDays(-150)) | ? alerts | ? {$_.hosts.name -match "host" } | select @{n="Time UTC";e={convertfrom-epoch $_.clock}},@{n="Server";e={$_.hosts.name}},@{n="alerts";e={$_.alerts.subject[0]}}
		Get past (180-150 days ago) events for host
    #>
	
	[cmdletbinding()]
	[Alias("gze")]
	Param (
		# epoch time
		$TimeFrom,
		# epoch time
		# Time until to display alerts. Default: till now. Time is in UTC/GMT
		$TimeTill=(convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()),
		$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$EventID,
		[array] $SortBy="clock",
        # Possible values for trigger events: 0 - trigger; 1 - discovered host; 2 - discovered service; 3 - auto-registered host
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$source, 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "event.get"
			params = @{
				output = "extend"
				select_acknowledges = "extend"
				time_from = $timeFrom
				time_till = $timeTill
				sortorder = "desc"
				select_alerts = "extend"
				eventids = $EventID
				selectHosts = @(
					"hostid",
					"name"
				)
				sortfield = @($sortby)
				filter = @{
					hostids = $HostID
				}
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixEvent { 
	<#
	.Synopsis
		Set events
	.Example
		Get-ZabbixEvent -EventID 445749 | Set-ZabbixEvent -ackMessage "TKT-2516: Resolved"
		Acknowledge event
	.Example
		Get-ZabbixEvent -TimeFrom (convertTo-epoch (get-date).addhours(-5)) -TimeTill (convertTo-epoch (get-date).addhours(0)) | ? alerts | ? {$_.hosts.name -match "web" } | select eventid,@{n="Time UTC+2";e={(convertfrom-epoch $_.clock).addhours(2)}},@{n="Server";e={$_.hosts.name}},@{n="alerts";e={$_.alerts.subject[0]}} | Set-ZabbixEvent -ackMessage TKT-2516: Resolved"
		Acknowledge events for last 5 hours for servers match name "web"
	#>
	
	[cmdletbinding()]
	[Alias("sze")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$EventID,
		$ackMessage,
		$HostID,
		[array] $SortBy="clock",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "event.acknowledge"
			params = @{
				eventids = $EventID
				message = $ackMessage
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixAlert { 
	<#
	.Synopsis
		Get alerts
	.Parameter HostID
		HostID
	.Example
		Get-ZabbixAlert | ? sendto -match email | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts from last 5 hours (default). Time display in UTC/GMT (default) 
	.Example
		Get-ZabbixAlert | ? sendto -match email | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.clock).addhours(+1)}},alertid,subject
		Get alerts from last 5 hours (default). Time display in UTC+1
	.Example
		Get-ZabbixAlert | ? sendto -match email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Get alerts from last 5 hours (default). Time display in UTC-5
	.Example
		Get-ZabbixAlert | ? sendto -match email | ? subject -match OK | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts with OK status
	.Example	
		Get-ZabbixAlert -TimeFrom (convertTo-epoch (((get-date).ToUniversalTime()).addhours(-10))) -TimeTill (convertTo-epoch (((get-date).ToUniversalTime()).addhours(-2))) | ? sendto -match mail | ? subject -match "" | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts within custom timewindow of 8 hours (-timeFrom, -timeTill in UTC/GMT). Time display in UTC/GMT (default)  
	.Example	
		Get-ZabbixAlert -TimeFrom (convertTo-epoch (((get-date).ToUniversalTime()).addhours(-5))) -TimeTill (convertTo-epoch ((get-date).ToUniversalTime()).addhours(0)) | ? sendto -match mail | select @{n="Time UTC";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts for last 5 hours
	.Example
		Get-ZabbixHost | ? name -match "hosts" | Get-ZabbixAlert | ? sendto -match mail | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Get alerts for hosts from last 5 hours (default). Display time in UTC-5 
	.Example
		Get-ZabbixHost -HostName "Server-01" | Get-ZabbixAlert -ea silent | ? sendto -match email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Works for single host (name case sensitive). Get alerts for host from last 5 hours (default). Display time in UTC-5
	.Example
		Get-ZabbixAlert -HostID (Get-ZabbixHost | ? name -match "Host|OtherHost").hostid | ? sendto -match email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Works for multiple hosts. Get alerts for hosts from last 5 hours (default). Display time in UTC-5
	.Example
		Get-ZabbixAlert -TimeFrom (convertTo-epoch ((get-date -date "05/25/2015 9:00").ToUniversalTime()).addhours(0)) -TimeTill (convertTo-epoch ((get-date -date "05/25/2015 14:00").ToUniversalTime()).addhours(0)) | ? sendto -match mail | select @{n="Time(UTC)";e={(convertfrom-epoch $_.clock).addhours(0)}},alertid,subject
		Get alerts between two dates (in UTC), present time in UTC
	#>
	
	[cmdletbinding()]
	[Alias("gzal")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		#epoch time
		#TimeFrom to display the alerts. Default: -5, from five hours ago. Time is in UTC/GMT"
		$TimeFrom=(convertTo-epoch ((get-date).addhours(-5)).ToUniversalTime()),
		#epoch time
		#TimeTill to display the alerts. Default: till now. Time is in UTC/GMT"
		$TimeTill=(convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()),
		[array] $SortBy="clock",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)

	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "alert.get"
			params = @{
				output = "extend"
				time_from = $timeFrom
				time_till = $timeTill
				selectMediatypes = "extend"
				selectUsers = "extend"
				selectHosts = @(
					"hostid",
					"name"
				)
				hostids = $HostID
				sortfield = @($sortby)
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Get-ZabbixAction { 
	<#
	.Synopsis
		Get actions
	.Description
		Get actions
	.Example
		Get-ZabbixAction
	.Example	
		Get-ZabbixAction | select name
	.Example	
		Get-ZabbixAction | ? name -match action | select name,def_longdata,r_longdata
	.Example
		Get-ZabbixAction  | ? name -match Prod | select name -ExpandProperty def_longdata	
	#>
	[cmdletbinding()]
	[Alias("gzac")]
	Param (
		[array] $SortBy="name",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "action.get"
			params = @{
				output = "extend"
				selectOperations = "extend"
				selectFilter = "extend"
				sortfield = @($sortby)
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixAction { 
	<#
	.Synopsis
		Set/Update action settings
	.Description
		Set/Update action settings
	.Example
		Get-ZabbixAction | ? name -match actionName | Set-ZabbixAction -status 1
		Disable action by name match
	#>
	
	[cmdletbinding()]
	[Alias("szac")]
	Param (
		[array] $SortBy="name",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$ActionID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "action.update"
			params = @{
				actionid = $ActionID
				status = $status
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixUser { 
	<#
	.Synopsis
		Get users
	.Parameter SortBy
		Sort output by (userid, alias (default)), not mandatory
	.Parameter getAccess
		Adds additional information about user permissions (default=$true), not mandatory
	.Example
		Get-ZabbixUser | select userid,alias,attempt_ip,@{n="attempt_clock(UTC)";e={convertfrom-epoch $_.attempt_clock}},@{n="usrgrps";e={$_.usrgrps.name}}
		Get users
	.Example
		Get-ZabbixUser | ? alias -match userName | select alias -ExpandProperty medias
		Get user medias
	.Example
		Get-ZabbixUser | ? alias -match userName | select alias -ExpandProperty mediatypes
		Get user mediatypes
	.Example
		Get-ZabbixUser | ? alias -match alias | select userid,alias,attempt_ip,@{n="attempt_clock(UTC)";e={convertfrom-epoch $_.attempt_clock}},@{n="usrgrps";e={$_.usrgrps.name}}
		Get users
	.Example
		Get-ZabbixUser | select name, alias, attempt_ip, @{n="attempt_clock (UTC-5)"; e={((convertfrom-epoch $_.attempt_clock)).addhours(-5)}},@{n="usrgrps";e={$_.usrgrps.name}} | ft -a
		Get users
	#>
	
	[cmdletbinding()]
	[Alias("gzu")]
	Param (
		[array]$SortBy="alias",
		[switch]$getAccess=$true,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$UserID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$MediaID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
	
		if (!(Get-ZabbixSession)) {return}
		
		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "user.get"
			params = @{
				output = "extend"
				selectMedias = "extend"
				selectMediatypes = "extend"
				selectUsrgrps = "extend"
				sortfield = @($sortby)
				getAccess = $getAccess
				userids = $UserID
				mediaids = $MediaID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Remove-ZabbixUser { 
    <#
	.Synopsis
		Remove/Delete users
	.Parameter UserID
		UserID
	.Example
		Get-ZabbixUser | ? alias -eq "alias" | Remove-ZabbixUser -WhatIf
		Delete one user
	.Example
		Get-ZabbixUser | ? alias -match "alias" | Remove-ZabbixUser
		Remove multiple users by alias match
	.Example
		Remove-ZabbixUser -UserID (Get-ZabbixUser | ? alias -match "alias").userid
		Delete multiple users by alias match
	.Example
		(Get-ZabbixUser | ? alias -match users) | ?{!$_.medias} | Remove-ZabbixUser
		Delete users who don't have media
	#>
	
	[cmdletbinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzu")]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$UserID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$Alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "user.delete"
			params = @($UserID)
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Alias,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function New-ZabbixUser { 
	<#
	.Synopsis
		Create new user
	.Parameter UserID
		UserID
	.Parameter Name
		User name
	.Parameter Surname
		User last name
	.Parameter Type
		Type of the user. Possible values: 1 - (default) Zabbix user; 2 - Zabbix admin; 3 - Zabbix super admin
	.Parameter Alias
		User alias. Example: firstname.lastname
	.Parameter Passwd
		User password
	.Parameter UserGroupID
		GroupID user belongs to
	.Parameter UserMediaSeverity
		User media settings: Severity. Trigger severities: Default: 63
	.Parameter UserMediaPeriod
		User media settings: Period. Example: "1-7,00:00-24:00"
	.Parameter UserMediaSendto
		User media settings: SendTo. Mostly email address
	.Parameter UserMediaActive
		User media settings: Active. User media enabled=0/disabled=1
	.Parameter mediatypeid
		Unique global media type id
	.Parameter RowsPerPage
		GUI frontend: Rows per page in web browser
	.Parameter Refresh
		GUI frontend: Automatic refresh period. Accepts seconds and time unit with suffix. Default: 30s
	.Parameter Autologin
		GUI frontend: Possible values: 0 - (default) auto-login disabled; 1 - auto-login enabled
	.Parameter Autologout
		GUI frontend: User session life time. Accepts seconds and time unit with suffix. If set to 0s, the session will never expire. Default: 15m
	.Parameter Theme
		GUI frontend: User's theme. Possible values: default - (default) system default; blue-theme - Blue; dark-theme - Dark
	.Parameter UserDefaultURL
		GUI frontend: URL of the page to redirect the user to after logging in
	.Example
		New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -sendto first.last@domain.com -UserGroupID 7,9 
		Create new user
	.Example
		New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -sendto first.last@domain.com -UserMediaActive 0 -rows_per_page 100 -Refresh 300 -UserGroupID (Get-ZabbixUserGroup | ? name -match "disabled|administrator" | select usrgrpid)
		Create new user (disabled)
	.Example
		New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -sendto first.last@domain.com -UserMediaActive 0 -rows_per_page 100 -Refresh 300 -UserGroupID (Get-ZabbixUserGroup | ? name -match "disabled|administrator").usrgrpid
		Create new user (disabled)
	.Example
		Import-Csv C:\zabbix-users.csv | %{New-ZabbixUser -Name $_.UserName -Surname $_.UserSurname -Alias $_.UserAlias -passwd "$_.Passwd" -UserMediaSendto $_.UserMediaSendto -UserMediaActive $_.UserMediaActive -rows_per_page $_.rows_per_page -Refresh $_.refresh -usrgrps (Get-ZabbixUserGroup | ? name -match "guest").usrgrpid}
		Mass create new users from the csv file
	.Example
		Import-Csv C:\zabbix-users.csv | %{New-ZabbixUser -Name $_.UserName -Surname $_.UserSurname -Alias $_.UserAlias -passwd "$_.Passwd" -UserMediaSendto $_.UserEmail -mediatypeid 1 -RowsPerPage 120 -Refresh 60s -UserGroupID (Get-ZabbixUserGroup | ? name -match "guest").usrgrpid}
		Mass create new users from the csv file
	.Example
		Get-ZabbixUser | ? alias -eq "SourceUser" | New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -sendto first@first.com -UserMediaActive 0 -rows_per_page 100 -Refresh 300
		Clone user. Enable media (-UserMediaActive 0)
	.Example
		Get-Zabbixuser | ? alias -eq "SourceUser" | New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -passwd "123456"
		Clone user
	.Example
		Get-ZabbixUser | ? alias -match "SourceUser" | New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -usrgrps (Get-ZabbixUserGroup | ? name -match disabled).usrgrpid
		Clone user, but disable it (assign to usrgrp Disabled)
	.Example
		Import-Csv C:\zabbix-users.csv | %{Get-Zabbixuser | ? alias -eq template.user | New-ZabbixUser -Name $_.UserName -Surname $_.UserSurname -Alias $_UserAlias -passwd "$_.Passwd" -UserMediaSendto $_.UserEmail}
		Mass create/clone from the user template
	.Example
		Import-Csv C:\zabbix-users.csv | %{Get-Zabbixuser | ? alias -eq template.user | New-ZabbixUser -Name $_.UserName -Surname $_.UserSurname -Alias $_UserAlias -passwd "$_.Passwd" -UserMediaSendto $_.UserEmail -UserMediaActive 1}
		Mass create/clone from the user template, but disable all medias for new users
	#>	
	
	[cmdletbinding()]
	[Alias("nzu")]
	Param (
		# [switch]$getAccess=$true,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$Alias,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$Passwd,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserGroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Surname,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$usrgrpid,
		# Trigger severities to send notifications about. Severities are stored in binary form with each bit representing the corresponding severity. For example, 12 equals 1100 in binary and means, that notifications will be sent from triggers with severities warning and average. 
		# Refer to the trigger object page for a list of supported trigger severities. Default: 63
		[Alias("severity")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$UserMediaSeverity="63",
		[Alias("period")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserMediaPeriod="1-7,00:00-24:00",
		[Alias("sendto")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserMediaSendto,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$mediatypeid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$usrgrps,
		[Alias("rows_per_page")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$RowsPerPage,
		# Whether the media is enabled. Possible values: 0 - (default) enabled; 1 - disabled.
		[Alias("active")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserMediaActive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$medias,
		# Type of the user. Possible values: 1 - (default) Zabbix user; 2 - Zabbix admin; 3 - Zabbix super admin.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$Type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$mediaTypes,
		# Automatic refresh period. Accepts seconds and time unit with suffix. Default: 30s.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Refresh,
		# Possible values: 0 - (default) auto-login disabled; 1 - auto-login enabled.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$Autologin,
		# User session life time. Accepts seconds and time unit with suffix. If set to 0s, the session will never expire. Default: 15m.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Autologout,
		# User's theme. Possible values: default - (default) system default; blue-theme - Blue; dark-theme - Dark.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][ValidateSet("default","blue-theme","dark-theme")][string]$Theme,
		# URL of the page to redirect the user to after logging in.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserDefaultURL,
		
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		if ($Autologin -and $Autologout) {Write-Host "`nAutologin and Autologout options cannot be enabled together!`n" -f red; return}
		
		if ($UserGroupID.length -gt 0) {
			if ($UserGroupID[0] -notmatch "[a-z][A-Z]") { for ($i=0; $i -lt $UserGroupID.length; $i++) {[array]$usrgrp+=$(@{usrgrpid = $($UserGroupID[$i])})} }
			else {$usrgrp=$UserGroupID}
		}

		# for ($i=0; $i -lt $UserGroupID.length; $i++) {[array]$usrgrp+=$(@{usrgrpid = $($UserGroupID[$i])})}
		# for ($i=0; $i -lt $medias.length; $i++) {$medias[$i].active=0}
		
		if ($UserMediaActive -and $medias) {for ($i=0; $i -lt $medias.length; $i++) {$medias[$i].active=$UserMediaActive}}
		if ($UserMediaSendto -and $medias) {for ($i=0; $i -lt $medias.length; $i++) {$medias[$i].sendto=$UserMediaSendto}}
		
		if ($medias) {$medias=$medias | select * -ExcludeProperty mediaid,userid}
		
		if (($UserMediaSendto -or $UserMediaActive) -and !$medias) {
			$Body = @{
				method = "user.create"
				params = @{
					name = $Name
					surname = $Surname
					alias = $Alias
					passwd = $Passwd
					url = $UserDefaultURL
					user_medias = @(
						@{
							mediatypeid = $mediatypeid
							sendto = $UserMediaSendto
							active = $UserMediaActive
							severity = $UserMediaSeverity
							period = $UserMediaPeriod
						}
					)
				}
				
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		elseif ($medias) {
			$Body = @{
				method = "user.create"
				params = @{
					name = $Name
					surname = $Surname
					alias = $Alias
					passwd = $Passwd
					url = $UserDefaultURL
					user_medias = @($medias)
				}
			
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		else {
			$Body = @{
				method = "user.create"
				params = @{
					name = $Name
					surname = $Surname
					alias = $Alias
					passwd = $Passwd
					url = $UserDefaultURL
				}
			
				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}

		if ($Type) {$Body.params.type=$Type}
		if ($Autologin) {$Body.params.autologin=$Autologin}
		if ($Autologout) {$Body.params.autologout=$Autologout}
		if ($Theme) {$Body.params.theme=$Theme}
		if ($Refresh) {$Body.params.refresh=$Refresh}
		if ($RowsPerPage) {$Body.params.rows_per_page=$RowsPerPage}
		if ($UserGroupID) {$Body.params.usrgrps=$usrgrp} else {$Body.params.usrgrps=@($usrgrps | select usrgrpid)}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Set-ZabbixUser { 
	<#
	.Synopsis
		Set user properties
	.Parameter UserID
		UserID
	.Parameter Name
		User name
	.Parameter Surname
		User last name
	.Parameter Type
		Type of the user. Possible values: 1 - (default) Zabbix user; 2 - Zabbix admin; 3 - Zabbix super admin
	.Parameter Alias
		User alias. Example: firstname.lastname
	.Parameter Passwd
		User password
	.Parameter UserGroupID
		GroupID user belongs to
	.Parameter UserMediaSeverity
		User media settings: Severity. Trigger severities: Default: 63
	.Parameter UserMediaPeriod
		User media settings: Period. Example: "1-7,00:00-24:00"
	.Parameter UserMediaSendto
		User media settings: SendTo. Mostly email address
	.Parameter UserMediaActive
		User media settings: Active. User media enabled=0/disabled=1
	.Parameter mediatypeid
		Unique global media type id
	.Parameter RowsPerPage
		GUI frontend: Rows per page in web browser
	.Parameter Refresh
		GUI frontend: Automatic refresh period. Accepts seconds and time unit with suffix. Default: 30s
	.Parameter Autologin
		GUI frontend: Possible values: 0 - (default) auto-login disabled; 1 - auto-login enabled
	.Parameter Autologout
		GUI frontend: User session life time. Accepts seconds and time unit with suffix. If set to 0s, the session will never expire. Default: 15m
	.Parameter Theme
		GUI frontend: User's theme. Possible values: default - (default) system default; blue-theme - Blue; dark-theme - Dark
	.Parameter UserDefaultURL
		GUI frontend: URL of the page to redirect the user to after logging in
	.Example
		Get-ZabbixUser | ? alias -eq "alias" | Set-ZabbixUser -Name NewName -Surname NewSurname -RowsPerPage 100 -UserGroupID 8 -Theme dark-theme
		Set user properties
	.Example
		Get-ZabbixUser | ? alias -match "alias" | Set-ZabbixUser -Name NewName -Surname NewSurname -RowsPerPage 100 -UserGroupID 8 -Theme dark-theme
		Same as above for multiple users
	.Example
		Get-Zabbixuser | ? alias -match "alias" | Set-ZabbixUser -UserGroupID (Get-ZabbixUserGroup | ? name -match disable).usrgrpid
		Disable users (by moving him to user group Disabled)
	.Example
		Get-ZabbixUser -getAccess | ? alias -match "user" | Set-ZabbixUser -Type 1
		Set user type (Zabbix User - 1, Zabbix Admin - 2, Zabbix Super Admin - 3 )
	.Example
		Get-ZabbixUser -UserID 71 | Set-ZabbixUser -UserGroupID (Get-ZabbixUserGroup | ? name -match "specialAccess|admin" |  select usrgrpid)
		Set user membership in user groups
	.Example
		Get-ZabbixUser -UserID 71 | Set-Zabbixuser -UserGroupID (Get-ZabbixUserGroup | ? name -match "specialAccess|admin").usrgrpid
		Set user membership in user groups
	.Example
		Get-ZabbixMediaType | select mediatypeid,type,description,status
		Get list of media types
		Get-ZabbixUser | ? alias -eq first.last | Set-Zabbixuser -UserMediaSendto new.email@example.com -UserMediaActive 0 -UserMediaSeverity 63 -mediatypeid 1 -UserGroupID 8,12
		Set user media properties (user email address, severity, enabled=0/disabled=1) for mediatypeid 1 (Email) and assign user to the user groups with ids 8 and 12
	.Example
		Get-ZabbixUser | ? alias -eq first.last | Set-ZabbixUser -matchMediatypeids "8|4" -UserMediaSendto first.last@domain.com -UserMediaSeverity 62
		Set multiple medias (8 and 4) for one user
	.Example
		Get-ZabbixUser | ? alias -eq first.last | Set-ZabbixUser -matchMediatypeids "" -UserMediaSendto first.last@domain.com -UserMediaSeverity 63 -UserMediaActive 0
		Set ALL! (careful) medias for user
	#>	
	
	[cmdletbinding()]
	[Alias("szu")]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$UserID,
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$usrgrpid,
		[Alias("usrgrpid")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserGroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Passwd,
		#user types: 1:Zabbix User,2:Zabbix Admin,3:Zabbix Super Admin 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$usrgrps,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$medias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$mediaid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$mediatypeid,

		[Alias("user_media")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$Media,
		# Amount of object rows to show per page. Default: 50.
		[Alias("rows_per_page")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$RowsPerPage,
		# Whether the media is enabled. Possible values: 0 - (default) enabled; 1 - disabled.
		[Alias("active")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserMediaActive,
		[Alias("sendto")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserMediaSendto,
		# Trigger severities to send notifications about. Severities are stored in binary form with each bit representing the corresponding severity. For example, 12 equals 1100 in binary and means, that notifications will be sent from triggers with severities warning and average. 
		# Refer to the trigger object page for a list of supported trigger severities. Default: 63
		[Alias("severity")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$UserMediaSeverity,
		[Alias("period")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserMediaPeriod,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Surname,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$Autologin,
		# User session life time. Accepts seconds and time unit with suffix. If set to 0s, the session will never expire. Default: 15m.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Autologout,
		# User's theme. Possible values: default - (default) system default; blue-theme - Blue; dark-theme - Dark.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][ValidateSet("default", "blue-theme", "dark-theme")][string]$Theme,
		# Automatic refresh period. Accepts seconds and time unit with suffix. Default: 30s.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Refresh,
		# Language code of the user's language. Default: en_GB.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Lang,
		# URL of the page to redirect the user to after logging in.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserDefaultURL,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][regex]$matchMediatypeids,

		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		if ($Autologin -and $Autologout) {Write-Host "`nAutologin and Autologout options cannot be enabled together!`n" -f red; return}
		if (!($matchMediatypeids -or $mediatypeid) -and ($UserMediaActive -or $UserMediaSendto -or $UserMediaSeverity -or $UserMediaPeriod)) {
			Write-Host "`n`nERROR: Missing parameters!`n`nFor single mediatypeid use -mediatypeid`nFor multiple mediatypeids use -matchMediatypeids" -f red
			Write-Host "`nHelp: gzh user -p mediatypeid`n`n" -f cyan
			return
		}  

		if ($UserGroupID.length -gt 0) {
			if ($UserGroupID[0] -notmatch "[a-z][A-Z]") { for ($i=0; $i -lt $UserGroupID.length; $i++) {[array]$usrgrp+=$(@{usrgrpid = $($UserGroupID[$i])})} }
			else {$usrgrp=$UserGroupID}
		}
		
		if ($matchMediatypeids) {
			$ErrorActionPreference="SilentlyContinue"
			if ($UserMediaActive) {for ($i=0; $i -lt $medias.length; $i++) {($medias[$i] | ? mediatypeid -match "$matchMediatypeids").active=$UserMediaActive}}
			if ($UserMediaSendto) {for ($i=0; $i -lt $medias.length; $i++) {($medias[$i] | ? mediatypeid -match "$matchMediatypeids").sendto=$UserMediaSendto}}
			if ($UserMediaSeverity) {for ($i=0; $i -lt $medias.length; $i++) {($medias[$i] | ? mediatypeid -match "$matchMediatypeids").severity=$UserMediaSeverity}}
			if ($UserMediaPeriod) {for ($i=0; $i -lt $medias.length; $i++) {($medias[$i] | ? mediatypeid -match "$matchMediatypeids").period=$UserMediaPeriod}}
			$ErrorActionPreference="Continue"
		}
		else {
			if ($UserMediaActive -and $mediatypeid) {($medias | ? mediatypeid -eq $mediatypeid).active=$UserMediaActive}
			if ($UserMediaSendto -and $mediatypeid) {($medias | ? mediatypeid -eq $mediatypeid).sendto=$UserMediaSendto}
			if ($UserMediaSeverity -and $mediatypeid) {($medias | ? mediatypeid -eq $mediatypeid).severity=$UserMediaSeverity}
			if ($UserMediaPeriod -and $mediatypeid) {($medias | ? mediatypeid -eq $mediatypeid).period=$UserMediaPeriod}
		}

		if ($medias) {$medias=$medias | select * -ExcludeProperty mediaid,userid}
		
		$Body = @{
			method = "user.update"
			params = @{
				userid = $UserID
				name = $Name
				surname = $Surname
				alias = $Alias
				type = $Type
				autologin = $Autologin
				autologout = $Autologout
				theme = $Theme
				refresh = $Refresh
				lang = $Lang
				rows_per_page = $RowsPerPage
				user_medias = @($medias)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		# if ($Type) {$Body.params.type=$Type}
		# if ($Autologin) {$Body.params.autologin=$Autologin}
		# if ($Autologout) {$Body.params.autologout=$Autologout}
		# if ($Theme) {$Body.params.theme=$Theme}
		# if ($Refresh) {$Body.params.refresh=$Refresh}
		# if ($RowsPerPage) {$Body.params.rows_per_page=$RowsPerPage}

		if ($UserDefaultURL) {$Body.params.url=$UserDefaultURL}	
		if ($Passwd) {$Body.params.passwd=$Passwd}
		if ($UserGroupID -or $usrgrp) {$Body.params.usrgrps=$usrgrp} else {$Body.params.usrgrps=@($usrgrps | select usrgrpid)}
		
		
		
		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixUserGroup { 
	<#
	.Synopsis
		Get user group
	.Description
		Get user group
	.Parameter SortBy
		Sort output by (usrgrpid, name (default)), not mandatory
	.Parameter getAccess
		adds additional information about user permissions (default=$true), not mandatory
	.Example
		Get-ZabbixUserGroup | select usrgrpid,name
		Get user groups
	.Example
		Get-ZabbixUserGroup | ? name -match administrators | select -ExpandProperty users | ft -a
		Get users in Administrators group
	.Example
		(Get-ZabbixUserGroup | ? name -match administrators).users | select alias,users_status
		Get users in user group
	#>
	
	[cmdletbinding()]
	[Alias("gzug")]
	Param (
		[array]$SortBy="name",
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$UserGroupName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$userids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "usergroup.get"
			params = @{
				output = "extend"
				selectUsers = "extend"
				selectRights = "extend"
				userids = $userids
				status = $status
				sortfield = @($sortby)
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function New-ZabbixUserGroup { 
	<#
	.Synopsis
		Create user group
	.Description
		Create user group
	.Parameter UserGroupName
		User group name
	.Parameter UserGroupDebugMode
		Enable/Disable debug mode for group members. Possible values are: 0 - (default) disabled; 1 - enabled
	.Parameter UserGroupGuiAccess
		Enable/Disable GUI access for group members. Possible values: 0 - (default) use the system default authentication method; 1 - use internal authentication; 2 - disable access to the frontend
	.Parameter UserGroupUsersStatus
		Enable/Disable status for group members. Possible values are: 0 - (default) enabled; 1 - disabled
	.Parameter UserGroupAccessRights
		Define access level for group members to the host groups. Possible values: 0 - access denied; 2 - read-only access; 3 - read-write access
	.Example
		New-ZabbixUserGroup -UserGroupName "NewUserGroup" -UserID 2,41,84
		Create new user group and assign the members
	.Example
		New-ZabbixUserGroup -UserGroupName "NewUserGroup" -UserID (Get-ZabbixUser | ? alias -match "user1|user2").userid -UserGroupUsersStatus 1 -UserGroupGuiAccess 2
		Create new user group, assign the members, all group members will be in disabled state, and will have no access to GUI frontend
	.Example
		(Get-ZabbixUserGroup | ? name -Match "SourceUserGroup") | New-ZabbixUserGroup -UserGroupName "NewUserGroup"
		Clone user group
	.Example
		$ROAccess=(Get-ZabbixHostGroup | ? name -match "ROHostGroup1|ROHostGroup2|ROHostGroup3").groupid | %{@{"permission"=2;"id"=$_}}
		1. Generate Read-Only access rights for certain host groups 
		$FullAccess=(Get-ZabbixHostGroup | ? name -match "RWHostGroup1|RWHostGroup2|RWHostGroup3").groupid | %{@{"permission"=3;"id"=$_}}
		2. Generate Read/Write access rights for certain host groups
		(Get-ZabbixUserGroup | ? name -Match "SourceUserGroup) | New-ZabbixUserGroup -UserGroupName "NewUserGroup" -UserGroupAccessRights ($ROAccess+$FullAccess)
		3. Clone user group and assign the new access rights
	#>
	
	[cmdletbinding()]
	[Alias("nzug")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupName,
		# Whether debug mode is enabled or disabled. Possible values are: 0 - (default) disabled; 1 - enabled.
		[Alias("debug_mode")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupDebugMode,
		# Frontend authentication method of the users in the group. Possible values: 0 - (default) use the system default authentication method; 1 - use internal authentication; 2 - disable access to the frontend.
		[Alias("gui_access")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupGuiAccess,
		# Whether the user group is enabled or disabled. Possible values are: 0 - (default) enabled; 1 - disabled.
		[Alias("users_status")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupUsersStatus,
		# ID of the host group to add permission to.
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupAccessRightsHostGroupID,
		# Access level to the host group. Possible values: 0 - access denied; 2 - read-only access; 3 - read-write access.
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupAccessRightsPermission,
		[Alias("rights")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserGroupAccessRights,
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$rights,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$userids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$users,

		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "usergroup.create"
			params = @{
				name  = $UserGroupName
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if ($UserGroupAccessRights) {$Body.params.rights=@(@($UserGroupAccessRights))}
		if ($UserID) {$Body.params.userids=$UserID} elseif ($users) {$Body.params.userids=@($users.userid)}
		if ($UserGroupGuiAccess) {$Body.params.gui_access=$UserGroupGuiAccess}
		if ($UserGroupDebugMode) {$Body.params.debug_mode=$UserGroupDebugMode}
		if ($UserGroupUsersStatus) {$Body.params.users_status=$UserGroupUsersStatus}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixUserGroup { 
	<#
	.Synopsis
		Update user group
	.Description
		Update user group
	.Parameter UserGroupName
		User group name
	.Parameter UserGroupDebugMode
		Enable/Disable debug mode for group members. Possible values are: 0 - (default) disabled; 1 - enabled
	.Parameter UserGroupGuiAccess
		Enable/Disable GUI access for group members. Possible values: 0 - (default) use the system default authentication method; 1 - use internal authentication; 2 - disable access to the frontend
	.Parameter UserGroupUsersStatus
		Enable/Disable status for group members. Possible values are: 0 - (default) enabled; 1 - disabled
	.Parameter UserGroupAccessRights
		Define access level for group members to the host groups. Possible values: 0 - access denied; 2 - read-only access; 3 - read-write access
	.Example
		Get-ZabbixUserGroup | ? name -eq "UserGroup" | Set-ZabbixUserGroup -UserID 2,4,8
		Replace users in the user group by new ones
	.Example
		$CurrentUsers=(Get-ZabbixUserGroup | ? name -eq "UserGroup").users.userid
		$NewUsers=(Get-ZabbixUser | ? name -match "user1|user2|user3|user4").userid
		(Get-ZabbixUserGroup | ? name -eq "UserGroup") | Set-ZabbixUserGroup -UserID ($currentUsers+$NewUsers)
		Add users to the user group
	.Example
		(Get-ZabbixUserGroup | ? name -Match "OldUserGroup") | Set-ZabbixUserGroup -UserGroupName "NewUserGroup"
		Rename user group
	.Example
		$ROAccess=(Get-ZabbixHostGroup | ? name -match "ROHostGroup1|ROHostGroup2|ROHostGroup3").groupid | %{@{"permission"=2;"id"=$_}}
		1. Generate Read-Only access rights for certain host groups 
		$FullAccess=(Get-ZabbixHostGroup | ? name -match "RWHostGroup1|RWHostGroup2|RWHostGroup3").groupid | %{@{"permission"=3;"id"=$_}}
		2. Generate Read/Write access rights for certain host groups
		(Get-ZabbixUserGroup | ? name -eq "UserGroup) | Set-ZabbixUserGroup -UserGroupAccessRights ($ROAccess+$FullAccess)
		3. Replace access permissions to the user group
	#>
	
	[cmdletbinding()]
	[Alias("szug")]
	Param (
		[Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupName,
		[Alias("usrgrpid")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupID,
		# Whether debug mode is enabled or disabled. Possible values are: 0 - (default) disabled; 1 - enabled.
		[Alias("debug_mode")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupDebugMode,
		# Frontend authentication method of the users in the group. Possible values: 0 - (default) use the system default authentication method; 1 - use internal authentication; 2 - disable access to the frontend.
		[Alias("gui_access")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupGuiAccess,
		# Whether the user group is enabled or disabled. Possible values are: 0 - (default) enabled; 1 - disabled.
		[Alias("users_status")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupUsersStatus,
		# ID of the host group to add permission to.
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupAccessRightsHostGroupID,
		# Access level to the host group. Possible values: 0 - access denied; 2 - read-only access; 3 - read-write access.
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$UserGroupAccessRightsPermission,
		[Alias("rights")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserGroupAccessRights,
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$rights,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$userids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$users,

		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "usergroup.update"
			params = @{
				usrgrpid = $UserGroupID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if ($UserGroupName) {$Body.params.name=$UserGroupName}
		if ($UserGroupAccessRights) {$Body.params.rights=@(@($UserGroupAccessRights))}
		if ($UserID) {$Body.params.userids=$UserID} elseif ($users) {$Body.params.userids=@($users.userid)}
		if ($UserGroupGuiAccess) {$Body.params.gui_access=$UserGroupGuiAccess}
		if ($UserGroupDebugMode) {$Body.params.debug_mode=$UserGroupDebugMode}
		if ($UserGroupUsersStatus) {$Body.params.users_status=$UserGroupUsersStatus}

		$BodyJSON = ConvertTo-Json $Body -Depth 3
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Remove-ZabbixUserGroup { 
    <#
	.Synopsis
		Remove/Delete user group
	.Description
		Remove/Delete user group
	.Parameter UserGroupID
		UserGroupID
	.Example
		Get-ZabbixUserGroup | ? name -match "group" | Remove-ZabbixUserGroup -WhatIf
		Whatif on delete multiple user groups
	.Example
		Get-ZabbixUserGroup | ? name -eq "UserGroup" | Remove-ZabbixUserGroup
		Delete user group
	.Example
		Remove-ZabbixUserGroup -UserGroupID (Get-ZabbixUserGroup | ? name -Match "UserGroup").usrgrpid -WhatIf
		Delete multiple user groups
	#>
	
	[cmdletbinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzug","Delete-ZabbixUserGroup")]
	Param (
		[Alias("usrgrpid")][Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][array]$UserGroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$UserGroupName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "usergroup.delete"
			params = @($UserGroupID)

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ($UserGroupID.count -gt 0) {
			if ([bool]$WhatIfPreference.IsPresent) {}
			if ($PSCmdlet.ShouldProcess("$((Get-ZabbixUserGroup | ? usrgrpid -match ($UserGroupID -join "|")).name)","Delete")) {  
				$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			}
		}
		else {
			if ([bool]$WhatIfPreference.IsPresent) {}
			if ($PSCmdlet.ShouldProcess("$(Get-ZabbixUserGroup | ? usrgrpid -eq $UserGroupID | select usrgrpid,name)","Delete")) {  
				$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			}
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixHistory { 
	<#
	.Synopsis
		Get History
	.Description
		Get History
	.Example
		Get-ZabbixHistory -ItemID (get-zabbixhost | ? name -match "server" | Get-ZabbixItem | ? name -match "system information").itemid
		Get history for item "system information", for server "server" for last 48 hours (default) present time in UTC/GMT (default)
	.Example
		Get-ZabbixHistory -ItemID (get-zabbixhost | ? name -match "server" | Get-ZabbixItem | ? name -match "system information").itemid | select itemid,@{n="clock(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},value
		Get history for item "system information", for server "server" for last 48 hours (default) present time in UTC/GMT-5
	.Example
        Get-ZabbixHistory -ItemID (get-zabbixhost -hostname  "server" | Get-ZabbixItem -webitems -ItemKey web.test.error -ea silent).itemid -TimeFrom (convertTo-epoch (get-date).adddays(-10)) | select itemid,@{n="clock(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},value
		Get history for web/http test errors for host "server" for last 10 days. present time in UTC/GMT-5
	#>
	[cmdletbinding()]
	[Alias("gzhist")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$ItemID,
		#epoch time
		#TimeFrom to display the history. Default: -48, form 48 hours ago. Time is in UTC/GMT+0
		$TimeFrom=(convertTo-epoch ((get-date).addhours(-48)).ToUniversalTime()),
		#epoch time
		#TimeTil to display the history. Default: till now. Time is in UTC/GMT+0
		$TimeTill=(convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()),
		#Limit output to #lines. Default: 50
		$Limit=50,
		#can sort by: itemid and clock. Default: by clock.
		[array] $SortBy="clock",
		#History object type to return: 0 - float; 1 - string; 2 - log; 3 - integer; 4 - text. Default: 1
		$History=1,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)

	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "history.get"
			params = @{
				output = "extend"
				history = $History
				itemids = $ItemID
				sortfield = $SortBy
				sortorder = "DESC"
				limit = $Limit
				hostids = $HostID
				time_from = $TimeFrom
				time_till = $TimeTill
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Get-ZabbixApplication {
	<# 
	.Synopsis
		Get application
	.Description
		Get application
	.Parameter HostID
		Get by HostID
	.Parameter TemplateID
		Get by TemplateID
	.Example
		Get-ZabbixApplication | ? name -match "appname" | ft -a
		Get applications by name match
	.Example
		Get-ZabbixHost -HostName HostName | Get-ZabbixApplication | ft -a
		Get applications by hostname (case sensitive)
	.Example
		Get-ZabbixApplication | ? name -match "appname" | ft -a
		Get applications by name match 
	.Example
		Get-ZabbixTemplate | ? name -match Template | Get-ZabbixApplication  | ft -a
		Get application and template
	.Example
		Get-ZabbixApplication -TemplateID (Get-ZabbixTemplate | ? name -match templateName).templateid | ? name -match "appName" | ft -a
		Get applications by TemplateID
	.Example
		Get-ZabbixTemplate | ? name -match templateName | %{Get-ZabbixApplication -TemplateID $_.templateid } | ft -a
		Get applications by TemplateID
	.Example
		Get-ZabbixHostGroup -GroupName "GroupName" | Get-ZabbixApplication
		Get applications by GroupName (case sensitive)
	.Example
		Get-ZabbixHost | ? name -eq SourceHost | Get-ZabbixApplication | New-ZabbixApplication -HostID (Get-ZabbixHost | ? name -match newHost).hostid
		Clone application(s) from host to host
	.Example
		Get-ZabbixHost | ? name -eq host | Get-ZabbixApplication | New-ZabbixApplication -HostID (Get-ZabbixTemplate | ? name -match "templateName").templateid
		Clone application(s) from template to template
	#>
    
	[CmdletBinding()]
	[Alias("gzapp")]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "application.get"
			params = @{
				output = "extend"
				selectHost = @(
					"hostid",
					"host"
				)
				# selectItems = "extend"
				selectDiscoveryRule = "extend"
				selectApplicationDiscovery = "extend"
				sortfield = "name"
				hostids = $HostID
				groupids = $GroupID
				templateids = $TemplateID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixApplication {
	<# 
	.Synopsis
		Set/Update application
	.Description
		Set/Update application
	.Example
		Get-ZabbixTemplate | ? name -match "templateName" | Get-ZabbixApplication | ? name -match appName | Set-ZabbixApplication -Name newAppName
		Rename application in the template
	#>
    
	[CmdletBinding()]
	[Alias("szapp")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$applicationid,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "application.update"
			params = @{
				applicationid = $applicationid
				name = $Name
				# hostid = $HostID
				# templateids = $TemplateID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixApplication {
	<# 
	.Synopsis
		Remove/Delete applications
	.Description
		Remove/Delete applications
	.Example
		Get-ZabbixTemplate | ? name -match "templateName" | Get-ZabbixApplication | ? name -match "appName" | Delete-ZabbixApplication
		Delete application from the template
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("Delete-ZabbixApplication","rzapp")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$applicationId,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "application.delete"
			params = @($applicationId)

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess("$($Name+"@"+(Get-ZabbixApplication | ? name -eq "$Name" | ? hostid -eq $HostID).host.host)","Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}

		if ($a.result) {$a.result} else {$a.error}
	}
}

Function New-ZabbixApplication {
	<# 
	.Synopsis
		Create new application
	.Description
		Create new application
	.Example
		New-ZabbixApplication -Name newAppName -HostID (Get-ZabbixHost | ? name -match host).hostid
		Create new application on host
	.Example
		Get-ZabbixHost | ? name -match "hostName" | New-ZabbixApplication -Name newAppName
		Create new application on host
	.Example
		Get-ZabbixHost | ? name -eq SourceHost | Get-ZabbixApplication | New-ZabbixApplication -HostID (Get-ZabbixHost | ? name -match newHost).hostid
		Clone application(s) from host to host
	.Example
		New-ZabbixApplication -Name newAppName -HostID (Get-ZabbixTemplate | ? name -match template).hostid
		Create new application in template
	.Example
		Get-ZabbixTemplate | ? name -match "templateName" | New-ZabbixApplication -name newAppName 
		Create new application in template
	#>
    
	[CmdletBinding()]
	[Alias("nzapp")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Name,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$TemplateID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}
		
		If (!$HostID -and !$TemplateID) {write-host "`nHostID or TemplateID is required.`n" -f red; Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | Remove-EmptyLines; break}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		if ($HostID) {
			$Body = @{
				method = "application.create"
				params = @{
					name = $Name
					hostid = $HostID
				}

				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}
		if ($TemplateID) {
			$Body = @{
				method = "application.create"
				params = @{
					name = $Name
					hostid = $TemplateID
				}

				jsonrpc = $jsonrpc
				id = $id
				auth = $session
			}
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixHostInterface { 
	<#
	.Synopsis
		Get host interface
	.Description
		Get host interface
	.Example
		Get-ZabbixHostInterface -HostID (Get-ZabbixHost -HostName ThisHost).hostid |ft -a
		Get interface(s) for single host (case sensitive)
	.Example	
		Get-ZabbixHostInterface -HostID (Get-ZabbixHost | ? name -match hostName).hostid
		Get interface(s) for multiple hosts (case insensitive)
	.Example
		Get-ZabbixHost -HostName HostName | Get-ZabbixHostInterface | ft -a
		Get interfaces for host
	.Example	
		hGet-ZabbixHost | ? name -match HostName | Get-ZabbixHostInterface | ft -a
		Get interfaces for multiple hosts
	.Example	
		Get-ZabbixHost | ? name -match HostName | Get-ZabbixHostInterface | ? port -match 10050 | ft -a
		Get interface matching port for multiple hosts
	.Example	
		Get-ZabbixHost -HostName HostName | Get-ZabbixHostInterface
		Get interface(s) for single host (case sensitive)
	.Example
		Get-ZabbixHost | ? name -match hostsName | %{$n=$_.name; Get-ZabbixHostInterface -HostID $_.hostid} | select @{n="name";e={$n}},hostid,interfaceid,ip,port | sort name | ft -a
		Get interface(s) for the host(s)
	#>
	[cmdletbinding()]
	[Alias("gzhsti")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "hostinterface.get"
			params = @{
				output = "extend"
				hostids = $HostID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

######### --> This should be checked ---> start
Function Set-ZabbixHostInterface { 
	<#
	.Synopsis
		Set host interface
	.Description
		Set host interface
	.Parameter HostID
		HostID
	.Parameter IP
		Interface IP address
	.Parameter DNS
		Interface DNS name
	.Parameter Port
		Interface Port
	.Parameter main
		Interface Main: Possible values are:  0 - not default;  1 - default
	.Parameter type
		Interface Type: Possible values are:  1 - agent;  2 - SNMP;  3 - IPMI;  4 - JMX
	.Parameter useIP
		Interface UseIP: Possible values are:  0 - connect using host DNS name;  1 - connect using host IP address for this host interface
	.Example
		Get-ZabbixHost | ? name -match host | Get-ZabbixHostInterface | %{Set-ZabbixHostInterface -IP 10.20.10.10 -InterfaceID $_.interfaceid -HostID $_.hostid -Port $_.port}
		Set new IP to multiple host interfaces
	.Example
		Get-ZabbixHost | ? name -match host | Get-ZabbixHostInterface | ? port -notmatch "10050|31001" | ? main -match 1 | Set-ZabbixHostInterface -main 0
		Set interfaces on multiple hosts to be not default 	
	.Example
		Get-ZabbixHost | ? name -match host | Get-ZabbixHostInterface | ? port -match 31021 | Set-ZabbixHostInterface -main 0
		Set interface matches port 31021 on multiple hosts to default
	.Example
		Get-ZabbixHost -HostName MyHost | Get-ZabbixHostInterface | Set-ZabbixHostInterface -dns MyHost.example.com -useIP 0
		Set interface DNS name and order to connect to host by DNS name and not by IP address
	.Example
		Get-ZabbixHost | ? name -match host | Get-ZabbixHostInterface | ? type -eq 4 | Remove-ZabbixHostInterface
		Remove all JMX (type 4) interfaces from host
	#>
	[cmdletbinding()]
	[Alias("szhsti")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$InterfaceID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$IP,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$DNS="",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Port,
		#Main: Possible values are:  0 - not default;  1 - default. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$main,
		#Type: Possible values are:  1 - agent;  2 - SNMP;  3 - IPMI;  4 - JMX. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$type="4",
		#UseIP: Possible values are:  0 - connect using host DNS name;  1 - connect using host IP address for this host interface. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$useIP="1",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}
		
		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "hostinterface.update"
			params = @{
				hostid = $HostID
				interfaceid = $InterfaceID
				port = $Port
				ip = $IP
				main = $main
				dns = $DNS
				useip = $useIP
				type = $type
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}
######### --> This should be checked ---> end

Function New-ZabbixHostInterface { 
	<#
	.Synopsis
		Create host interface
	.Description
		Create host interface
	.Parameter HostID
		HostID
	.Parameter IP
		Interface IP address
	.Parameter DNS
		Interface DNS name
	.Parameter Port
		Interface Port
	.Parameter main
		Interface Main: Possible values are:  0 - not default;  1 - default
	.Parameter type
		Interface Type: Possible values are:  1 - agent;  2 - SNMP;  3 - IPMI;  4 - JMX
	.Parameter useIP
		Interface UseIP: Possible values are:  0 - connect using host DNS name;  1 - connect using host IP address for this host interface
	.Example
		Get-ZabbixHost | ? name -match host | New-ZabbixHostInterface -IP 10.20.10.15 -port 31721
		Create new interface for host
	.Example	
		Get-ZabbixHost | ? name -match "host01" | New-ZabbixHostInterface -Port 31721 -type 4 -main 1 -ip (Get-ZabbixHost | ? name -match "host01").interfaces.ip
		Create new interface for host
	.Example	
		Get-ZabbixHost | ? name -match hosts | select hostid,name,@{n="ip";e={$_.interfaces.ip}} | New-ZabbixHostInterface -Port 31001 -type 4 -main 1 -verbose
		Get-ZabbixHost | ? name -match hosts | select name,*error* | ft -a
		Create new JMX (-type 4) interface to hosts and check if interface has no errors 
	.Example	
		(1..100) | %{Get-ZabbixHost | ? name -match "host0$_" | New-ZabbixHostInterface -Port 31721 -type 4 -main 0 -ip (Get-ZabbixHost | ? name -match "host0$_").interfaces.ip[0]}
		Create new interface for multiple hosts 
	.Example
		(1..100) | %{Get-ZabbixHost | ? name -match "host0$_" | Get-ZabbixHostInterface | ? port -match 31751 | Set-ZabbixHostInterface -main 0}
		Make existing JMX port not default
	.Example		
		(1..100) | %{Get-ZabbixHost | ? name -match "host0$_" | New-ZabbixHostInterface -Port 31771 -type 4 -main 1 -ip (Get-ZabbixHost | ? name -match "host0$_").interfaces.ip[0]}
		Create new JMX interface and set it default
	.Example	
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match "one|two|three|four").hostid | ? key_ -match "version" | ? key_ -notmatch "VmVersion" | ? lastvalue -ne 0 | ? applications -match "app1|app2|app3|app3" | select @{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_,interfaces | sort host,application | ft -a
		Check whether new settings are working
	.Example
		Get-ZabbixHost | ? name -match hostname | Get-ZabbixHostInterface | ? port -match 31021 | Set-ZabbixHostInterface -main 0
		Get-ZabbixHost | ? name -match hostname | Get-ZabbixHostInterface | ? port -match 31021 | ft -a
		Get-ZabbixHost | ? name -match hostname | select hostid,name,@{n="ip";e={$_.interfaces.ip[0]}} | New-ZabbixHostInterface -Port 31001 -type 4 -main 1 -verbose
		Get-ZabbixHost | ? name -match hostname | Get-ZabbixHostInterface | ft -a
		Manually add new template for created interface 
		Run the checks: 
		Get-ZabbixHost | ? name -match hostname | select name,*error* | ft -a
		Get-ZabbixHost | ? name -match hostname | select name,*jmx* | ft -a
		Get-ZabbixItem -HostId (Get-ZabbixHost | ? name -match hostname).hostid | ? key_ -match "Version|ProductName|HeapMemoryUsage.used" | ? key_ -notmatch "vmver" | select  @{n="lastclock";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_ | sort host,application,key_ | ft -a 
		Add new JMX interface with matching new JMX template, step by step	
	#>
	[cmdletbinding()]
	[Alias("nzhsti")]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$HostID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$IP,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$DNS="",
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$Port,
		#Main: Possible values are:  0 - not default;  1 - default. 
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$main="0",
		#Type: Possible values are:  1 - agent;  2 - SNMP;  3 - IPMI;  4 - JMX. 
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$type="4",
		#UseIP: Possible values are:  0 - connect using host DNS name;  1 - connect using host IP address for this host interface. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$useIP="1",
		#[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$InterfaceID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "hostinterface.create"
			params = @{
				hostid = $HostID
				main = $main
				dns = $dns
				port = $Port
				ip = $IP
				useip = $useIP
				type = $type
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixHostInterface { 
	<#
	.Synopsis
		Remove host interface
	.Description
		Remove host interface
	.Example
		Get-ZabbixHost | ? name -match "host02" | Get-ZabbixHostInterface | ? port -Match 31021 | Remove-ZabbixHostInterface
		Remove single host interface
	.Example	
		Remove-ZabbixHostInterface -interfaceid (Get-ZabbixHost | ? name -match "host02" | Get-ZabbixHostInterface).interfaceid
		Remove all interfaces from host
	.Example	
		Get-ZabbixHost | ? name -match hostName | ? name -notmatch otherHostName | Get-ZabbixHostInterface | ? port -match 31021 | Remove-ZabbixHostInterface
		Remove interfaces by port
	#>
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzhsti")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$InterfaceId,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$Port,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "hostinterface.delete"
			params = @($interfaceid)

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($Port,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixScreen {
	<# 
	.Synopsis
		Get screen from zabbix server
	.Description
		Get screen from zabbix server
	.Example
		Get-ZabbixScreen | ? name -match screenName
		Get screen 
	.Example
		Get-ZabbixScreen | ? name -match "" | select * -ExcludeProperty screenitems | ft -a
		Get screen
	.Example
		Get-ZabbixScreen | ? name -match screenName | select * -ExcludeProperty screenitems | ft -a
		Get screen
	.Example
		Get-ZabbixScreen | ? name -match "" | select -Expands screenitems | ft -a
		Get screen items
	.Example
		Get-ZabbixScreen -ScreenID 20
		Get screen
	.Example
		Get-ZabbixScreen -UserID 1 | select screenid,name,userid | ft -a
		Get screen
	.Example
		Get-ZabbixScreen -UserID (Get-ZabbixUser | ? alias -match admin).userid
		Get screen
	.Example
		Get-ZabbixScreen | ? name -match screenName | Get-ZabbixUser
		Get user, screen belongs to
	.Example
		Get-ZabbixScreen -pv screen | ? name -match screenName | Get-ZabbixUser | select @{n='Screen';e={$screen.Name}},userid,alias
		Get screen names and related user info
	#>
    
	[CmdletBinding()]
	[Alias("gzscr")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$UserID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$ScreenID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$ScreenItemID,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URL=($global:zabSessionParams.url)
    )
    
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
	
		$Body = @{
			method = "screen.get"
			params = @{
				output = "extend"
				selectUsers = "extend"
				selectUserGroups = "extend"
				selectScreenItems = "extend"
				screenids = $ScreenID
				userids = $UserID
				screenitemids = $ScreenItemID
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Get-ZabbixProblem { 
	<#
	.Synopsis
		Get Problems
	.Description
		Get Problems
	.Example
		Get-ZabbixProblem | select @{n="clock(UTC+2)";e={(convertfrom-epoch $_.clock).addhours(2)}},* | ft -a
		Get Problems
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$objectids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		
		$Body = @{
			method = "problem.get"
			params = @{
				output = "extend"
				selectAcknowledges = "extend"
				selectTags  = "extend"
				objectids = $objectid
				recent 	= "true"
				sortfield = "eventid"
				sortorder = "DESC"	
				
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixGraph { 
	<#
	.Synopsis
		Get graph
	.Description
		Get graph
	.Example
		Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph | select name
		Get graphs for single host
	.Example
		Get-ZabbixHost | ? name -match hosName |  Get-ZabbixGraph | select name
		Get graphs for multiple hosts	
	.Example	
		Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph -expandName | ? name -match 'RAM utilization' | select name
        Get graphs for single host     
	.Example
        Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph -expandName | ? name -match 'RAM utilization' | select name -ExpandProperty gitems | ft -a
        Get graphs for single host	
	.Example	
		Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph -expandName | ? {!$_.graphDiscovery} | select name -ExpandProperty gitems | ft -a
        Get graphs for single host
    .Example
		Get-ZabbixHost | ? name -match "hostName" | Get-ZabbixGraph -expandName | ? {!$_.graphDiscovery} | select name -ExpandProperty gitems | ft -a
		Get graphs for multiple hosts
    .Example
		Get-ZabbixHost | ? name -match "hostName" | Get-ZabbixGraph -expandName | ? {!$_.graphDiscovery} | select name -ExpandProperty gitems -Unique | ft -a
		Get-ZabbixHost | ? name -match "hostName" | Get-ZabbixGraph  -expandName | ? { !$_.graphDiscovery } | select name -Unique
		Get graphs for multiple hosts, sort out duplicates
	.Example
        Get-ZabbixGraph -HostID (Get-ZabbixHost | ? name -match "multipleHosts").hostid | select @{n="host";e={$_.hosts.name}},name | ? host -match "host0[5,6]"| ? name -notmatch Network | sort host
        Get graphs for multiple hosts
	#>
    
	[cmdletbinding()]
	[Alias("gzgph")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GraphID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$ItemID,
		[switch]$expandName=$true,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {
		
		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "graph.get"
			params = @{
				output = "extend"
				selectTemplates = "extend"
				selectHosts = @(
					"hostid",
					"name"
				)
				selectItems = "extend"
				selectGraphItems = "extend"
				selectGraphDiscovery = "extend"
				expandName = $expandName
				hostids = $HostID
				graphids = $GraphID
				templateids = $TemplateID
				itemids = $ItemID
				sortfield = "name"
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Save-ZabbixGraph {
	<#
	.Synopsis
		Save graph
	.Description
		Save graph
	.Example
		Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph | ? name -match 'CPU utilization' | Save-ZabbixGraph -verbose 
		Save single graph (default location: $env:TEMP\psbbix)
	.Example
		Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph | ? name -match 'CPU utilization' | Save-ZabbixGraph -sTime (convertTo-epoch (get-date).AddMonths(-3)) -fileFullPath $env:TEMP\psbbix\graphName.png -show 
		Save single graph and show it
	.Example
		Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph | ? name -eq 'RAM utilization (%)' | Save-ZabbixGraph -sTime (convertto-epoch (get-date -date "05/25/2015 00:00").ToUniversalTime()) -show
		Save single graph, time sent as UTC, and will appear as local Zabbix server time
	.Example	
		(Get-ZabbixHost | ? name -eq "singleHost" | Get-ZabbixGraph | ? name -match 'RAM utilization | CPU utilization').graphid | %{Save-ZabbixGraph -GraphID $_ -sTime (convertto-epoch (get-date -date "05/25/2015 00:00")) -fileFullPath $env:TEMP\psbbix\graphid-$_.png -show}
		Save and show graphs for single host
	.Example
		(Get-ZabbixGraph -HostID (Get-ZabbixHost | ? name -match "multipleHosts").hostid | ? name -match 'RAM utilization | CPU utilization').graphid | %{Save-ZabbixGraph -GraphID $_ -sTime (convertto-epoch (get-date -date "05/25/2015 00:00")) -verbose -show}
		Save multiple graphs for multiple hosts
	.Example
		(Get-ZabbixGraph -HostID (Get-ZabbixHost | ? name -match "multipleHosts").hostid | ? name -match 'RAM utilization | CPU utilization').graphid | %{Save-ZabbixGraph -GraphID $_ -sTime (convertto-epoch (get-date -date "05/25/2015 00:00")) -show -mail -from "zabbix@domain.com" -to first.last@mail.com -smtpserver 10.10.20.10 -priority High}
		Save and send by email multiple graphs, for multiple hosts
    #>
    
	[cmdletbinding()]
	[Alias("szgph")]
	param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$GraphID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$fileFullPath,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][string]$sTime=(convertTo-epoch ((get-date).addmonths(-1)).ToUniversalTime()),
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Period=(convertTo-epoch ((get-date).addhours(0)).ToUniversalTime())-$sTime,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Width="900",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Hight="200",
		[switch]$show,
        [switch]$mail,
        [string]$SMTPServer,
        [string[]]$to,
        [string]$from,
        [string]$subject,
        [string]$priority,
        [string]$body
	)

	if (!(Get-ZabbixSession)) {return}
	elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

	$boundparams=$PSBoundParameters | out-string
	write-verbose "($boundparams)"
    
    $psbbixTmpDir="$env:TEMP\psbbix"
    if (!$fileFullPath) {
        if (!(test-path $psbbixTmpDir)) {mkdir $psbbixTmpDir}
        $fileFullPath="$psbbixTmpDir\graph-$graphid.png"
    }
	write-verbose "Graph files located here: $psbbixTmpDir"
	write-verbose "Full path: $fileFullPath"
	
	if ($noSSL) {
		$gurl=($zabSessionParams.url.replace('https','http'))
        try {invoke-webrequest "$gurl/chart2.php?graphid=$graphid`&width=$Width`&hight=$Hight`&stime=$sTime`&period=$Period" -OutFile $fileFullPath}
        catch {write-host "$_"}
	} else {
		$gurl=$zabSessionParams.url
        write-host "SSL doesn't work currently." -f yellow
	}

	if ($show) {
        if (test-path "c:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {&"c:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -incognito $fileFullPath}
        elseif (test-path "c:\Program Files\Internet Explorer\iexplore.exe") {&"c:\Program Files\Internet Explorer\iexplore.exe" $fileFullPath}
        else {start "file:///$fileFullPath"}
	}
	
	if ($mail) {
        if (!$from) {$from="zabbix@example.net"}
        if ($subject) {$subject="Zabbix: graphid: $GraphID. $subject"}
        if (!$subject) {$subject="Zabbix: graphid: $GraphID"}
	    try {
            if ($body) {Send-MailMessage -from $from -to $to -subject $subject -body $body -Attachments $fileFullPath -SmtpServer $SMTPServer}
            else {Send-MailMessage -from $from -to $to -subject $subject -Attachments $fileFullPath -SmtpServer $SMTPServer}
        } catch {$_.exception.message}
	}
}

Function Get-ZabbixMediaType { 
	<#
	.Synopsis
		Get media types
	.Description
		Get media types
	.Example
		Get-ZabbixMediaType 
		Get media types
	.Example
		Get-ZabbixMediaType | ? description -match email
		Get Email media type 
	.Example
		Get-ZabbixMediaType | ? descr* -eq EmailMediaType | New-ZabbixMediaType -Description "DisabledCopyOfEmailMediaType" -status 1
		Copy/Clone existing media type to new one, and disable it		
	#>
	[cmdletbinding()]
	[Alias("gzmt")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		
		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "mediatype.get"
			params = @{
				output = "extend"
				selectUsers = "extend"
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function New-ZabbixMediaType { 
	<#
	.Synopsis
		Create media types
	.Description
		Create media types
	.Example
		$EmailMediaTypeCreateParams=@{
			Description="EmailMediaType-01"
			Type=0
			MaxAlertSendSessions=5
			MaxAlertSendAttempts=5
			AlertSendRetryInterval="12s"
			SMTPServerIPorFQDN="mail.example.com"
			SMTPServerPort=25
			SMTPServerHostName="mail"
			EmailAddressFrom="zabbix-01@example.com"
			SMTPServerAuthentication=1
			Username="testUser"
			Passwd="TestUser"
			SMTPServerConnectionSecurity=""
			SMTPServerConnectionSecurityVerifyPeer=""
			SMTPServerConnectionSecurityVerifyHost=""
		}
		New-ZabbixMediaType @EmailMediaTypeCreateParams
		Create new Email (-type 0) media type
	.Example
		$PushMediaTypeCreateParams=@{
			Description="Push notifications - 01"
			Type=1
			status=1
			MaxAlertSendSessions=3
			MaxAlertSendAttempts=3
			AlertSendRetryInterval="7s"
			ExecScriptName="push-notification.sh"
			ExecScriptParams="{ALERT.SENDTO}\n{ALERT.SUBJECT}\n{ALERT.MESSAGE}\n"
		}
		New-ZabbixMediaType @PushMediaTypeCreateParams 
		Create new media type with custom options	
	.Example
		Get-ZabbixMediaType | ? descr* -eq EmailMediaType | New-ZabbixMediaType -Description "DisabledCopyOfEmailMediaType" -status 1
		Copy/Clone existing media type to new one, and disable it
	#>
	[cmdletbinding()]
	[Alias("nzmt")]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$Description,
		# Transport used by the media type. Possible values: 0 - e-mail; 1 - script; 2 - SMS; 3 - Jabber; 100 - Ez Texting.
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][int]$Type,
		# Email address from which notifications will be sent. Required for email media types.
		[Alias("smtp_email")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$EmailAddressFrom,
		# SMTP HELO. Required for email media types.
		[Alias("smtp_helo")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SMTPServerHostName,
		# SMTP server. Required for email media types.
		[Alias("smtp_server")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SMTPServerIPorFQDN,
		# SMTP server port.
		[Alias("smtp_port")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SMTPServerPort,
		# SMTP server authentication required. Possible values: 0 - (default) disabled; 1 - enabled
		[Alias("smtp_authentication")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerAuthentication,
		# SMTP server connection security. Possible values: 0 - (default) disabled; 1 - StartTLS; 2 - SSL/TLS
		[Alias("smtp_security")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerConnectionSecurity,
		# SMTP server connection security. Possible values: 0 - (default) disabled; 1 - enabled
		[Alias("smtp_verify_peer")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerConnectionSecurityVerifyPeer,
		# SMTP server connection security. Possible values: 0 - (default) disabled; 1 - enabled
		[Alias("smtp_verify_host")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerConnectionSecurityVerifyHost,
		# Whether the media type is enabled. Possible values: 0 - (default) enabled; 1 - disabled.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$status,
		# Username or Jabber identifier. Required for Jabber and Ez Texting media types.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Username,
		# Authentication password. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Passwd,
		# Serial device name of the GSM modem. Required for SMS media types.
		[Alias("gsm_modem")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$GsmModem,
		# For script media types exec_path contains the name of the executed script. 
		[Alias("exec_path")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ExecScriptName,
		# Script parameters. Each parameter ends with a new line feed.
		[Alias("exec_params")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ExecScriptParams,
		# The maximum number of alerts that can be processed in parallel. Possible values for SMS: 1 - (default) Possible values for other media types: 0-100
		[Alias("maxsessions")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$MaxAlertSendSessions,
		# The maximum number of attempts to send an alert. Possible values: 1-10 Default value: 3
		[Alias("maxattempts")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$MaxAlertSendAttempts,
		# The interval between retry attempts. Accepts seconds and time unit with suffix. Possible values: 0-60s Default value: 10s
		[Alias("attempt_interval")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$AlertSendRetryInterval,
		
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}
		
		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "mediatype.create"
			params = @{
				description = $Description
				type = $Type
				status = $status
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		# General
		if ($MaxAlertSendSessions) {$Body.params.maxsessions=$MaxAlertSendSessions}
		if ($MaxAlertSendAttempts) {$Body.params.maxattempts=$MaxAlertSendAttempts}
		if ($AlertSendRetryInterval) {$Body.params.attempt_interval=$AlertSendRetryInterval}
		# Email
		if ($SMTPServerIPorFQDN) {$Body.params.smtp_server=$SMTPServerIPorFQDN}
		if ($SMTPServerPort) {$Body.params.smtp_port=$SMTPServerPort}
		if ($SMTPServerHostName) {$Body.params.smtp_helo=$SMTPServerHostName}
		if ($EmailAddressFrom) {$Body.params.smtp_email=$EmailAddressFrom}
		if ($SMTPServerAuthentication) {$Body.params.smtp_authentication=$SMTPServerAuthentication}
		if ($Username) {$Body.params.username=$Username}
		if ($Passwd) {$Body.params.passwd=$Passwd}
		if ($SMTPServerConnectionSecurity) {$Body.params.smtp_security=$SMTPServerConnectionSecurity}
		if ($SMTPServerConnectionSecurityVerifyPeer) {$Body.params.smtp_verify_peer=$SMTPServerConnectionSecurityVerifyPeer}
		if ($SMTPServerConnectionSecurityVerifyHost) {$Body.params.smtp_verify_host=$SMTPServerConnectionSecurityVerifyHost}
		# Other
		if ($ExecScriptName) {$Body.params.exec_path=$ExecScriptName} 
		if ($ExecScriptParams) {$Body.params.exec_params="$ExecScriptParams`n"} 
		if ($GsmModem) {$Body.params.gsm_modem=$GsmModem} 

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Set-ZabbixMediaType { 
	<#
	.Synopsis
		Set media types
	.Description
		Set media types
	.Example
		Get-ZabbixMediatype | ? name -eq EmailMediaType-01 | Set-ZabbixMediaType -status 1
		Disable the media type
	.Example
		Get-ZabbixMediatype | ? name -like *email* | Set-ZabbixMediaType -AlertSendRetryInterval "7s" -EmailAddressFrom "zabbix-02@example.com"
		Update all media types, contain "email" in the description field
	.Example
		$EmailMediaTypeCreateParams=@{
			Description="EmailMediaType-01"
			Type=0
			MaxAlertSendSessions=5
			MaxAlertSendAttempts=5
			AlertSendRetryInterval="12s"
			SMTPServerIPorFQDN="mail.example.com"
			SMTPServerPort=25
			SMTPServerHostName="mail"
			EmailAddressFrom="zabbix-01@example.com"
			SMTPServerAuthentication=1
			Username="testUser"
			Passwd="TestUser"
			SMTPServerConnectionSecurity=""
			SMTPServerConnectionSecurityVerifyPeer=""
			SMTPServerConnectionSecurityVerifyHost=""
		}
		Get-ZabbixMediaType | ? Description -like *email* | Set-ZabbixMediaType @EmailMediaTypeCreateParams
		Update settings in multiple media types
	.Example
		$PushMediaTypeCreateParams=@{
			Description="Push notifications - 01"
			Type=1
			status=1
			MaxAlertSendSessions=3
			MaxAlertSendAttempts=3
			AlertSendRetryInterval="7s"
			ExecScriptName="push-notification.sh"
			ExecScriptParams="{ALERT.SENDTO}\n{ALERT.SUBJECT}\n{ALERT.MESSAGE}\n"
		}
		Get-ZabbixMediaType | ? Description -like *push* | Set-ZabbixMediaType @PushMediaTypeCreateParams 
		Update multiple media types
	#>
	[cmdletbinding()]
	[Alias("szmt")]
	Param (

		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$mediatypeid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Description,
		# Transport used by the media type. Possible values: 0 - e-mail; 1 - script; 2 - SMS; 3 - Jabber; 100 - Ez Texting.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$Type,
		# Email address from which notifications will be sent. Required for email media types.
		[Alias("smtp_email")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$EmailAddressFrom,
		# SMTP HELO. Required for email media types.
		[Alias("smtp_helo")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SMTPServerHostName,
		# SMTP server. Required for email media types.
		[Alias("smtp_server")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SMTPServerIPorFQDN,
		# SMTP server port.
		[Alias("smtp_port")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SMTPServerPort,
		# SMTP server authentication required. Possible values: 0 - (default) disabled; 1 - enabled
		[Alias("smtp_authentication")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerAuthentication,
		# SMTP server connection security. Possible values: 0 - (default) disabled; 1 - StartTLS; 2 - SSL/TLS
		[Alias("smtp_security")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerConnectionSecurity,
		# SMTP server connection security. Possible values: 0 - (default) disabled; 1 - enabled
		[Alias("smtp_verify_peer")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerConnectionSecurityVerifyPeer,
		# SMTP server connection security. Possible values: 0 - (default) disabled; 1 - enabled
		[Alias("smtp_verify_host")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$SMTPServerConnectionSecurityVerifyHost,
		# Whether the media type is enabled. Possible values: 0 - (default) enabled; 1 - disabled.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$status,
		# Username or Jabber identifier. Required for Jabber and Ez Texting media types.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Username,
		# Authentication password. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Passwd,
		# Serial device name of the GSM modem. Required for SMS media types.
		[Alias("gsm_modem")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$GsmModem,
		# For script media types exec_path contains the name of the executed script. 
		[Alias("exec_path")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ExecScriptName,
		# Script parameters. Each parameter ends with a new line feed.
		[Alias("exec_params")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ExecScriptParams,
		# The maximum number of alerts that can be processed in parallel. Possible values for SMS: 1 - (default) Possible values for other media types: 0-100
		[Alias("maxsessions")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$MaxAlertSendSessions,
		# The maximum number of attempts to send an alert. Possible values: 1-10 Default value: 3
		[Alias("maxattempts")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$MaxAlertSendAttempts,
		# The interval between retry attempts. Accepts seconds and time unit with suffix. Possible values: 0-60s Default value: 10s
		[Alias("attempt_interval")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$AlertSendRetryInterval,
		
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}
		
		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "mediatype.update"
			params = @{
				mediatypeid = $mediatypeid
				description = $Description
				type = $Type
				status = $status
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		# General
		if ($MaxAlertSendSessions) {$Body.params.maxsessions=$MaxAlertSendSessions}
		if ($MaxAlertSendAttempts) {$Body.params.maxattempts=$MaxAlertSendAttempts}
		if ($AlertSendRetryInterval) {$Body.params.attempt_interval=$AlertSendRetryInterval}
		# Email
		if ($SMTPServerIPorFQDN) {$Body.params.smtp_server=$SMTPServerIPorFQDN}
		if ($SMTPServerPort) {$Body.params.smtp_port=$SMTPServerPort}
		if ($SMTPServerHostName) {$Body.params.smtp_helo=$SMTPServerHostName}
		if ($EmailAddressFrom) {$Body.params.smtp_email=$EmailAddressFrom}
		if ($SMTPServerAuthentication) {$Body.params.smtp_authentication=$SMTPServerAuthentication}
		if ($Username) {$Body.params.username=$Username}
		if ($Passwd) {$Body.params.passwd=$Passwd}
		if ($SMTPServerConnectionSecurity) {$Body.params.smtp_security=$SMTPServerConnectionSecurity}
		if ($SMTPServerConnectionSecurityVerifyPeer) {$Body.params.smtp_verify_peer=$SMTPServerConnectionSecurityVerifyPeer}
		if ($SMTPServerConnectionSecurityVerifyHost) {$Body.params.smtp_verify_host=$SMTPServerConnectionSecurityVerifyHost}
		# Other
		if ($ExecScriptName) {$Body.params.exec_path=$ExecScriptName} 
		if ($ExecScriptParams) {$Body.params.exec_params="$ExecScriptParams`n"} 
		if ($GsmModem) {$Body.params.gsm_modem=$GsmModem} 

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Remove-ZabbixMediaType { 
	<#
	.Synopsis
		Remove media types
	.Description
		Remove media types
	.Example
		Get-ZabbixMediaType | ? descr* -match MediatypeToDelete | Remove-ZabbixMediaType -WhatIf
		WhatIf on deleting media types
	.Example
		Get-ZabbixMediaType | ? descr* -match MediatypeToDelete | Remove-ZabbixMediaType
		Remove media types
	.Example
		Delete-ZabbixMediaType -mediatypeid (Get-ZabbixMediaType | ? descr* -match MediaTypeToDelete-0[1-3]).mediatypeid
		Delete media types
	#>
	[cmdletbinding(SupportsShouldProcess,ConfirmImpact='High')]
	[Alias("rzmt","Delete-ZabbixMediaType")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$mediatypeid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][string]$URL=($global:zabSessionParams.url)
	)
	
	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}
		
		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "mediatype.delete"
			params = @(
				$mediatypeid
			)

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		if ([bool]$WhatIfPreference.IsPresent) {}
		if ($PSCmdlet.ShouldProcess($mediatypeid,"Delete")) {  
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		}
		# $a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result} else {$a.error}
	}
}

Function Get-ZabbixHostInventory {
	<# 
	.Synopsis
		Get host's inventory
	.Description
		Get host's inventory
	.Parameter HostName
		To filter by HostName of the host (case sensitive)
	.Parameter HostID
		To filter by HostID of the host
	.Example
		Get-ZabbixHostInventory -HostName HostName1,HostName2 
		Get full inventory for host (HostName is case sensitive)
	.Example
		Get-ZabbixHost | ? name -match host | ? inventory | Get-ZabbixHostInventory
		Get hosts with inventory
	.Example  
		Get-ZabbixHostInventory HostName1,HostName2 | ? os | select name,os,tag | ft -a
		Get inventory for hosts (HostName is case sensitive)
	.Example  
		(gc server-HostNames.txt) | %{Get-ZabbixHostInventory $_ | select name,os,tag } | ft -a
		Get inventory for hosts (HostName is case sensitive))
	.Example
		Get-ZabbixHostInventory -HostID (gc server-hostids.txt | Out-String -Stream) | select hostid,name,location,os,os_* | ft -a
		Get inventory
	.Example
		Get-ZabbixHostInventory -GroupID 15 | select name,os,os_full,os_short,location
		Get inventory for host in host group 15
    .Example
        Get-ZabbixHostInventory -GroupID 15 | ? inventory_mode -eq 0 | select hostid,@{n='hostname';e={(Get-ZabbixHost -HostID $_.hostid).host}},inventory_mode,name | ft -a
        Get Inventory for hosts in specific host group with GroupID 15
	.Example
		(Get-ZabbixHostGroup | ? name -eq HostGroup) | Get-ZabbixHostInventory | select hostid,name,os
		Get inventory for hosts in HostGroup
	.Example
		(Get-ZabbixHostGroup | ? name -eq HostGroup) | Get-ZabbixHostInventory | Set-ZabbixHostInventory -OSName OSName
		Set hosts' OSName to all hosts in HostGroup
	.Example
		(Get-ZabbixHostGroup | ? groupid -eq 16) | Get-ZabbixHostInventory | select hostid,name,os,os_full
		(Get-ZabbixHostGroup | ? groupid -eq 16) | Get-ZabbixHostInventory | Set-ZabbixHostInventory -OSFullName "OSFullName"
		Set hosts' OSName to all hosts in HostGroup
	.Example
		Get-ZabbixHostInventory | ? os -match linux | select hostid,name,os,tag | sort os | ft -a
		Get only linux hosts
	.Example
		Get-ZabbixHostInventory | ? os | group os -NoElement | sort count -desc
		Get quantity of hosts for each OS
	
	#>
	
	[CmdletBinding()]
	[Alias("gzhstinv")]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HostName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$InventoryMode,
		[string]$SortBy="name",
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$hostids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
    )
	
	process {

		if (!(Get-ZabbixSession)) {return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"
		write-verbose "$($hostname | out-string)"

		# for ($i=0; $i -lt $HostName.length; $i++) {[array]$hstn+=$(@{host = $($HostName[$i])})}
		if ($hostname.length -gt 3) {$HostName=$HostName.host}

		$Body = @{
			method = "host.get"
			params = @{
				selectInventory = "extend"
				# host = $HostName
				hostid = $HostID
				groupids = $GroupID
				# filter = @($hstn.host)
				inventory_mode = $InventoryMode
				filter = @{
					host = $HostName
					hostid = $HostID
					groupid = $GroupID
					# host = @($hstn)
				}
				sortfield = $SortBy
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		$BodyJSON = ConvertTo-Json $Body -Depth 4
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			# if ($a.result) {$a.result} else {$a.error}
			if ($a.result) {$a.result.inventory} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}
}

Function Set-ZabbixHostInventory {
	<# 
	.Synopsis
		Set host's inventory
	.Description
		Set host's inventory
	.Example
		Get-ZabbixHost | ? name -eq host | Set-ZabbixHost -InventoryMode 0
		Enable manual inventory mode on host
	.Example
		Get-ZabbixHostInventory | ? inventory_mode -eq 0 | select hostid,@{n='hostname';e={(Get-ZabbixHost -HostID $_.hostid).host}},inventory_mode,name | ft -a
		Get inventory enabled hosts
	.Example
		Get-ZabbixHostInventory -HostName Hostname1,Hostname2 | Set-ZabbixHostInventory HostName1,HostName2 -OSFullName "OSFullName"
		Set inventory
	.Example
		Get-ZabbixHost | ? name -match "host-0[5-9]" | Set-ZabbixHostInventory -OSFullName "OSFullName"
		Set inventory
	.Example
		Get-ZabbixHostInventory | ? name -eq NameInInventory | Set-ZabbixHostInventory -OSFullName "OSFullName"
		Set inventory for host, which inventory entry name is NameInInventory 
	.Example
		Get-ZabbixHostInventory | select @{n='hostname';e={(Get-ZabbixHost -HostID $_.hostid).host}},* | ? hostname -match "host" | Set-ZabbixHostInventory -OSFullName "-OSFullName"
		Set inventory entry for multiple hosts
	.Example
		Get-ZabbixHostInventory | ? name -match host | Set-ZabbixHostInventory -OSName " "
		Delete inventory entry
	.Example
		Get-ZabbixHostInventory -GroupID 15 | Set-ZabbixHostInventory -Location Location
		Set inventory location to all, inventory enabled hosts, in host group 15
	.Example
		Get-ZabbixHostInventory -GroupID 15 | select @{n='hostname';e={(Get-ZabbixHost -HostID $_.hostid).host}},* | %{Set-ZabbixHostInventory -Name $_.hostname -HostID $_.hostid}
		Copy hostname to inventory's name field
	.Example
		Get-ZabbixHostInventory -GroupID 15 | ? location | Set-ZabbixHostInventory -Location Location
		Set inventory location to hosts
	.Example
		Import-csv C:\input-inventory-mass-data.csv | %{$splatParams=@{}}{$splatParams=(("$_").trim('@{}').replace("; ","`r`n") | ConvertFrom-StringData); Set-ZabbixHostInventory @splatParams}
		Mass inventory data population
		(Get-ZabbixHostInventory -hostid (Import-csv C:\Inventory-input.csv).hostid) -verbose | select hostid,os*
		Data validation
	.Example
		HostID,Type,TypeDetails,Name,Alias,OSName,OSFullName,OSShortName,SerialNumberA,SerialNumberB,Tag,AssetTag,MACAddressA,MACAddressB,Hardware,DetailedHardware,Software,SoftwareDetails,SoftwareApplicationA,SoftwareApplicationB,SoftwareApplicationC,SoftwareApplicationD,SoftwareApplicationE,ContactPerson,Location,LocationLatitude,LocationLongitude,Notes,Chassis,Model,HWArchitecture,Vendor,ContractNumber,InstallerName,DeploymentStatus,URLA,URLB,URLC,HostNetworks,HostSubnetMask,HostRouter,OOBIPAddress,OOBHostSubnetMask,OOBRouter,HWPurchaseDate,HWInstallationDate,HWMaintenanceExpiryDate,HWDecommissioningDate,SiteAddressA,SiteAddressB,SiteAddressC,SiteCity,SiteState,SiteCountry,SiteZIPCode,SiteRackLocation,SiteNotes,PrimaryPOCName,PrimaryEmail,PrimaryPOCPhoneA,PrimaryPOCPhoneB,PrimaryPOCMobileNumber,PrimaryPOCScreenName,PrimaryPOCnNotes,SecondaryPOCName,SecondaryPOCEmail,SecondaryPOCPhoneA,SecondaryPOCPhoneB,SecondaryPOCMobileNumber,SecondaryPOCScreenName,SecondaryPOCNotes
		10000,Type,TypeDetails,Name,Alias,OSName,DetailedOSName,ShortOSName,SerialNumberA,SerialNumberBB,Tag,AssetTag,MACAddressA,MACAddressB,Hardware,DetailedHardware,Software,SoftwareDetails,SoftwareApplicationA,SoftwareApplicationB,SoftwareApplicationC,SoftwareApplicationD,SoftwareApplicationE,ContactPerson,Location,LocLat,LocLong,Notes,Chassis,Model,HWArchitecture,Vendor,ContractNumber,InstallerName,DeploymentStatus,URLA,URLB,URLC,HostNetworks,HostSubnetMask,HostRouter,OOBIPAddress,OOBHostSubnetMask,OOBRouter,HWPurchaseDate,HWInstallationDate,HWMaintenanceExpiryDate,HWDecommissioningDate,SiteAddressA,SiteAddressB,SiteAddressC,SiteCity,SiteState,SiteCountry,SiteZIPCode,SiteRackLocation,SiteNotes,PrimaryPOCName,PrimaryEmail,PrimaryPOCPhoneA,PrimaryPOCPhoneB,PrimaryPOCMobileNumber,PrimaryPOCScreenName,PrimaryPOCnNotes,SecondaryPOCName,SecondaryPOCEmail,SecondaryPOCPhoneA,SecondaryPOCPhoneB,SecondaryPOCMobileNumber,SecondaryPOCScreenName,SecondaryPOCNotes
		CSV file used in previous example
	#>
	[CmdletBinding()]
	[Alias("szhstinv")]
	Param (
        # [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False)][array]$HostName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostID,
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$hostids,
		# Host inventory population mode: Possible values are: -1 - disabled; 0 - (default) manual; 1 - automatic.
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][int]$InventoryMode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$status,
		[switch]$force,

		# [Alias("type")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Type,
		[Alias("type_full")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$TypeDetails,
		# [Alias("name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Name,
		# [Alias("alias")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Alias,
		[Alias("os")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OSName,
		# [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OS,
		[Alias("os_full")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OSFullName,
		[Alias("os_short")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OSShortName,
		[Alias("serialno_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SerialNumberA,
		[Alias("serialno_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SerialNumberB,
		# [Alias("tag")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Tag,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Tag,
		[Alias("asset_tag")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$AssetTag,
		[Alias("macaddress_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$MACAddressA,
		[Alias("macaddress_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$MACAddressB,
		# [Alias("hardware")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Hardware,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Hardware,
		[Alias("hardware_full")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$DetailedHardware,
		# [Alias("software")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Software,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Software,
		[Alias("software_full")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SoftwareDetails,
		[Alias("software_app_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SoftwareApplicationA,
		[Alias("software_app_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SoftwareApplicationB,
		[Alias("software_app_c")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SoftwareApplicationC,
		[Alias("software_app_d")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SoftwareApplicationD,
		[Alias("software_app_e")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SoftwareApplicationE,
		[Alias("contact")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ContactPerson,
		# [Alias("location")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Location,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Location,
		[Alias("location_lat")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$LocationLatitude,
		[Alias("location_lon")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$LocationLongitude,
		# [Alias("notes")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Notes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Notes,
		# [Alias("chassis")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Chassis,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Chassis,
		# [Alias("model")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Model,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Model,
		[Alias("hw_arch")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HWArchitecture,
		# [Alias("vendor")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Vendor,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$Vendor,
		[Alias("contract_number")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ContractNumber,
		[Alias("installer_name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$InstallerName,
		[Alias("deployment_status")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$DeploymentStatus,
		[Alias("url_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URLA,
		[Alias("url_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URLB,
		[Alias("url_c")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$URLC,
		[Alias("host_networks")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostNetworks,
		[Alias("host_netmask")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostSubnetMask,
		[Alias("host_router")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HostRouter,
		[Alias("oob_ip")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OOBIPAddress,
		[Alias("oob_netmask")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OOBHostSubnetMask,
		[Alias("oob_router")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$OOBRouter,
		[Alias("date_hw_purchase")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HWPurchaseDate,
		[Alias("date_hw_install")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HWInstallationDate,
		[Alias("date_hw_expiry")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HWMaintenanceExpiryDate,
		[Alias("date_hw_decomm")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$HWDecommissioningDate,
		[Alias("site_address_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteAddressA,
		[Alias("site_address_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteAddressB,
		[Alias("site_address_c")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteAddressC,
		[Alias("site_city")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteCity,
		[Alias("site_state")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteState,
		[Alias("site_country")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteCountry,
		[Alias("site_zip")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteZIPCode,
		[Alias("site_rack")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteRackLocation,
		[Alias("site_notes")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SiteNotes,
		[Alias("poc_1_name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryPOCName,
		[Alias("poc_1_email")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryEmail,
		[Alias("poc_1_phone_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryPOCPhoneA,
		[Alias("poc_1_phone_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryPOCPhoneB,
		[Alias("poc_1_cell")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryPOCMobileNumber,
		[Alias("poc_1_screen")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryPOCScreenName,
		[Alias("poc_1_notes")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$PrimaryPOCnNotes,
		[Alias("poc_2_name")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCName,
		[Alias("poc_2_email")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCEmail,
		[Alias("poc_2_phone_a")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCPhoneA,
		[Alias("poc_2_phone_b")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCPhoneB,
		[Alias("poc_2_cell")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCMobileNumber,
		[Alias("poc_2_screen")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCScreenName,
		[Alias("poc_2_notes")][Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$SecondaryPOCNotes,
		
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc=($global:zabSessionParams.jsonrpc),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session=($global:zabSessionParams.session),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id=($global:zabSessionParams.id),
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL=($global:zabSessionParams.url)
	)

	process {

		if (!(Get-ZabbixSession)) {return}
		elseif (!$psboundparameters.count) {Write-MissingParamsMessage; return}

		$boundparams=$PSBoundParameters | out-string
		write-verbose "($boundparams)"

		$Body = @{
			method = "host.update"
			params = @{
				# host = $HostName
				hostid = $HostID
				groupid = $GroupID
				inventory_mode = $InventoryMode
				# filter = @{
				# 	host = $HostName
				# }
				inventory = @{}
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}

		if ($Type) {$Body.params.inventory.type=$Type}
		if ($TypeDetails) {$Body.params.inventory.type_full=$TypeDetails}
		if ($Name) {$Body.params.inventory.name=$Name}
		if ($Alias) {$Body.params.inventory.alias=$Alias}
		if ($OSName) {$Body.params.inventory.os=$OSName}
		if ($OSFullName) {$Body.params.inventory.os_full=$OSFullName}
		if ($OSShortName) {$Body.params.inventory.os_short=$OSShortName}
		if ($SerialNumberA) {$Body.params.inventory.serialno_a=$SerialNumberA}
		if ($SerialNumberB) {$Body.params.inventory.serialno_b=$SerialNumberB}
		if ($Tag) {$Body.params.inventory.tag=$Tag}
		if ($AssetTag) {$Body.params.inventory.asset_tag=$AssetTag}
		if ($MACAddressA) {$Body.params.inventory.macaddress_a=$MACAddressA}
		if ($MACAddressB) {$Body.params.inventory.macaddress_b=$MACAddressB}
		if ($Hardware) {$Body.params.inventory.hardware=$Hardware}
		if ($DetailedHardware) {$Body.params.inventory.hardware_full=$DetailedHardware}
		if ($Software) {$Body.params.inventory.software=$Software}
		if ($SoftwareDetails) {$Body.params.inventory.software_full=$SoftwareDetails}
		if ($SoftwareApplicationA) {$Body.params.inventory.software_app_a=$SoftwareApplicationA}
		if ($SoftwareApplicationB) {$Body.params.inventory.software_app_b=$SoftwareApplicationB}
		if ($SoftwareApplicationC) {$Body.params.inventory.software_app_c=$SoftwareApplicationC}
		if ($SoftwareApplicationD) {$Body.params.inventory.software_app_d=$SoftwareApplicationD}
		if ($SoftwareApplicationE) {$Body.params.inventory.software_app_e=$SoftwareApplicationE}
		if ($ContactPerson) {$Body.params.inventory.contact=$ContactPerson}
		if ($Location) {$Body.params.inventory.location=$Location}
		if ($LocationLatitude) {$Body.params.inventory.location_lat=$LocationLatitude}
		if ($LocationLongitude) {$Body.params.inventory.location_lon=$LocationLongitude}
		if ($Notes) {$Body.params.inventory.notes=$Notes}
		if ($Chassis) {$Body.params.inventory.chassis=$Chassis}
		if ($Model) {$Body.params.inventory.model=$Model}
		if ($HWArchitecture) {$Body.params.inventory.hw_arch=$HWArchitecture}
		if ($Vendor) {$Body.params.inventory.vendor=$Vendor}
		if ($ContractNumber) {$Body.params.inventory.contract_number=$ContractNumber}
		if ($InstallerName) {$Body.params.inventory.installer_name=$InstallerName}
		if ($DeploymentStatus) {$Body.params.inventory.deployment_status=$DeploymentStatus}
		if ($URLA) {$Body.params.inventory.url_a=$URLA}
		if ($URLB) {$Body.params.inventory.url_b=$URLB}
		if ($URLC) {$Body.params.inventory.url_c=$URLC}
		if ($HostNetworks) {$Body.params.inventory.host_networks=$HostNetworks}
		if ($HostSubnetMask) {$Body.params.inventory.host_netmask=$HostSubnetMask}
		if ($HostRouter) {$Body.params.inventory.host_router=$HostRouter}
		if ($OOBIPAddress) {$Body.params.inventory.oob_ip=$OOBIPAddress}
		if ($OOBHostSubnetMask) {$Body.params.inventory.oob_netmask=$OOBHostSubnetMask}
		if ($OOBRouter) {$Body.params.inventory.oob_router=$OOBRouter}
		if ($HWPurchaseDate) {$Body.params.inventory.date_hw_purchase=$HWPurchaseDate}
		if ($HWInstallationDate) {$Body.params.inventory.date_hw_install=$HWInstallationDate}
		if ($HWMaintenanceExpiryDate) {$Body.params.inventory.date_hw_expiry=$HWMaintenanceExpiryDate}
		if ($HWDecommissioningDate) {$Body.params.inventory.date_hw_decomm=$HWDecommissioningDate}
		if ($SiteAddressA) {$Body.params.inventory.site_address_a=$SiteAddressA}
		if ($SiteAddressB) {$Body.params.inventory.site_address_b=$SiteAddressB}
		if ($SiteAddressC) {$Body.params.inventory.site_address_c=$SiteAddressC}
		if ($SiteCity) {$Body.params.inventory.site_city=$SiteCity}
		if ($SiteState) {$Body.params.inventory.site_state=$SiteState}
		if ($SiteCountry) {$Body.params.inventory.site_country=$SiteCountry}
		if ($SiteZIPCode) {$Body.params.inventory.site_zip=$SiteZIPCode}
		if ($SiteRackLocation) {$Body.params.inventory.site_rack=$SiteRackLocation}
		if ($SiteNotes) {$Body.params.inventory.site_notes=$SiteNotes}
		if ($PrimaryPOCName) {$Body.params.inventory.poc_1_name=$PrimaryPOCName}
		if ($PrimaryEmail) {$Body.params.inventory.poc_1_email=$PrimaryEmail}
		if ($PrimaryPOCPhoneA) {$Body.params.inventory.poc_1_phone_a=$PrimaryPOCPhoneA}
		if ($PrimaryPOCPhoneB) {$Body.params.inventory.poc_1_phone_b=$PrimaryPOCPhoneB}
		if ($PrimaryPOCMobileNumber) {$Body.params.inventory.poc_1_cell=$PrimaryPOCMobileNumber}
		if ($PrimaryPOCScreenName) {$Body.params.inventory.poc_1_screen=$PrimaryPOCScreenName}
		if ($PrimaryPOCnNotes) {$Body.params.inventory.poc_1_notes=$PrimaryPOCnNotes}
		if ($SecondaryPOCName) {$Body.params.inventory.poc_2_name=$SecondaryPOCName}
		if ($SecondaryPOCEmail) {$Body.params.inventory.poc_2_email=$SecondaryPOCEmail}
		if ($SecondaryPOCPhoneA) {$Body.params.inventory.poc_2_phone_a=$SecondaryPOCPhoneA}
		if ($SecondaryPOCPhoneB) {$Body.params.inventory.poc_2_phone_b=$SecondaryPOCPhoneB}
		if ($SecondaryPOCMobileNumber) {$Body.params.inventory.poc_2_cell=$SecondaryPOCMobileNumber}
		if ($SecondaryPOCScreenName) {$Body.params.inventory.poc_2_screen=$SecondaryPOCScreenName}
		if ($SecondaryPOCNotes) {$Body.params.inventory.poc_2_notes=$SecondaryPOCNotes}


		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		try {
			$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
			# if ($a.result) {$a.result} else {$a.error}
			if ($a.result) {$a.result} else {$a.error}
		} catch {
			Write-Host "$_"
			Write-Host "Too many entries to return from Zabbix server. Check/reduce the filters." -f cyan
		}
	}

}