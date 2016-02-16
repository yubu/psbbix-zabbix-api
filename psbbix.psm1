Function New-ZabbixSession {
	
	<# 
	.Synopsis
		Create new Zabbix session
	.Description
		Create new Zabbix session
	.Parameter PSCredential
		Credential
	.Parameter IPAdress
		Accept IP adress or domain name
	.Parameter noSSL
		Connect to Zabbix server with plain http
	.Example
		New-ZabbixSession 10.10.10.10
		Connect to Zabbix server
	.Example
		Connect-Zabbix -IPAdress 10.10.10.10 -noSSL
		Connect to Zabbix server with noSSL (http)
	.Example
		Connect-Zabbix -User admin -Password zabbix -IPAdress zabbix.domain.net
		Connect to Zabbix server
	#>
    
	[CmdletBinding()]
    [Alias("Connect-Zabbix")]
	Param (
        [Parameter(Mandatory=$True)][string]$IPAdress,
        [Parameter(Mandatory=$True)][PSCredential]$PSCredential,
        [Switch]$UseSSL,
		[switch]$noSSL
    )
    
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
	
    $URL = $Protocol+"://$IPAdress/zabbix"
    try {if (!$global:zabSession) {
		$global:zabSession=Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post |
			Select-Object jsonrpc,@{Name="session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
	   }
    }
    catch {
        [void]::$_
        write-host "Seems SSL certificate is self signed. Trying with no SSL validation..." -f yellow
    } 
    finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $global:zabSession=Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post |
			Select-Object jsonrpc,@{Name="session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
    }	
	
    if ($zabsession.session) {
		$global:zabSessionParams=@{jsonrpc=$zabsession.jsonrpc;session=$zabsession.session;id=$zabsession.id;url=$zabsession.URL}
		write-host "`nConnected to $IPAdress." -f green
        write-host "Zabbix Server version: " -f green -nonewline
        Get-ZabbixVersion @zabSessionParams
        ""
        write-host 'Usage: Get-ZabbixVersion @zabSessionParams' -f yellow
		write-host 'Usage: Get-ZabbixHost @zabSessionParams Hostname/IP' -f yellow
        ""
	} 
	else {write-host "ERROR: Not connected. Try again." -f red; $zabsession}
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
    [Alias("Get-ZabbixConnection")]
    param ()
	
    if (!($global:zabSession -and $global:zabSessionParams)) {
        write-host "`nDisconnected form Zabbix Server!`n" -f red; return
    }
    elseif ($global:zabSession -and $global:zabSessionParams -and ($ZabbixVersion=Get-ZabbixVersion @zabSessionParams)) {
		$zabSession
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
		Disconnect-Zabbix @zabSessionParams
		Disconnect from Zabbix server
	.Example
		Remove-Zabbixsession @zabSessionParams
		Disconnect from Zabbix server
	#>
	
	[CmdletBinding()]
    [Alias("Disconnect-Zabbix")]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	if (Get-ZabbixVersion @zabSessionParams) {
		$Body = @{
			method = "user.logout"
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {$a.result | out-null} else {$a.error}
		
		$global:zabSession = ""
		$global:zabSessionParams = ""
		
		if (!(Get-ZabbixVersion @zabSessionParams)) {}
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
		Get-ZabbixVersion @zabSessionParams
		Get Zabbix server version
	#>
    
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
    
	if (!($global:zabsession -or $global:zabSessionParams)) {write-host "`nDisconnected from Zabbix Server!`n" -f red; return}
	if ($global:zabsession -and $global:zabSessionParams) {
    if (!$psboundparameters.count) {Get-ZabbixVersion @zabSessionParams; return}

		$Body = @{
			method = "apiinfo.version"
			jsonrpc = $jsonrpc
			id = $id
		}
		
		$BodyJSON = ConvertTo-Json $Body
		write-verbose $BodyJSON
		
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
		if ($a.result) {return $a.result} else {$a.error}
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
		Get-ZabbixHost @zabSessionParams
		Get all hosts
	.Example  
		Get-ZabbixHost -HostName HostName @zabSessionParams
		Get host by name (case sensitive)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match host | select hostid,host,status,available,httptests
		Get host(s) by name match (case insensitive)
    .Example
        Get-ZabbixHost @zabSessionParams | ? name -match host | select -ExpandProperty interfaces -Property name | sort name
        Get hosts' interfaces by host name match (case insensitive)        
	.Example
		Get-ZabbixHost @zabSessionParams  | ? name -match os | Get-ZabbixTemplate @zabSessionParams | select templateid,name -Unique
		Get templates by name match (case insensitive)
	.Example
		Get-ZabbixHost @zabSessionParams | ? status -eq 1 | select hostid,name
		Get only disabled hosts
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match "" | ? jmx_available -match 1 | select hostid,name
		Get host(s) with JMX interface(s) active
	.Example
		Get-ZabbixHost @zabSessionParams | ? parentTemplates -match "jmx" | select hostid,name,available,jmx_available
		Get host(s) with JMX Templates and get their connection status
	.Example
		Get-ZabbixHost @zabSessionParams | ? status -eq 0 | ? available -eq 0 | select hostid,name,status,available,jmx_available | ft -a
		Get hosts, which are enabled, but unreachable
	.Example
		Get-ZabbixHost @zabSessionParams -GroupID (Get-ZabbixGroup @zabSessionParams -GroupName "GroupName").groupid | select hostid,host,status,available,httptests
		Get host(s) by host group, match name "GroupName" (case sensitive)
	.Example
		Get-ZabbixHost @zabSessionParams -hostname HostName | Get-ZabbixItem @zabSessionParams -WebItems -ItemKey web.test.error -ea silent | select name,key_,lastclock
		Get Items for the host (HostName is case sensitive)
	.Example
		(Get-ZabbixHost @zabSessionParams | ? name -match host).parentTemplates.name
		Get templates linked to the host by hostname match (case insensitive) 
	.Example
		Get-ZabbixHost @zabSessionParams | ? parentTemplates -match "jmx" | select name -Unique
		Get hosts with templates, by template name match
	.Example
		Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixItem @zabSessionParams -WebItems -ItemKey web.test.error -ea silent | select name,key_,@{n='lastclock';e={convertFrom-epoch $_.lastclock}}
		Get Items for the host. Item lastclock (last time it happened in UTC)
	.Example
		Get-ZabbixHost @zabSessionParams -hostname HostName | Get-ZabbixHttpTest @zabSessionParams -ea silent | select httptestid,name,steps
		Get host (case sensitive) and it's HttpTests
    .Example
        Get-ZabbixHost @zabSessionParams -hostname HostName | Get-ZabbixHttpTest @zabSessionParams -ea silent | select -ExpandProperty steps | ft -a
        Get host (case sensitive) and it's HttpTests
    .Example
        Get-ZabbixHost @zabSessionParams | ? name -match hostName | select host -ExpandProperty interfaces | ? port -match 10050
        Get interfaces for the host(s)    
    .Example
		Get-ZabbixHost @zabSessionParams | ? name -match hostsName | %{$n=$_.name; Get-ZabbixHostInterface @zabSessionParams -HostID $_.hostid} | select @{n="name";e={$n}},hostid,interfaceid,ip,port | sort name | ft -a
		Get interface(s) for the host(s)
	#>
	
    [CmdletBinding()]
	Param (
        $HostName,
        [array]$HostID,
		[array]$GroupID,
		[array]$HttpTestID,
		[Parameter(ValueFromPipelineByPropertyName=$true)][string]$status,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
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
			
			filter = @{
			    host = $HostName
		    }
			hostids = $HostID
			groupids = $GroupID
			httptestid = $HttpTestID
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
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
		IP adress of the host
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
		New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID "10081","10166"
		Create new host (case sensitive), with two linked Templates	
	.Example
		New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID (Get-ZabbixHost @zabSessionParams | ? name -match "host").parentTemplates.templateid -status 0
		Create new host (case sensitive), with multiple attached Templates and enable it (-status 0)
	.Example
		New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID (Get-ZabbixHost @zabSessionParams | ? name -match "host").parentTemplates.templateid -status 1
		Create new host (case sensitive), with multiple attached Templates and leave it disabled (-status 1)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match SourceHost | New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10
		Clone host with single interface
	.Example 
		Get-ZabbixHost @zabSessionParams | ? name -match SourceHost | New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10 -TemplateID (Get-ZabbixHost @zabSessionParams | ? name -match "SourceHost").parentTemplates.templateid -status 1
		Clone host, while new host will be disabled
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match SourceHost | New-ZabbixHost @zabSessionParams -HostName NewHostName -IP 10.20.10.10 -TemplateID (Get-ZabbixHost @zabSessionParams | ? name -match "SourceHost").parentTemplates.templateid -Interfaces (Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName SourceHost).hostid) -status 1
		Get-ZabbixHost @zabSessionParams | ? name -match NewHost | Get-ZabbixHostInterface @zabSessionParams | %{Set-ZabbixHostInterface @zabSessionParams -IP 10.20.10.10 -InterfaceID $_.interfaceid -Port $_.port -HostID $_.hostid}
		Get-ZabbixHost @zabSessionParams | ? name -match NewHost | %{$n=$_.name; Get-ZabbixHostInterface @zabSessionParams -HostID $_.hostid} | ft -a @{n="name";e={$n}},hostid,interfaceid,ip,port
		Clone the host with multiple interfaces, then update interfaces with new IP, then check the interfaces
	#>
	
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$True)][string]$HostName,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$false)][string]$IP,
        [string]$DNSName,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Port = 10050,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$status,
        [Parameter(Mandatory=$False)][string]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$Groups,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$Templates,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$Interfaces,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL,
        [Switch]$MonitorByDNSName
    )

    Switch ($MonitorByDNSName.IsPresent) {
        $False {$ByDNSName = 1} # = ByIP
        $True {$ByDNSName = 0} # = ByDomainName
    }
    
	if ($TemplateID.count -gt 5) {write-host "`nOnly up to 5 templates are allowed." -f red -b yellow; return} 
	
    if ($GroupID) {
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
				groups = @{
				    groupid = $GroupID
				}
				status = $Status
				templates = @(
					@{templateid = $TemplateID[0]}
					@{templateid = $TemplateID[1]}
					@{templateid = $TemplateID[2]}
					@{templateid = $TemplateID[3]}
					@{templateid = $TemplateID[4]}
				)
			}
			
			jsonrpc = $jsonrpc
			auth = $session
			id = $id
		}
	}
	elseif ($interfaces) {
		$Body = @{
			method = "host.create"
			params = @{
				host = $HostName
				interfaces = $Interfaces
				groups = $Groups
				status = $Status
				templates = @(
					@{templateid = $TemplateID[0]}
					@{templateid = $TemplateID[1]}
					@{templateid = $TemplateID[2]}
					@{templateid = $TemplateID[3]}
					@{templateid = $TemplateID[4]}
				)
			}
			
			jsonrpc = $jsonrpc
			auth = $session
			id = $id
		}
	}
	else {
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
				groups = $groups
				status = $Status
				templates = @(
					@{templateid = $TemplateID[0]}
					@{templateid = $TemplateID[1]}
					@{templateid = $TemplateID[2]}
					@{templateid = $TemplateID[3]}
					@{templateid = $TemplateID[4]}
				)
			}
			
			jsonrpc = $jsonrpc
			auth = $session
			id = $id
		}
	}
    $BodyJSON = ConvertTo-Json $Body -Depth 3
    write-verbose $BodyJSON
	
	$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	if ($a.result) {$a.result} else {$a.error}
}

Function Set-ZabbixHost {
	<# 
	.Synopsis
		Set/update host settings
	.Description
		Set/update host settings
	.Parameter HostID
		HostID
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -eq "host" | Set-ZabbixHost @zabSessionParams -status 0
		Enable host (-status 0)
	.Example
		(1..9) | %{(Get-ZabbixHost @zabSessionParams | ? name -eq "host0$_") | Set-ZabbixHost @zabSessionParams -status 1}
		Disable multiple hosts (-status 1)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match "hostName" | %{Set-ZabbixHost @zabSessionParams -status 1 -HostID $_.hostid -parentTemplates $_.parenttemplates}
		Disable multiple hosts
	.Example
		Get-ZabbixHost @zabSessionParams -HostName HostName | Set-ZabbixHost @zabSessionParams -removeTemplates -TemplateID (Get-ZabbixHost @zabSessionParams -HostName "Host").parentTemplates.templateid
		Unlink(remove) templates from host (case sensitive)
	.Example
		Get-ZabbixHost @zabSessionParams -HostName HostName | Set-ZabbixHost @zabSessionParams -TemplateID (Get-ZabbixHost @zabSessionParams -HostName SourceHost).parentTemplates.templateid
		Link(add) templates to the host, according config of other host (case sensitive)
	.Example
		(1..9) | %{Get-ZabbixHost @zabSessionParams -HostName "Host0$_" | Set-ZabbixHost @zabSessionParams -TemplateID ((Get-ZabbixHost @zabSessionParams | ? name -match "sourcehost").parenttemplates.templateid)}
		Link(add) templates to multiple hosts, according config of other host
	#>	 
    
	[CmdletBinding()]
	Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]$HostName,
        [Parameter(ValueFromPipelineByPropertyName=$true)]$HostID,
		[array]$TemplateID,
		[Parameter(ValueFromPipelineByPropertyName=$true)][array]$parentTemplates,
		[array]$GroupID,
		[array]$HttpTestID,
		[switch]$removeTemplates,
		[Parameter(ValueFromPipelineByPropertyName=$true)][string]$status,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$proxy_hostid,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
    
	if ($TemplateID.count -gt 5) {write-host "`nOnly up to 5 templates are allowed." -f red -b yellow; return}
	
	if ($removeTemplates) {
		$Body = @{
			method = "host.update"
			params = @{
				hostid = $HostID
				status = $status
				host = $HostName
				templates_clear = @(
					@{templateid = $TemplateID[0]}
					@{templateid = $TemplateID[1]}
					@{templateid = $TemplateID[2]}
					@{templateid = $TemplateID[3]}
					@{templateid = $TemplateID[4]}
				)
			}

			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
	}
	elseif ($TemplateID) { 
		$Body = @{
			method = "host.update"
			params = @{
				hostid = $HostID
				status = $status
				templates = @(
					@{templateid = $TemplateID[0]}
					@{templateid = $TemplateID[1]}
					@{templateid = $TemplateID[2]}
					@{templateid = $TemplateID[3]}
					@{templateid = $TemplateID[4]}
				)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
	}
	else {
		$Body = @{
			method = "host.update"
			params = @{
				hostid = $HostID
				status = $status
				parenttemplates = $parenttemplates
				proxy_hostid = $proxy_hostid
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

Function Remove-ZabbixHost {
	<# 
	.Synopsis
		Delete/Remove selected host
	.Description
		Delete/Remove selected host
	.Parameter HostID
		To filter by ID/IDs
	.Example 
		Remove-ZabbixHost @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "RetiredHosts").hostid -WhatIf
		Remove host(s) by name match (case insensitive) (check only: -WhatIf)
     .Example 
		Remove-ZabbixHost @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "RetiredHosts").hostid
		Remove host(s) by name match (case insensitive)
	.Example
		Remove-ZabbixHost @zabSessionParams -HostID "10001","10002" 
		Remove hosts by IDs
	.Example
		Remove-ZabbixHost @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName HostRetired).hostid
		Remove single host by name (exact amtch, case sensitive)
	.Example
		Get-ZabbixHost  @zabSessionParams | ? name -eq HostName | Remove-ZabbixHost @zabSessionParams -WhatIf
		Remove single host (check only: -WhatIf)
     .Example
		Get-ZabbixHost  @zabSessionParams | ? name -eq HostName | Remove-ZabbixHost @zabSessionParams
		Remove single host
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match "HostName-0[1-8]" | %{Remove-ZabbixHost @zabSessionParams -HostID $_.hostid}
		Delete multiple hosts 
	#>
	
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	Param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$HostID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	
    $Body = @{
	    method = "host.delete"
	    params = @($HostID)
	    jsonrpc = $jsonrpc
	    id = $id
	    auth = $session
    }
	
    $BodyJSON = ConvertTo-Json $Body
	write-verbose $BodyJSON
    
	if ([bool]$WhatIfPreference.IsPresent) {
	}
	if ($PSCmdlet.ShouldProcess($HostID,"Delete")){  
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	}
	
	if ($a.result) {$a.result} else {$a.error}
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
		Get-ZabbixTemplate @zabSessionParams
		Get all templates 
	.Example
		Get-ZabbixTemplate @zabSessionParams | select name,hosts
		Get templates and hosts
	.Example
		Get-ZabbixTemplate @zabSessionParams -TemplateName "Template OS Windows"
		Get template by name (case sensitive)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match os | Get-ZabbixTemplate @zabSessionParams | select templateid,name -Unique
		Get templates by name match (case insensitive)
	.Example
		Get-ZabbixTemplate @zabSessionParams | ? {$_.hosts.host -match "host"} | select templateid,name
		Get templates linked to host by hostname.
	#>
    
	[CmdletBinding()]
	Param (
        $TemplateName,
        $TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
    $Body = @{
	    method = "template.get"
	    params = @{
		    output = "extend"
		    selectHosts = "extend"
		    filter = @{
			    host = $TemplateName
		    }
            templateids = $TemplateID
			hostids = $HostID
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
		Get-ZabbixMaintenance @zabSessionParams | select maintenanceid,name
		Get maintenance
	.Example
		Get-ZabbixMaintenance @zabSessionParams -MaintenanceName MaintenanceName
		Get maintenance by name (case sensitive)
	.Example 
		Get-ZabbixMaintenance @zabSessionParams | ? name -match maintenance
		Get maintenance by name match (case insensitive)
    .Example
        Get-ZabbixMaintenance @zabSessionParams | ? name -match "" | select @{n="MaintenanceName";e={$_.name}} -ExpandProperty groups | ft -a
        Get maintenance by name match (case insensitive)   
	.Example
		Get-ZabbixMaintenance @zabSessionParams -MaintenanceID 10123
		Get maintenance by ID
	.Example
        Get-ZabbixMaintenance @zabSessionParams | select maintenanceid,name,@{n="Active_since(UTC-5)";e={(convertFrom-epoch $_.active_since).addhours(-5)}},@{n="Active_till(UTC-5)";e={(convertFrom-epoch $_.active_till).addhours(-5)}},@{n="TimeperiodStart(UTC-5)";e={(convertfrom-epoch $_.timeperiods.start_date).addhours(-5)}},@{n="Duration(hours)";e={$_.timeperiods.period/3600}} | ft -a
        Get maintenance and it's timeperiod
	.Example
		(Get-ZabbixMaintenance @zabSessionParams -MaintenanceName MaintenanceName).timeperiods
		Get timeperiods from maintenance (case sensitive)
    .Example
        Get-ZabbixMaintenance @zabSessionParams | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | ft -a
        Get timeperiods from maintenance
	.Example
        Get-ZabbixMaintenance @zabSessionParams | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | select MaintenanceName,timeperiodid,timeperiod_type,@{n="start_date(UTC)";e={convertfrom-epoch $_.start_date}},@{n="period(Hours)";e={$_.period/3600}} | ft -a
        Get timeperiods maintenance and timeperiods (Time in UTC)
    .Example
		(Get-ZabbixMaintenance @zabSessionParams -MaintenanceName MaintenanceName).hosts.host
		Get hosts from maintenance (case sensitive)
	.Example
		(Get-ZabbixMaintenance @zabSessionParams -MaintenanceName MaintenanceName).hostid  
		Get HostIDs of hosta from maintenance (case sensitive)
	.Example
		Get-ZabbixMaintenance @zabSessionParams | ? name -match maintenance | select Name,@{n="TimeperiodStart";e={(convertfrom-epoch $_.timeperiods.start_date).addhours(-5)}},@{n="Duration(hours)";e={$_.timeperiods.period/3600}}
		Get timeperiods from maintenance (case insensitive), display name, timeperiod (according UTC-5) and duration
	#>
    
	[CmdletBinding()]
	Param (
        $MaintenanceName,
        $MaintenanceID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
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
	.Parameter TimeperiodStartTime
		Maintenance timeperiod's start time (epoch time format)
	.Parameter TimeperiodPeriod
		Maintenance timeperiod's period/duration (epoch time format)	
	.Example
		New-ZabbixMaintenance @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "hosts").hostid -MaintenanceName "NewMaintenance" -ActiveSince (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) -ActiveTill (convertTo-epoch ((get-date).addhours(7)).ToUniversalTime()) -TimeperiodPeriod (4*3600)
		Create new maintenance for few hosts (time will be according Zabbix server time). Maintenance will be active for 7 hours from now, with Period 4 hours, which will start immediately 
	.Example
		New-ZabbixMaintenance @zabSessionParams -HostID "10109","10110","10111","10112","10113","10114" -MaintenanceName NewMaintenanceName -MaintenanceDescription NewMaintenanceDescription -ActiveSince 1432584300 -ActiveTill 1432605900 -TimeperiodStartTime 1432584300 -TimeperiodPeriod 25200
		Create new maintenance (time (epoch format) will be according your PC (client) local time). Name and Description are case sensitive 
	.Example
		New-ZabbixMaintenance @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match otherhost).hostid -MaintenanceName NewMaintenanceName -MaintenanceDescription NewMaintenanceDescription -ActiveSince (convertTo-epoch (get-date -date "05/25/2015 07:05")) -ActiveTill (convertTo-epoch (get-date -date "05/25/2015 17:05")) -TimeperiodPeriod (7*3600) -TimeperiodStartDate (convertTo-epoch (get-date -date "05/25/2015 09:05"))
		Create new, future maintenance (case sensitive) (time will be sent in UTC). Will be set on Zabbix server according it's local time. 
	.Example
		$hosts=Get-Zabbixhost @zabSessionParams | ? name -match "host|anotherhost"
		$groups=(Get-ZabbixGroup @zabSessionParams | ? name -match "group")
		New-ZabbixMaintenance @zabSessionParams -HostID $hosts.hostid -GroupID $groups.groupid -MaintenanceName "NewMaintenanaceName" -ActiveSince (convertTo-epoch (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) -ActiveTill (convertTo-epoch ((get-date).addhours(+4)).ToUniversalTime()) -TimeperiodPeriod (3*3600)
		Create new maintenance for few hosts (time will be according current Zabbix server time). Maintenanace Active from now for 4 hours, and Period with duration of 3 hours, sarting immediately
	#>

    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$True)][string]$MaintenanceName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)][array]$HostID,
		$MaintenanceDescription,
		#Type of maintenance.  Possible values:  0 - (default) with data collection;  1 - without data collection. 
		$MaintenanceType,
		#epoch time
		[Parameter(Mandatory=$True)]$ActiveSince,
		#epoch time
		[Parameter(Mandatory=$True)]$ActiveTill,
		#Possible values: 0 - (default) one time only;  2 - daily;  3 - weekly;  4 - monthly. 
		$TimePeriodType=0,
		#Time of day when the maintenance starts in seconds.  Required for daily, weekly and monthly periods. (epoch time)
		$TimeperiodStartTime,
		#Date when the maintenance period must come into effect.  Required only for one time periods. Default: current date. (epoch time)
		$TimeperiodStartDate,
		#epoch time
		[Parameter(Mandatory=$True)]$TimeperiodPeriod,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
    
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
						#start_time = $TimeperiodStartTime
						start_date = $TimeperiodStartDate
						period = $TimeperiodPeriod
					}
				)
				groupids = @($groupid)
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
						#start_time = $TimeperiodStartTime
						period = $TimeperiodPeriod
					}
				)
				hostids = @($hostid)
			}
			
			jsonrpc = $jsonrpc
			id = $id
			auth = $session
		}
	}
    
	$BodyJSON = ConvertTo-Json $Body -Depth 4
	write-verbose $BodyJSON
    
	$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
    if ($a.result) {$a.result} else {$a.error}
 }

Function Remove-ZabbixMaintenance {
	<# 
	.Synopsis
		Delete/Remove maintenance
	.Description
		Delete/Remove maintenance
	.Parameter MaintenanceID
		To filter by ID/IDs of the maintenance
	.Example
		Remove-ZabbixMaintenance @zabSessionParams -MaintenanceID "3","4" 
		Remove maintenance by IDs
	.Example
		Remove-ZabbixMaintenance @zabSessionParams -MaintenanceID (Get-ZabbixMaintenance @zabSessionParams | ? name -match "Maintenance|Name").maintenanceid -WhatIf
		Remove multiple maintenances (check only: -WhatIf)
    .Example
		Remove-ZabbixMaintenance @zabSessionParams -MaintenanceID (Get-ZabbixMaintenance @zabSessionParams | ? name -match "Maintenance|Name").maintenanceid
		Remove multiple maintenances
	.Example
		Get-ZabbixMaintenance @zabSessionParams | ? name -eq name | Remove-ZabbixMaintenance @zabSessionParams
		Remove single maintenance by name
	#>
    
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)][array]$MaintenanceID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
     $Body = @{
	    method = "maintenance.delete"
	    params = @($MaintenanceID)
	    jsonrpc = $jsonrpc
	    id = $id
	    auth = $session
    }
	
    $BodyJSON = ConvertTo-Json $Body
	write-verbose $BodyJSON
	
    
	if ([bool]$WhatIfPreference.IsPresent) {
	}
	if ($PSCmdlet.ShouldProcess($HostID,"Delete")){  
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	}
	
	if ($a.result) {$a.result} else {$a.error}
 }
 
Function Export-ZabbixConfig {
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
		Export-ZabbixConfig @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid
		Export hosts configuration
	.Example
		Export-ZabbixConfig @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid | clip
		Capture to clipboard exported hosts configurarion
	.Example
		Export-ZabbixConfig @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid | sc c:\zabbix-hosts-export.xml
		Export hosts configuration to xml file
	.Example
		Export-ZabbixConfig @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match TemplateName).templateid | sc c:\zabbix-templates-export.xml
		Export template configuration to xml file
	#>
    [CmdletBinding()]
	Param (
		[array]$HostID,
		[array]$GroupID,
		[array]$TemplateID,
		[string]$Format="xml",
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	
		$Body = @{
		method = "configuration.export"
		params = @{
			options = @{
				hosts = @($HostID)
				templates = @($TemplateID)
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

Function Get-ZabbixAlert { 
	<#
	.Synopsis
		Get alerts
	.Parameter HostID
		HostID
	.Example
		Get-ZabbixAlert @zabSessionParams | ? sendto -match email | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alarms from last 5 hours (default). Time display in UTC/GMT (default) 
	.Example
		Get-ZabbixAlert @zabSessionParams | ? sendto -match email | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.clock).addhours(+1)}},alertid,subject
		Get alarms from last 5 hours (default). Time display in UTC+1
	.Example
		Get-ZabbixAlert @zabSessionParams | ? sendto -match email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Get alarms from last 5 hours (default). Time display in UTC-5
	.Example
		Get-ZabbixAlert @zabSessionParams | ? sendto -match email | ? subject -match OK | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts with OK status
	.Example	
		Get-ZabbixAlert @zabSessionParams -TimeFrom (convertTo-epoch (((get-date).ToUniversalTime()).addhours(-10))) -TimeTill (convertTo-epoch (((get-date).ToUniversalTime()).addhours(-2))) | ? sendto -match mail | ? subject -match "" | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts within custom timewindow of 8 hours (-timeFrom, -timeTill in UTC/GMT). Time display in UTC/GMT (default)  
	.Example	
		Get-ZabbixAlert @zabSessionParams -TimeFrom (convertTo-epoch (((get-date).ToUniversalTime()).addhours(-5))) -TimeTill (convertTo-epoch ((get-date).ToUniversalTime()).addhours(0)) | ? sendto -match mail | select @{n="Time UTC";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
		Get alerts for last 5 hours
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match "server-01" | Get-ZabbixAlert @zabSessionParams | ? sendto -match mail | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Works for single host (name case insensitive). Get alerts for host from last 5 hours (default). Display time in UTC-5 
	.Example
		Get-ZabbixHost @zabSessionParams -HostName "Server-01" | Get-ZabbixAlert @zabSessionParams -ea silent | ? sendto -match email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Works for single host (name case sensitive). Get alerts for host from last 5 hours (default). Display time in UTC-5
	.Example
		Get-ZabbixAlert @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "Host|OtherHost").hostid | ? sendto -match email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
		Works for multiple hosts. Get alerts for hosts from last 5 hours (default). Display time in UTC-5
	.Example
		Get-ZabbixAlert @zabSessionParams -TimeFrom (convertTo-epoch ((get-date -date "05/25/2015 9:00").ToUniversalTime()).addhours(0)) -TimeTill (convertTo-epoch ((get-date -date "05/25/2015 14:00").ToUniversalTime()).addhours(0)) | ? sendto -match mail | select @{n="Time(UTC)";e={(convertfrom-epoch $_.clock).addhours(0)}},alertid,subject
		Get alerts between two dates (in UTC), present time in UTC
	#>
	
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		#epoch time
		#"Time from to display alerts. Default: -2, from three hours ago. Time is in UTC/GMT"
		$TimeFrom=(convertTo-epoch ((get-date).addhours(-5)).ToUniversalTime()),
		#epoch time
		#"Time until to display alerts. Default: till now. Time is in UTC/GMT"
		$TimeTill=(convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()),
		[array] $SortBy="clock",
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
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
		Get-ZabbixUser @zabSessionParams | select userid,alias,attempt_ip,@{n="attempt_clock(UTC)";e={convertfrom-epoch $_.attempt_clock}},@{n="usrgrps";e={$_.usrgrps.name}}
		Get user
	.Example
		Get-ZabbixUser @zabSessionParams | ? alias -match alias | select userid,alias,attempt_ip,@{n="attempt_clock(UTC)";e={convertfrom-epoch $_.attempt_clock}},@{n="usrgrps";e={$_.usrgrps.name}}
		Get user
	.Example
		Get-ZabbixUser @zabSessionParams | select name, alias, attempt_ip, @{n="attempt_clock (UTC-5)"; e={((convertfrom-epoch $_.attempt_clock)).addhours(-5)}},@{n="usrgrps";e={$_.usrgrps.name}} | ft -a
		Get user
	#>
	
	[cmdletbinding()]
	Param (
		[array]$SortBy="alias",
		[switch]$getAccess=$true,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
	    method = "user.get"
	    params = @{
		    output = "extend"
			selectMedias = "extend"
			selectMediatypes = "extend"
			selectUsrgrps = "extend"
			sortfield = @($sortby)
			getAccess = $getAccess
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Remove-ZabbixUser { 
    <#
	.Synopsis
		Remove/Delete users
	.Parameter UserID
		UserID
	.Example
		Get-ZabbixUser @zabSessionParams | ? alias -eq "alias" | Remove-ZabbixUser @zabSessionParams -WhatIf
		Delete one user
	.Example
		Remove-ZabbixUser @zabSessionParams -UserID (Get-ZabbixUser @zabSessionParams | ? alias -match "alias").userid
		Delete multiple users by alias match
	#>
	
	[cmdletbinding(SupportsShouldProcess,ConfirmImpact='High')]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$UserID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
	    method = "user.delete"
	    params = @($UserID)
	    jsonrpc = $jsonrpc
	    id = $id
	    auth = $session
    }

    $BodyJSON = ConvertTo-Json $Body
	write-verbose $BodyJSON
	
	if ([bool]$WhatIfPreference.IsPresent) {
	}
	if ($PSCmdlet.ShouldProcess($UserID,"Delete")){  
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	}
	
    if ($a.result) {$a.result} else {$a.error}
}

Function Set-ZabbixUser { 
	<#
	.Synopsis
		Set user properties
	.Parameter UserID
		UserID
	.Example
		Get-ZabbixUser @zabSessionParams | ? alias -match "alias" | Set-ZabbixUser @zabSessionParams -Name NewName -Surname NewSurname -rows_per_page 100
		Set user properties
	.Example
		Get-Zabbixuser @zabSessionParams | ? alias -match "alias" | Set-ZabbixUser @zabSessionParams -usrgrps (Get-ZabbixUserGroup @zabSessionParams | ? name -match disable).usrgrpid
		Disable user (by moving him to usrgrp Disabled)
	#>	
	
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$UserID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$usrgrpid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Passwd,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$sendto,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$usrgrps,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$medias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$rows_per_page,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$UserMediaActive=1,
		#[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$medias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Surname,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
		method = "user.update"
		params = @{
			userid = $UserID
			name = $Name
			surname = $Surname
			alias = $Alias
			passwd = $Passwd
			usrgrps = $usrgrps
			rows_per_page = $Rows_Per_Page
			medias = $medias
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

Function New-ZabbixUser { 
	<#
	.Synopsis
		Create new users
	.Parameter UserID
		UserID
	.Example
		New-ZabbixUser @zabSessionParams -Name NewName -Surname NewSurname -Alias first.surname -passwd "123456" -sendto first.last@domain.com -MediaActive 0 -rows_per_page 100 -Refresh 300 -usrgrps (Get-ZabbixUserGroup @zabSessionParams | ? name -match "disabled|administrator").usrgrpid
		Create new user
	.Example
		Import-Csv C:\zabbix-users.csv | %{New-ZabbixUser @zabSessionParams -Name $_.Name -Surname $_.Surname -Alias $_.alias -passwd $_.passwd -sendto $_.sendto -MediaActive $_.MediaActive -rows_per_page $_.rows_per_page -Refresh $_.refresh -usrgrps (Get-ZabbixUserGroup @zabSessionParams | ? name -match "guest").usrgrpid}
		Mass create new users
	.Example
		Get-ZabbixUser @zabSessionParams | ? alias -match "SourceUser" | New-ZabbixUser @zabSessionParams -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -sendto first@first.com -MediaActive 0 -rows_per_page 100 -Refresh 300
		Clone user. Enable media (-UserMediaActive 0)
	.Example
		Get-Zabbixuser @zabSessionParams | ? alias -match "SourceUser" | New-ZabbixUser @zabSessionParams -Name NewName -Surname NewSurname -Alias first.last -passwd "123456"
		Clone user
	.Example
		Get-ZabbixUser @zabSessionParams | ? alias -match "User" | New-ZabbixUser @zabSessionParams -Name NewName -Surname NewSurname -Alias first.last -passwd "123456" -usrgrps (Get-ZabbixUserGroup @zabSessionParams | ? name -match disabled).usrgrpid
		Clone user, but disable it (assign to usrgrp Disabled)
	#>	
	
	[cmdletbinding()]
	Param (
		[switch]$getAccess=$true,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$Alias,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$Passwd,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Severity="63",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Period="1-7,00:00-24:00",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Sendto,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$usrgrps,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$rows_per_page,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$MediaActive=1,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$medias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$mediaTypes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Refresh,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Surname,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	if (!$sendto -or !$MediaActive) {
		$Body = @{
			method = "user.create"
			params = @{
				name = $name
				surname = $surname
				alias = $alias
				passwd = $passwd
				usrgrps = $usrgrps
				rows_per_page = $rows_per_page
				refresh = $refresh
				getAccess = $getAccess
				medias = $medias
				mediatypes = $mediaTypes
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
				name = $name
				surname = $surname
				alias = $alias
				passwd = $passwd
				usrgrps = $usrgrps
				rows_per_page = $rows_per_page
				refresh = $refresh
				getAccess = $getAccess
				user_medias = @(
					@{
						#mediaid = "1"
						mediatypeid = "1"
						sendto = $Sendto
						active = $MediaActive
						severity = $Severity
						period = $Period
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

Function Get-ZabbixUserGroup { 
	<#
	.Synopsis
		Get user groups
	.Description
		Get user groups
	.Parameter SortBy
		Sort output by (usrgrpid, name (default)), not mandatory
	.Parameter getAccess
		adds additional information about user permissions (default=$true), not mandatory
	.Example
		Get-ZabbixUserGroup  @zabSessionParams | select usrgrpid,name
		Get groups
	.Example
		(Get-ZabbixUserGroup @zabSessionParams | ? name -match administrators).users | select alias,users_status
		Get users in group.
	#>
	
	[cmdletbinding()]
	Param (
		[array]$SortBy="name",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$userids,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
	    method = "usergroup.get"
	    params = @{
		    output = "extend"
			selectUsers = "extend"
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Get-ZabbixTrigger {
	<# 
	.Synopsis
		Get triggers
	.Description
		Get triggers
	.Parameter TriggerID
		To filter by ID of the trigger
	.Example
        Get-ZabbixTrigger @zabSessionParams | ? status -eq 0 | ? expression -match fs.size | select status,description,expression | sort description
        Get enabled triggers
	.Example
		Get-ZabbixTemplate @zabSessionParams | ? name -match "TemplateName" | Get-ZabbixTrigger @zabSessionParams | select description,expression
		Get triggers from template
	.Example
		Get-ZabbixTrigger @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match Template).templateid -ExpandDescription -ExpandExpression | ft -a status,description,expression
		Get triggers by templateid (-ExpandDescription and -ExpandExpression will show full text instead of ID only)
	.Example
		Get-ZabbixTrigger @zabSessionParams -ExpandDescription -ExpandExpression | ? description -match "Template" | select description,expression
		Get triggers where description match the string (-ExpandDescription and -ExpandExpression will show full text instead of ID only)
    .Example 
		Get-ZabbixTrigger @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match "Template").templateid | select description,expression
		Get list of triggers from templates
	.Example
		Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixTrigger @zabSessionParams -ea silent | ? status -match 0 | ft -a status,templateid,description,expression
		Get triggers for host (status 0 == enabled, templateid 0 == assigned directly to host, not from template) 
	#>
    
	[CmdletBinding()]
	Param (
		[switch]$ExpandDescription,
		[switch]$ExpandExpression,
        [array]$TriggerID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	
	$Body = @{
		method = "trigger.get"
		params = @{
			output = "extend"
			selectFunctions = "extend"
			selectLastEvent = "extend"
			selectGroups = "extend"
			selectHosts = "extend"
			expandDescription = $ExpandDescription
			expandExpression = $ExpandExpression
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
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
		Get-ZabbixTrigger @zabSessionParams -TemplateID (Get-zabbixTemplate @zabSessionParams | ? name -match "Template Name").templateid | ? description -match "trigger description" | Set-ZabbixTrigger @zabSessionParams -status 1
		Disable trigger
	.Example
		Get-ZabbixTemplate @zabSessionParams | ? name -match "Template" | Get-ZabbixTrigger @zabSessionParams | ? description -match triggerDescription | set-ZabbixTrigger @zabSessionParams -status 0
		Enable trigger
	#>

    [CmdletBinding()]
	Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]$TriggerID,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$status,
		[switch]$ExpandDescription,
		[switch]$ExpandExpression,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	
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
    write-host $BodyJSON
	
	$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
    if ($a.result) {$a.result} else {$a.error}
}

Function Get-ZabbixAction { 
	<#
	.Synopsis
		Get actions
	.Description
		Get actions
	.Example
		Get-ZabbixAction @zabSessionParams
	.Example	
		Get-ZabbixAction @zabSessionParams | select name
	.Example	
		Get-ZabbixAction @zabSessionParams | ? name -match action | select name,def_longdata,r_longdata
	#>
	[cmdletbinding()]
	Param (
		[array] $SortBy="name",
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Set-ZabbixAction { 
	<#
	.Synopsis
		Set/Update action settings
	.Description
		Set/Update action settings
	.Example
		Get-ZabbixAction @zabSessionParams | ? name -match actionName | Set-ZabbixAction @zabSessionParams -status 1
		Disable action by name match
	#>
	
	[cmdletbinding()]
	Param (
		[array] $SortBy="name",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$ActionID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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

Function Get-ZabbixApplication {
	<# 
	.Synopsis
		Get applications
	.Description
		Get applications
	.Parameter HostID
		Get by HostID
	.Parameter TemplateID
		Get by TemplateID
	.Example
		Get-ZabbixApplication @zabSessionParams | ? name -match "appname" | ft -a applicationid,name,hosts
		Get applications by name match
	.Example
		Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixApplication @zabSessionParams -ea silent | ft -a applicationid,name,hosts
		Get applications by hostname (case sensitive)
	.Example
		Get-ZabbixApplication @zabSessionParams | ? name -match "appname" | ? hosts -match host | ft -a applicationid,name,hosts
		Get applications by name and by hostname matches 
	.Example
		Get-ZabbixApplication @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match templateName).templateid | ? name -match "" | ft -a applicationid,name,hosts
		Get applications by TemplateID
	.Example
		Get-ZabbixTemplate @zabSessionParams | ? name -match TemplateName | %{Get-ZabbixApplication @zabSessionParams -TemplateID $_.templateid } | ft -a applicationid,name,hosts
		Same as above one: Get applications by TemplateID
	.Example
		Get-ZabbixGroup @zabSessionParams -GroupName "GroupName" | Get-ZabbixApplication @zabSessionParams
		Get applications by GroupName
	#>
    
	[CmdletBinding()]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
    $Body = @{
	    method = "application.get"
	    params = @{
		    output = "extend"
            selectHosts = @(
                "hostid",
                "host"
            )
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Get-ZabbixHostInterface { 
	<#
	.Synopsis
		Get host interface
	.Description
		Get host interface
	.Example
		Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName ThisHost).hostid
		Get interface(s) for single host (case sensitive)
	.Example	
		Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match hostName).hostid
		Get interface(s) for multiple hosts (case insensitive)
	.Example	
		Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixHostInterface @zabSessionParams
		Get interface(s) for single host (case sensitive)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match hostsName | %{$n=$_.name; Get-ZabbixHostInterface @zabSessionParams -HostID $_.hostid} | select @{n="name";e={$n}},hostid,interfaceid,ip,port | sort name | ft -a
		Get interface(s) for the host(s)
	#>
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Set-ZabbixHostInterface { 
	<#
	.Synopsis
		Set host interface
	.Description
		Set host interface
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match host | Get-ZabbixHostInterface @zabSessionParams | %{Set-ZabbixHostInterface @zabSessionParams -IP 10.20.10.10 -InterfaceID $_.interfaceid -HostID $_.hostid -Port $_.port}
		Set new IP to multiple host interfaces
	#>
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$InterfaceID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$IP,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Port,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
	    method = "hostinterface.update"
	    params = @{
			hostid = $HostID
			interfaceid = $InterfaceID
			port = $Port
			ip = $IP
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

Function Get-ZabbixHttpTest {
	<# 
	.Synopsis
		Get web/http tests
	.Description
		Get web/http tests
	.Parameter HttpTestName
		To filter by name of the http test
	.Example
		Get-ZabbixHttpTest @zabSessionParams
		Get web/http tests
	.Example
		Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTest | select httptestid,name
		Get web/http test by name match (case insensitive)
	.Example
		Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTest | select steps | select -first 1 | fl *
		Get web/http test by name match, first occurrence
	.Example
		Get-ZabbixHttpTest @zabSessionParams | ? name -like "test*Name" | ? {$_.hosts.host -match "Template name"}) | select name,@{e={$_.steps.url}},@{n='host';e={$_.hosts.host}} -Unique | sort host
		Get web/http test by name (case insensitive)
	.Example
		Get-ZabbixHttpTest @zabSessionParams -HttpTestID 96
		Get web/http test by ID
	.Example
		(Get-ZabbixHttpTest @zabSessionParams -HttpTestName HttpTestName).hosts.host 
		Get hosts with web/http test by name match (case sensitive) 
	.Example 
		Get-ZabbixHttpTest @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid | select name,steps
		Get web/http tests by hostname match (case insensitive)
	.Example
		(Get-ZabbixTemplate @zabSessionParams ) | ? name -eq "Template Name" | get-ZabbixHttpTest @zabSessionParams | select name,steps
		Get web/http tests by template name 
	.Example 
		Get-ZabbixHost @zabSessionParams | ? name -match host | Get-ZabbixHttpTest @zabSessionParams | select name
		Get web/http tests for hostname match (works for single host)
	.Example
		Get-ZabbixHttpTest @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -eq hostnname).hostid | ? name -match "httpTest" | fl httptestid,name,steps
		Get web/http test for host by name (case insensitive), and filter web/hhtp test by test name match (case insensitive)
	.Example
		Get-ZabbixHttpTest -HttpTestName SomeHTTPtest @zabSessionParams | select -Unique 
		Get web/http test by name (case sensitive)
	.Example
		Get-ZabbixHttpTest -HttpTestName HTTPTestName @zabSessionParams | select name,@{n="host";e={$_.hosts.host}}
		Get web/http test by name (case sensitive) and hosts it is assigned to
	.Example
		(Get-ZabbixHttpTest @zabSessionParams | ? name -eq "HTTPtestName").hosts.host | sort
		Get hosts by web/http test's name (case insensitive)
	.Example	
		(Get-ZabbixHttpTest @zabSessionParams | ? name -eq "httpTestName").hosts.host | ? {$_ -notmatch "template"} | sort
		Get only hosts by web/http test name, sorted (templates (not hosts) are sortrd out)
	.Example
		Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTestName | select name, @{n="required";e={$_.steps.required}} -Unique
		Get web/http test name and field required
	.Example
		Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTestName | select name, @{n="url";e={$_.steps.url}} -Unique
		Get web/http test name and field url
	#>
    
	[CmdletBinding()]
	Param (
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HttpTestID,
		$HttpTestName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
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
		New-ZabbixHttpTest @zabSessionParams -HttpTestName NewHttpTest -HttpTestStepURL "http://{HOST.CONN}:30555/health-check/do" -HttpTestStepRequired "version" -HostID (Get-ZabbixHost @zabSessionParams -HostName HostName).hostid
		Create new web/http test for server/template
	.Example
		Get-ZabbixTemplate @zabSessionParams | ? name -eq "Template Name" | Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTestSource | New-ZabbixHttpTest @zabSessionParams -HttpTestName NewHttpName
		Clone web/http test in template
	#>
    
	[CmdletBinding()]
	Param (
        $HttpTestID,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$HostID,
        $HttpTestStepRequired,
		[Parameter(ValueFromPipelineByPropertyName=$true)][array]$StatusCodes=200,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$Timeout=15,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$status,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$Steps,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$applicationid,
		[Parameter(ValueFromPipelineByPropertyName=$true)]$TemplateID,
		$HttpTestStepName,
		[Parameter(Mandatory=$True)]$HttpTestName,
		#[Parameter(Mandatory=$True)]$HttpTestStepURL,
		[Parameter(Mandatory=$false)]$HttpTestStepURL,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
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

Function Set-ZabbixHttpTest {
	<# 
	.Synopsis
		Set/Update web/http test
	.Description
		Set/Update web/http test
	.Parameter HttpTestName
		web/http test name
	.Example
		Set-ZabbixHttpTest @zabSessionParams -HttpTestID (Get-ZabbixHttpTest @zabSessionParams -HttpTestName TestOldName ).httptestid -HttpTestName "testNewName" -status 0
		Enable (-status 0) web/http test and rename it (case sensitive)  
	.Example
		Get-ZabbixHttpTest @zabSessionParams -HttpTestName httpTest | Set-ZabbixHttpTest @zabSessionParams -status 1
		Disable web/http test (-status 1) 
	.Example
		Set-ZabbixHttpTest @zabSessionParams -HttpTestID (Get-ZabbixHttpTest @zabSessionParams -HttpTestName testName).httptestid -UpdateSteps -HttpTestStepName (Get-ZabbixHttpTest -HttpTestName testName).steps.name -HttpTestStepURL (Get-ZabbixHttpTest @zabSessionParams -HttpTestName SourceHttpTestName).steps.url
		Replace test steps' URL by other URL, taken from "othertest"  
	.Example
		Set-ZabbixHttpTest @zabSessionParams -HttpTestID (Get-ZabbixHttpTest @zabSessionParams | ? name -like "test*Name" | ? {$_.hosts.host -match "Template"}).httptestid -UpdateSteps -HttpTestStepName "NewTestName" -HttpTestStepURL "http://10.20.10.10:30555/health-check/do"
		Edit web/http test, update name and test url
	#>

	[CmdletBinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]$HttpTestID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$HttpTestName,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]$HttpTestStepURL,
		$HostID,
		$HttpTestStepName,
        $HttpTestStepRequired,
		$status,
		[switch]$UpdateSteps,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	
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
						timeout = 15
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

Function Remove-ZabbixHttpTest {
	<# 
	.Synopsis
		Delete web/http test
	.Description
		Delete web/http test
	.Parameter HttpTestName
		web/http test name
	.Example
		Remove-ZabbixHttpTest @zabSessionParams -HttpTestID (Get-ZabbixTemplate @zabSessionParams | ? name -eq "Template Name" | Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTests).httptestid
		Delete web/http tests
	.Example
		Get-ZabbixTemplate @zabSessionParams | ? name -eq "Template Name" | Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTest | %{Remove-ZabbixHttpTest @zabSessionParams -HttpTestID $_.HttpTestID}
		Delete web/http tests 
	#>

	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    Param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$HttpTestID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
    )
	
	$Body = @{
		method = "httptest.delete"
		params = @($HttpTestID)
		jsonrpc = $jsonrpc
		id = $id
		auth = $session
	}

    $BodyJSON = ConvertTo-Json $Body -Depth 3
	write-verbose $BodyJSON
	
    if ([bool]$WhatIfPreference.IsPresent) {
		##
	}
	if ($PSCmdlet.ShouldProcess($HostID,"Delete")){  
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	}
	
	if ($a.result) {$a.result} else {$a.error}
}

Function Get-ZabbixHostInterface { 
	<#
	.Synopsis
		Get host interface
	.Description
		Get host interface
	.Example
		Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName TheseHosts).hostid
		Get Hosts interfaces
	.Example	
		Get-ZabbixHost @zabSessionParams -HostName host-01 | Get-ZabbixHostInterface @zabSessionParams | ft -a
		Get single host interface information
	.Example	
		 Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid | ft -a
		 Get multiple hosts interface information
	.Example
		Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName ThisHost).hostid
		Get interface(s) for single host (case sensitive)
	.Example	
		Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match hostName).hostid
		Get interface(s) for multiple hosts (case insensitive)
	.Example	
		Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixHostInterface @zabSessionParams
		Get interface(s) for single host (case sensitive)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match hostsName | %{$n=$_.name; Get-ZabbixHostInterface @zabSessionParams -HostID $_.hostid} | ft -a @{n="name";e={$n}},hostid,interfaceid,ip,port
		Get interface(s) for the host(s)
	#>
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Set-ZabbixHostInterface { 
	<#
	.Synopsis
		Set host interface
	.Description
		Set host interface
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match host | Get-ZabbixHostInterface @zabSessionParams | %{Set-ZabbixHostInterface @zabSessionParams -IP 10.20.10.12 -Verbose -InterfaceID $_.interfaceid -HostID $_.hostid -Port $_.port}
		Modify interface settings for the host
	.Example	
		Get-ZabbixHost @zabSessionParams | ? name -match host | Get-ZabbixHostInterface @zabSessionParams | %{Set-ZabbixHostInterface @zabSessionParams -InterfaceID $_.interfaceid -IP 10.20.10.15 -Port $_.port -HostID $_.hostid}
	.Example	
		(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | Get-ZabbixHostInterface @zabSessionParams | ? port -match 31721 | Set-ZabbixHostInterface @zabSessionParams -main 1}
	#>
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$InterfaceID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$IP,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$Port,
		#Main: Possible values are:  0 - not default;  1 - default. 
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$main,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
	    method = "hostinterface.update"
	    params = @{
			hostid = $HostID
			interfaceid = $InterfaceID
			port = $Port
			ip = $IP
			main = $main
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

Function New-ZabbixHostInterface { 
	<#
	.Synopsis
		Create host interface
	.Description
		Create host interface
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match host | New-ZabbixHostInterface @zabSessionParams -IP 10.20.10.15 -port 31721
	.Example	
		Get-ZabbixHost @zabSessionParams | ? name -match "host01" | New-ZabbixHostInterface @zabSessionParams -Port 31721 -type 4 -main 1 -ip (Get-ZabbixHost @zabSessionParams | ? name -match "host01").interfaces.ip
	.Example	
		(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | New-ZabbixHostInterface @zabSessionParams -Port 31702 -type 4 -main 1 -ip (Get-ZabbixHost @zabSessionParams | ? name -match "host0$_").interfaces.ip}
		(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | New-ZabbixHostInterface @zabSessionParams -Port 31721 -type 4 -main 0 -ip (Get-ZabbixHost @zabSessionParams | ? name -match "host0$_").interfaces.ip[0]}
	.Example
		(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | Get-ZabbixHostInterface @zabSessionParams | ? port -match 31751 | Set-ZabbixHostInterface @zabSessionParams -main 0}
		Make existing JMX port not default
		(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | New-ZabbixHostInterface @zabSessionParams -Port 31771 -type 4 -main 1 -ip (Get-ZabbixHost @zabSessionParams | ? name -match "host0$_").interfaces.ip[0]}
		Create new JMX connection and set it default
		Get-ZabbixItem @zabSessionParams -HostId (Get-ZabbixHost @zabSessionParams | ? name -match "one|two|three|four").hostid | ? key_ -match "version" | ? key_ -notmatch "VmVersion" | ? lastvalue -ne 0 | ? applications -match "app1|app2|app3|app3" | select @{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_,interfaces | sort host,application | ft -a
		Check whether new settings are working
	#>
	[cmdletbinding()]
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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

Function Remove-ZabbixHostInterface { 
	<#
	.Synopsis
		Remove host interface
	.Description
		Remove host interface
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match "host02" | Get-ZabbixHostInterface @zabSessionParams | ? port -Match 31721 | Remove-ZabbixHostInterface @zabSessionParams
		Remove single host interface
	.Example	
		Remove-ZabbixHostInterface @zabSessionParams -interfaceid (Get-ZabbixHost @zabSessionParams | ? name -match "host02" | Get-ZabbixHostInterface @zabSessionParams).interfaceid
		Remove all interfaces from host
	.Example	

	#>
	[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$HostID,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][array]$InterfaceId,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
	$Body = @{
	    method = "hostinterface.delete"
	    params = @($interfaceid)

	    jsonrpc = $jsonrpc
	    id = $id
	    auth = $session
    }
	
    $BodyJSON = ConvertTo-Json $Body
	write-verbose $BodyJSON
	
	if ([bool]$WhatIfPreference.IsPresent) {
		#$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	}
	if ($PSCmdlet.ShouldProcess($HostID,"Delete")){  
		$a = Invoke-RestMethod "$URL/api_jsonrpc.php" -ContentType "application/json" -Body $BodyJSON -Method Post
	}
	
    if ($a.result) {$a.result} else {$a.error}
}

Function Get-ZabbixItem { 
	<#
	.Synopsis
		Retrieves items
	.Example
		Get-ZabbixItem @zabSessionParams -HostId (Get-ZabbixHost @zabSessionParams | ? name -match hostName).hostid | select name,key_,lastvalue
		Get Items for host (case insensitive)
	.Example
		Get-ZabbixItem @zabSessionParams -ItemName 'RAM Utilization (%)' -HostId (Get-ZabbixHost @zabSessionParams | ? name -match "dc1").hostid | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},status,prevvalue,@{n="lastvalue";e={[decimal][math]::Round($_.lastvalue,3)}} | sort lastvalue -desc | ft -a
		Get Items  with name 'RAM Utilization (%)' for hosts by match
	.Example
		Get-ZabbixItem @zabSessionParams -ItemName 'Memory Total' -HostId (Get-ZabbixHost @zabSessionParams | ? name -match "").hostid | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},prevvalue,@{n="lastvalue";e={[decimal][math]::round(($_.lastvalue/1gb),2)}} | sort lastvalue -desc | ft -a
		Get Items  with name 'Memory Total' for hosts by match
	.Example	
		Get-ZabbixItem @zabSessionParams -HostId (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid | ? key_ -match "/mnt/reporter_files,[used,free]" | ? lastvalue -ne 0 | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="lastvalue";e={[decimal][math]::round(($_.lastvalue/1gb),2)}},key_,description | sort host | ft -a
		Get Items for host(s) with key_ match
	.Example	
		Get-ZabbixItem @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match "myTemplates").templateid | ? history -ne 7 | select @{n="Template";e={$_.hosts.name}},history,name -Unique | sort Template
		Get Items for templates, where history not 7 days
	.Example
		Get-ZabbixItem @zabSessionParams -HostId (Get-ZabbixHost @zabSessionParams | ? name -match hostName).hostid | ? key_ -match "Version|ProductName" | ? key_ -notmatch "vmver" | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},lastvalue,name,key_ | sort host,key_ | ft -a
		Get Items by host match, by key_ match/notmatch
	.Example
		Get-ZabbixHost -hostname hostName @zabSessionParams | Get-ZabbixItem @zabSessionParams -SortBy status -ItemKey pfree | select name, key_,@{n="Time(UTC)"e={convertfrom-epoch $_.lastclock}},lastvalue,status | ft -a
		Get Items (disk usage(%) information) for single host
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -match "hostName" | Get-ZabbixItem @zabSessionParams -ItemName 'RAM Utilization (%)' | select @{n="hostname";e={$_.hosts.name}},name,key_,@{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},prevvalue,lastvalue | ft -a
		Get Items for single host by match
	.Example
		Get-ZabbixItem @zabSessionParams -SortBy status -ItemKey pfree -HostId (Get-ZabbixHost @zabSessionParams | ? name -match hostName).hostid | select @{n="hostname";e={$_.hosts.name}},@{n="Time(UTC)";e={convertfrom-epoch $_.lastclock}},status,key_,lastvalue,name | sort hostname,key_ | ft -a
		Get Items (disk usage(%) info) for multiple hosts
	.Example
		Get-ZabbixItem @zabSessionParams -SortBy status -ItemKey pfree -HostId (Get-ZabbixHost @zabSessionParams | ? name -match hostName).hostid | ? key_ -match "c:" | select @{n="hostname";e={$_.hosts.name}},@{n="Time(UTC)";e={convertfrom-epoch $_.lastclock}},status,key_,lastvalue,name | sort hostname,key_ | ft -a
		Get Items (disk usage info) according disk match for multiple hosts
	.Example
		(1..8) | %{Get-ZabbixHost @zabSessionParams hostName-0$_ | Get-ZabbixItem @zabSessionParams -ItemKey 'java.lang:type=Memory' | ? status -match 0 | select key_,interfaces}
		Get Items and their interface
	.Example
        (1..8) | %{Get-ZabbixHost @zabSessionParams hostName-0$_ | Get-ZabbixItem @zabSessionParams -ItemKey 'MemoryUsage.used' | ? status -match 0 | select @{n="Host";e={$_.hosts.name}},@{n="If.IP";e={$_.interfaces.ip}},@{n="If.Port";e={$_.interfaces.port}},@{n="Application";e={$_.applications.name}},key_ } | ft -a
        Get Items and interfaces
	.Example
		Get-ZabbixItem @zabSessionParams -ItemKey 'version' -ItemName "Version of zabbix_agent(d) running" -HostId (Get-ZabbixHost @zabSessionParams | ? name -notmatch "DC2").hostid | ? status -match 0 | select @{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},key_,lastvalue | sort host
		Get Zabbix agent version
	.Example
		Get-ZabbixItem @zabSessionParams -HostId (Get-ZabbixHost @zabSessionParams | ? name -match "hostName").hostid | ? key_ -match "version" | ? key_ -notmatch "VmVersion" | ? lastvalue -ne 0 | ? applications -match "" | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_,@{n="If.IP";e={$_.interfaces.ip}},@{n="If.Port";e={$_.interfaces.port}} | sort host | ft -a 
		Get Java application versions via JMX
	.Example
		Get-ZabbixItem @zabSessionParams -HostId (Get-ZabbixHost @zabSessionParams | ? name -match "hostName").hostid | ? key_ -match "HeapMemoryUsage.committed" | ? lastvalue -ne 0 | ? applications -match "application" | select @{n="Time(UTC+1)";e={(convertfrom-epoch $_.lastclock).addhours(+1)}},@{n="host";e={$_.hosts.name}},@{n="Application";e={$_.applications.name}},lastvalue,key_,@{n="If.IP";e={$_.interfaces.ip}},@{n="If.Port";e={$_.interfaces.port}} | sort host | ft -a
		Get JVM memory usage via JMX
	#>
	
	[cmdletbinding()]
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Get-ZabbixGraph { 
	<#
	.Synopsis
		Get graph
	.Description
		Get graph
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams | select name
        Get graphs for single host
	.Example	
		Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams -expandName | ? name -match 'RAM utilization' | select name
        Get graphs for single host     
	.Example
        Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams -expandName | ? name -match 'RAM utilization' | select name -ExpandProperty gitems | ft -a
        Get graphs for single host	
	.Example	
		Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams -expandName | ? {!$_.graphDiscovery} | select name -ExpandProperty gitems | ft -a
        Get graphs for single host
    .Example
        Get-ZabbixGraph @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "multipleHosts").hostid | select @{n="host";e={$_.hosts.name}},name | ? host -match "host0[5,6]"| ? name -notmatch Network | sort host
        Get graphs for multiple hosts
	#>
    
	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$HostID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GroupID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$GraphID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$TemplateID,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$ItemID,
		[switch]$expandName=$true,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$jsonrpc,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$session,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$id,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][string]$URL
	)
	
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
        Write-Host "Too many entries to return from Zabbix server. Check/reduce filters." -f cyan
    }
}

Function Save-ZabbixGraph {
	<#
	.Synopsis
		Save graph
	.Description
		Save graph
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams | ? name -match 'CPU utilization' | Save-ZabbixGraph -verbose 
		Save single graph (default location: $env:TEMP\psbbix)
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams | ? name -match 'CPU utilization' | Save-ZabbixGraph -sTime (convertTo-epoch (get-date).AddMonths(-3)) -fileFullPath $env:TEMP\psbbix\graphName.png -show 
		Save single graph and show it
	.Example
		Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams | ? name -eq 'RAM utilization (%)' | Save-ZabbixGraph -sTime (convertto-epoch (get-date -date "05/25/2015 00:00").ToUniversalTime()) -show
		Save single graph, time sent as UTC, and will appear as local Zabbix server time
	.Example	
		(Get-ZabbixHost @zabSessionParams | ? name -eq "singleHost" | Get-ZabbixGraph @zabSessionParams | ? name -match 'RAM utilization | CPU utilization').graphid | %{Save-ZabbixGraph -GraphID $_ -sTime (convertto-epoch (get-date -date "05/25/2015 00:00")) -fileFullPath $env:TEMP\psbbix\graphid-$_.png -show}
		Save and show graphs for single host
	.Example
		(Get-ZabbixGraph @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "multipleHosts").hostid | ? name -match 'RAM utilization | CPU utilization').graphid | %{Save-ZabbixGraph -GraphID $_ -sTime (convertto-epoch (get-date -date "05/25/2015 00:00")) -verbose -show}
		Save multiple grpahs for multiple hosts
	.Example
		(Get-ZabbixGraph @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "multipleHosts").hostid | ? name -match 'RAM utilization | CPU utilization').graphid | %{Save-ZabbixGraph -GraphID $_ -sTime (convertto-epoch (get-date -date "05/25/2015 00:00")) -show -mail -from "zabbix@domain.com" -to first.last@mail.com -smtpserver 10.10.20.10 -proprity High}
		Save and send by email multiple grpahs, for multiple hosts
    #>
    
	[cmdletbinding()]
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
    
    $psbbixTmpDir="$env:TEMP\psbbix"
    if (!$fileFullPath) {
        if (!(test-path $psbbixTmpDir)) {mkdir $psbbixTmpDir}
        $fileFullPath="$psbbixTmpDir\graph-$graphid.png"
    }
    write-verbose "Graph files locateted here: $psbbixTmpDir"
	
    $gurl=($zabSessionParams.url.replace('https','http'))
    try {invoke-webrequest "$gurl/chart2.php?graphid=$graphid`&width=$Width`&hight=$Hight`&stime=$sTime`&period=$Period" -OutFile $fileFullPath}
    catch {write-host "$_"}
	
	if ($show) {
        if (test-path "c:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {&"c:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -incognito $fileFullPath}
        elseif (test-path "c:\Program Files\Internet Explorer\iexplore.exe") {&"c:\Program Files\Internet Explorer\iexplore.exe" $fileFullPath}
        else {start "file:///$fileFullPath"}
	}
	
	if ($mail) {
        if (!$from) {$from="zabbix@mydomain.com"}
        if (!$subject) {$subject="Zabbix: graphid: $GraphID"}
	    if ($body) {Send-MailMessage -from $from -to $to -subject $subject -body $body -Attachments $fileFullPath -SmtpServer $SMTPServer}
        else {Send-MailMessage -from $from -to $to -subject $subject -Attachments $fileFullPath -SmtpServer $SMTPServer}
	}
}