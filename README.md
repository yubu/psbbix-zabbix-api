
# psbbix
Powershell Module for Zabbix API

##### Compatibility
- Tested with Zabbix 2.4
- Tested with Zabbix 3.4 
- Tested with Powershell 5.0+
- Tested with Powershell Core 6.0+

##### Based on:
- [Zabbix](<https://onedrive.live.com/?cid=3b909e9df5dc497a&id=3B909E9DF5DC497A%213668&ithint=folder,psm1&authkey=!AJrwHxfukZT-ueA>) by Benjamin RIOUAL
- [ZabbixPosh Api](<https://zabbixposhapi.codeplex.com/>) by simsaull

##### Zabbix Docs:
- [Zabbix API Libraries](<http://zabbix.org/wiki/Docs/api/libraries>)
- [Zabbix 2.4 API documentation](<https://www.zabbix.com/documentation/2.4/manual/api>)
- [Zabbix 3.4 API documentation](<https://www.zabbix.com/documentation/3.4/manual/api>)
- [Zabbix 4.2 API documentation](<https://www.zabbix.com/documentation/4.2/manual/api>)

### Warning:
- Be careful. Especially with the mass delete and the mass update. 
- Bugs happen. Use on your own risk.

### Experimental:
Get-ZabbixHostInventory
- Get stats from inventories
```powershell
Get-ZabbixHostInventory | ? os | group os -NoElement | sort count -desc
Get-ZabbixHostInventory | ? os -match linux | select hostid,name,os,tag | ft -a
Get-ZabbixHostInventory | ? location | group location -NoElement | sort count -desc
```
Set-ZabbixHostInventory
- Mass population the hosts' inventories:
```powershell
Example: input-inventory-mass-data.csv (two hosts)

HostID,Type,TypeDetails,Name,Alias,OSName,OSFullName,OSShortName,SerialNumberA,SerialNumberB,Tag,AssetTag,MACAddressA,MACAddressB,Hardware,DetailedHardware,Software,SoftwareDetails,SoftwareApplicationA,SoftwareApplicationB,SoftwareApplicationC,SoftwareApplicationD,SoftwareApplicationE,ContactPerson,Location,LocationLatitude,LocationLongitude,Notes,Chassis,Model,HWArchitecture,Vendor,ContractNumber,InstallerName,DeploymentStatus,URLA,URLB,URLC,HostNetworks,HostSubnetMask,HostRouter,OOBIPAddress,OOBHostSubnetMask,OOBRouter,HWPurchaseDate,HWInstallationDate,HWMaintenanceExpiryDate,HWDecommissioningDate,SiteAddressA,SiteAddressB,SiteAddressC,SiteCity,SiteState,SiteCountry,SiteZIPCode,SiteRackLocation,SiteNotes,PrimaryPOCName,PrimaryEmail,PrimaryPOCPhoneA,PrimaryPOCPhoneB,PrimaryPOCMobileNumber,PrimaryPOCScreenName,PrimaryPOCnNotes,SecondaryPOCName,SecondaryPOCEmail,SecondaryPOCPhoneA,SecondaryPOCPhoneB,SecondaryPOCMobileNumber,SecondaryPOCScreenName,SecondaryPOCNotes
10000,Type,TypeDetails,Name,Alias,OSName,DetailedOSName,ShortOSName,SerialNumberA,SerialNumberBB,Tag,AssetTag,MACAddressA,MACAddressB,Hardware,DetailedHardware,Software,SoftwareDetails,SoftwareApplicationA,SoftwareApplicationB,SoftwareApplicationC,SoftwareApplicationD,SoftwareApplicationE,ContactPerson,Location,LocLat,LocLong,Notes,Chassis,Model,HWArchitecture,Vendor,ContractNumber,InstallerName,DeploymentStatus,URLA,URLB,URLC,HostNetworks,HostSubnetMask,HostRouter,OOBIPAddress,OOBHostSubnetMask,OOBRouter,HWPurchaseDate,HWInstallationDate,HWMaintenanceExpiryDate,HWDecommissioningDate,SiteAddressA,SiteAddressB,SiteAddressC,SiteCity,SiteState,SiteCountry,SiteZIPCode,SiteRackLocation,SiteNotes,PrimaryPOCName,PrimaryEmail,PrimaryPOCPhoneA,PrimaryPOCPhoneB,PrimaryPOCMobileNumber,PrimaryPOCScreenName,PrimaryPOCnNotes,SecondaryPOCName,SecondaryPOCEmail,SecondaryPOCPhoneA,SecondaryPOCPhoneB,SecondaryPOCMobileNumber,SecondaryPOCScreenName,SecondaryPOCNotes
10001,Type,TypeDetails,Name,Alias,OSName,DetailedOSName,ShortOSName,SerialNumberA,SerialNumberBB,Tag,AssetTag,MACAddressA,MACAddressB,Hardware,DetailedHardware,Software,SoftwareDetails,SoftwareApplicationA,SoftwareApplicationB,SoftwareApplicationC,SoftwareApplicationD,SoftwareApplicationE,ContactPerson,Location,LocLat,LocLong,Notes,Chassis,Model,HWArchitecture,Vendor,ContractNumber,InstallerName,DeploymentStatus,URLA,URLB,URLC,HostNetworks,HostSubnetMask,HostRouter,OOBIPAddress,OOBHostSubnetMask,OOBRouter,HWPurchaseDate,HWInstallationDate,HWMaintenanceExpiryDate,HWDecommissioningDate,SiteAddressA,SiteAddressB,SiteAddressC,SiteCity,SiteState,SiteCountry,SiteZIPCode,SiteRackLocation,SiteNotes,PrimaryPOCName,PrimaryEmail,PrimaryPOCPhoneA,PrimaryPOCPhoneB,PrimaryPOCMobileNumber,PrimaryPOCScreenName,PrimaryPOCnNotes,SecondaryPOCName,SecondaryPOCEmail,SecondaryPOCPhoneA,SecondaryPOCPhoneB,SecondaryPOCMobileNumber,SecondaryPOCScreenName,SecondaryPOCNotes

Command:
Import-csv input-inventory-mass-data.csv | %{$splatParams=@{}}{$splatParams=(("$_").trim('@{}').replace("; ","`r`n") | ConvertFrom-StringData); Set-ZabbixHostInventory @splatParams}
```

### Installation from GitHub
```powershell
cd $env:Userprofile\Documents\WindowsPowerShell\Modules\
git clone https://github.com/yubu/psbbix.git
Import-Module psbbix
```
or
```powershell
cd c:\temp
git clone https://github.com/yubu/psbbix.git
Import-Module c:\temp\psbbix\psbbix.psm1
```
### Installation from Powershell Gallery 
    Install-Module psbbix

<!-- ### Installation from Powershell Gallery prerelease version
#### 0.2.0-alpha is available in the Gallery
    Install-Module psbbix -AllowPrerelease -AllowClobber -->

### Getting Started
##### Use powershell help to get commands and examples
```powershell
gcm -module psbbix
help get-zabbixhost -ex
## if you hate a lot of empty lines within powershell examples, you can compress the white space:
help get-zabbixhost -ex | out-string | remove-emptyLines
```
##### Use Get-ZabbixHelp (alias gzh) to find examples fast, in high density format. Search pattern will be highlighted by yellow color (Thanks to David Mohundro's Find-String module).
```powershell
Get-ZabbixHelp help
gzh -list                                       # List module functions
gzh -alias                                      # List module aliases
gzh *                                           # Get all examples
gzh host set                                    # Get (Zabbix)host related command with verb set == Set-ZabbixHost
gzh hostgroup new                               # Get (Zabbix)hostgroup related command with verb new == New-ZabbixHostGroup
gzh item -pattern "cassandra|entropy" 
gzh alert -pattern "example 4"
gzh graph -p path
```
##### Connect
```powershell
connect-Zabbix 10.10.10.10
connect-Zabbix 10.10.10.10 -noSSL
```

##### Session parameters
```powershell
@zabSessionParams should be used with almost every command
```

##### Get-ZabbixHost
```powershell
Get-ZabbixHost -HostName hostname
Get-ZabbixHost -HostName HostName
## all inline parameters are case sensitive! (because of Linux/MySQL)
## two above commands will work for different hosts
```
```powershell
Get-ZabbixHost -hostname Host | Get-ZabbixHttpTest -ea silent | select httptestid,name,steps
Get-ZabbixHost -hostname Host | Get-ZabbixHttpTest -ea silent | select -ExpandProperty steps | ft -a
```
```powershell
Get-ZabbixHost | ? name -match "host"
## not case sensitive (powershell way)
Get-ZabbixHost | ? name -match "" | measure
## count hosts 
```

##### New-ZabbixHost
```powershell
New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID "10081","10166"
## create new host
New-ZabbixHost -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID (Get-ZabbixHost | ? name -match "host").parentTemplates.templateid -status 1
## create new host, but disabled (-status 1)
```
```powershell
Import-Csv c:\new-servers.csv | %{New-ZabbixHost -HostName $_.Hostname -IP $_.IP -GroupID $_.GroupID -TemplateID $_.TemplateID -status $_.status}
## mass create new hosts
```
```powershell
Get-ZabbixHost | ? name -match SourceHost | New-ZabbixHost -HostName NewHost -IP 10.20.10.10
## clone host with single interface 
```
```powershell
Get-ZabbixHost | ? name -match SourceHost | New-ZabbixHost -HostName NewHostName -IP 10.20.10.10 -TemplateID (Get-ZabbixHost | ? name -match "SourceHost").parentTemplates.templateid -Interfaces (Get-ZabbixHostInterface -HostID (Get-ZabbixHost -HostName SourceHost).hostid) -status 1
Get-ZabbixHost | ? name -match NewHost | Get-ZabbixHostInterface | %{Set-ZabbixHostInterface -IP 10.20.10.10 -InterfaceID $_.interfaceid -Port $_.port -HostID $_.hostid}
## clone host with multiple interfaces, then update interfaces with new IP
```

##### Set-ZabbixHost
```powershell
Get-ZabbixHost | ? name -eq "hostName" | Set-ZabbixHost -status 1
## disable one host
Get-ZabbixHost | ? name -match "hostName" | %{Set-ZabbixHost -status 1 -HostID $_.hostid -parentTemplates $_.parenttemplates}
## disable multiple hosts
```
> **Warning**:  
If host has multiple linked templates and then Set-ZabbixHost will be executed with single new template, ALL templates will be replaced by only ONE new template.
```powershell
## this will work:
Get-ZabbixHost -HostName HostName | Set-ZabbixHost -TemplateID ExistingTemplateID,ExistingTemplateID,NewTemplateID
## and this:
$templateID=(Get-ZabbixTemplate -HostID (Get-ZabbixHost | ? name -match hostname).hostid).templateid
#Store existing templateIDs
$templateID+=(Get-ZabbixTemplate | ? name -match "newTemplate").templateid
#Add new templateIDs
Get-ZabbixHost | ? name -match hosts | Set-ZabbixHost -TemplateID $templateID 
```



##### Remove-ZabbixHost
```powershell
##!! use carefully !!##
Remove-ZabbixHost -HostID (Get-ZabbixHost -HostName ThisHostsRetired).hostid -WhatIf
## remove host(s) (case sensitive) (check only)
Remove-ZabbixHost -HostID (Get-ZabbixHost -HostName ThisHostsRetired).hostid
## remove host(s) (case sensitive)
Get-ZabbixHost  | ? name -eq RetiredHost | Remove-ZabbixHost
## remove single host (case insensitive)
Get-ZabbixHost | ? name -match "HostName-0[1-8]"  | %{Remove-ZabbixHost -HostID $_.hostid}
## delete multiple hosts
```

##### Get-ZabbixTemplate
```powershell
Get-ZabbixTemplate | select name,hosts
```

##### Get-ZabbixMaintenance
```powershell
Get-ZabbixMaintenance | select maintenanceid,name
(Get-ZabbixMaintenance -MaintenanceName "Maintenance").timeperiods
Get-ZabbixMaintenance | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | ft -a
## Get maintenance and timeperiods
Get-ZabbixMaintenance | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | select MaintenanceName,timeperiodid,timeperiod_type,@{n="start_date(UTC)";e={convertfrom-epoch $_.start_date}},@{n="period(Hours)";e={$_.period/3600}} | ft -a
## Get maintenance and timeperiods (Time in UTC)
```
```powershell
Get-ZabbixMaintenance | ? name -match "" | select Name,@{n="TimeperiodStart";e={(convertfrom-epoch $_.timeperiods.start_date).addhours(-5)}},@{n="Duration(hours)";e={$_.timeperiods.period/3600}}
## get all maintenances, display name, timeperiod (according UTC-5) and duration
```

##### New-ZabbixMaintenance
```powershell
New-ZabbixMaintenance -HostID (Get-ZabbixHost | ? name -match "hosts").hostid -MaintenanceName "NewMaintenance" -ActiveSince (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) -ActiveTill (convertTo-epoch ((get-date).addhours(7)).ToUniversalTime()) -TimeperiodPeriod (4*3600)
 -ActiveSince (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) == now
 -ActiveTill (convertTo-epoch ((get-date).addhours(7)).ToUniversalTime()) == now + 7 hours
 -TimeperiodPeriod (5*3600) == 5 hours
## Create new maintenance (time sent UTC, and will appear according Zabbix server)
New-ZabbixMaintenance -HostID (Get-ZabbixHost | ? name -match otherhost).hostid -MaintenanceName NewMaintenanceName -MaintenanceDescription NewMaintenanceDescription -ActiveSince (convertTo-epoch (get-date -date "05/25/2015 07:05")) -ActiveTill (convertTo-epoch (get-date -date "05/25/2015 17:05")) -TimeperiodPeriod (7*3600) -TimeperiodStartDate (convertTo-epoch (get-date -date "05/25/2015 09:05")
## Create new, future maintenance (case sensitive) (time will be sent in UTC). Will be set on Zabbix server according it's local time.
```

##### Remove-ZabbixMaintenance
```powershell
Remove-ZabbixMaintenance -MaintenanceID "3","4" 
Get-ZabbixMaintenance | ? name -match "MaintenanceName" | Remove-ZabbixMaintenance -WhatIf
```

##### Export-ZabbixConfig
```powershell
Export-ZabbixConfig -HostID (Get-ZabbixHost | ? name -match host).hostid | sc c:\zabbix-hosts-export.xml
Export-ZabbixConfig -TemplateID (Get-ZabbixTemplate | ? name -match "My template").templateid | sc c:\zabbix-templates-export.xml
```

##### Get-ZabbixAlert
```powershell
Get-ZabbixAlert |  ? sendto -match Email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
## get alarms from last 3 hours (default params). Time display UTC-5
Get-ZabbixAlert -TimeFrom (convertTo-epoch (get-date -date (((get-date).addhours(-5)).ToString())) -UTCOffset +0) -TimeTill (convertTo-epoch (get-date -date (((get-date).addhours(-4)).ToString())) -UTCOffset +0) |  ? sendto -match Email | ? subject -match OK | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
## get alerts with custom timewindow of 1 hour. (-timeFrom, -timeTill) 
```
```powershell
Get-ZabbixAlert -HostID (Get-ZabbixHost | ? name -match "Host|Other").hostid |  ? sendto -match Email | select @{n="Time(UTC+3)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
## works for multiple hosts. Get alerts for host from last 3 hours (default params). Display time in UTC -5
```

##### Get-ZabbixUser
```powershell
Get-ZabbixUser | select name,alias, attempt_ip, @{n="attempt_clock (UTC-5)"; e={((convertfrom-epoch $_.attempt_clock)).addhours(-5)}},@{n="usrgrps";e={$_.usrgrps.name}}
```

##### Remove-ZabbixUser
```powershell
Get-ZabbixUser | ? alias -eq "alias" | Remove-ZabbixUser
## delete one user
Remove-ZabbixUser -UserID (Get-ZabbixUser | ? alias -match "alias").userid
## delete multiple users
```

##### Set-ZabbixUser
```powershell
Get-ZabbixUser | ? alias -match "alias"  | Set-ZabbixUser -verbose -Name NewName -Surname NewSurname -rows_per_page 100
```

##### New-ZabbixUser
```powershell
Get-Zabbixuser | ? alias -match "User" | New-ZabbixUser -Name NewName -Surname NewSurname -Alias first.last -verbose -passwd "123456"
## clone user
```

##### Get-ZabbixUserGroup
```powershell
Get-ZabbixUserGroup  | select usrgrpid,name
(Get-ZabbixUserGroup | ? name -match administrators).users | select alias,users_status
```

##### Get-ZabbixTrigger
```powershell
Get-ZabbixTrigger -TemplateID (Get-ZabbixTemplate | ? name -match Template).templateid -ExpandDescription -ExpandExpression | ft -a status,description,expression
## get triggers by template
Get-ZabbixHost -HostName HostName | Get-ZabbixTrigger -ea silent | ? status -match 0 | ft -a status,templateid,description,expression
## get triggers by host (case sensitive)
```

##### Set-ZabbixTrigger
```powershell
Get-ZabbixTrigger -TemplateID (Get-zabbixTemplate | ? name -match "Template JMX JVM Generic").templateid | ? description -match "uses suboptimal JIT compiler" | Set-ZabbixTrigger -status 1
## disable trigger
```

##### Get-ZabbixAction
```powershell
Get-ZabbixAction  | select name
Get-ZabbixAction  | ? name -match action | select name,def_longdata,r_longdata
```

##### Set-ZabbixAction
```powershell
Get-ZabbixAction  | ? name -match actionName | Set-ZabbixAction  -status 1
## disable action
```

##### Get-ZabbixHostInterface
```powershell
Get-ZabbixHostInterface -HostID (Get-ZabbixHost -HostName ThisHost).hostid
Get-ZabbixHost -HostName HostName | Get-ZabbixHostInterface
```

##### Set-ZabbixHostInterface
```powershell
Get-ZabbixHost | ? name -match host | Get-ZabbixHostInterface | %{Set-ZabbixHostInterface -IP 10.20.10.12 -InterfaceID $_.interfaceid -HostID $_.hostid -Port $_.port}
## Modify interface settings for the single host
(1..100) | %{Get-ZabbixHost | ? name -match "host0$_" | Get-ZabbixHostInterface | ? port -match 31721 | Set-ZabbixHostInterface -main 1}
## Make interface default on all hosts
```

##### New-ZabbixHostInterface
```powershell
Get-ZabbixHost | ? name -match host | New-ZabbixHostInterface -IP 10.20.10.15 -port 31721
## Create new interface for the single host
(1..100) | %{Get-ZabbixHost | ? name -match "host0$_" | New-ZabbixHostInterface -Port 31771 -type 4 -main 1 -ip (Get-ZabbixHost | ? name -match "host0$_").interfaces.ip[0]}
## Create new JMX connection and set it default 
```

##### Remove-ZabbixHostInterface
```powershell
Get-ZabbixHost | ? name -match "host02" | Get-ZabbixHostInterface | ? port -Match 31721 | Remove-ZabbixHostInterface
## Remove interface on single host
Remove-ZabbixHostInterface -interfaceid (Get-ZabbixHost | ? name -match "host02" | Get-ZabbixHostInterface).interfaceid
## Remove all interfaces from the host
```

##### Get-ZabbixHttpTest
```powershell
Get-ZabbixHttpTest | ? name -match httpTest | select httptestid,name
Get-ZabbixHttpTest | ? name -like "test*Name" | ? {$_.hosts.host -match "Template name"}) | select name,@{e={$_.steps.url}},@{n='host';e={$_.hosts.host}} | sort host
```

##### New-ZabbixHttpTest
```powershell
New-ZabbixHttpTest -HttpTestName NewHttpTest -HttpTestStepURL "http://{HOST.CONN}:30555/health-check/do" -HttpTestStepRequired "version" -HostID (Get-ZabbixHost -HostName HostName).hostid
## create new http test
Get-ZabbixTemplate | ? name -eq "Template Name" | Get-ZabbixHttpTest | ? name -match httpTestSource | New-ZabbixHttpTest -HttpTestName NewHttpName
## clone http test 
```

##### Set-ZabbixHttpTest
```powershell
Get-ZabbixHttpTest -HttpTestName httpTest | Set-ZabbixHttpTest -status 1
## disable http test
```

##### Remove-ZabbixHttpTest
```powershell
Remove-ZabbixHttpTest -HttpTestID (Get-ZabbixTemplate | ? name -eq "Template Name" | Get-ZabbixHttpTest | ? name -match httpTests).httptestid
## delete http tests
```