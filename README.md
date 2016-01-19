# psbbix
Powershell Module for Zabbix API

##### Compatibility
- Tested with Zabbix 2.4 
- Tested with Powershell 5

##### Based on:
- [Zabbix](<https://onedrive.live.com/?cid=3b909e9df5dc497a&id=3B909E9DF5DC497A%213668&ithint=folder,psm1&authkey=!AJrwHxfukZT-ueA>) by Benjamin RIOUAL
- [ZabbixPosh Api](<https://zabbixposhapi.codeplex.com/>) by simsaull

##### Zabbix Docs:
- [Zabbix API Libraries](<http://zabbix.org/wiki/Docs/api/libraries>)
- [Zabbix 2.4 API documentation](<https://www.zabbix.com/documentation/2.4/manual/api>)

### Warning: 
Be careful. Especially with mass delete and mass update. 
Bugs happen. Use on your own risk.

### Installation
1. download repository zip.
2. mkdir $env:userprofile\Documents\WindowsPowerShell\Modules\psbbix
3. copy all files to $env:userprofile\Documents\WindowsPowerShell\Modules\psbbix
4. add the following lines to the powershell profile file:
```powershell
.  $env:userprofile\Documents\WindowsPowerShell\Modules\psbbix\epoch-time-convert.ps1
import-module $env:userprofile\Documents\WindowsPowerShell\Modules\psbbix\psbbix.psm1
```
### Getting Started
##### Use powershell help to get commands and examples
```powershell
gcm -module psbbix
help get-zabbixhost -ex
## if you hate a lot of empty lines within powershell examples, you can compress the white space:
help get-zabbixhost -ex | out-string | remove-emptyLines
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
Get-ZabbixHost @zabSessionParams -HostName hostname
Get-ZabbixHost @zabSessionParams -HostName HostName
## all inline parameters are case sensitive! (because of Linux/MySQL)
## two above commands will work for different hosts
```
```powershell
Get-ZabbixHost @zabSessionParams -hostname Host | Get-ZabbixHttpTest @zabSessionParams -ea silent | select httptestid,name,steps
Get-ZabbixHost @zabSessionParams -hostname Host | Get-ZabbixHttpTest @zabSessionParams -ea silent | select -ExpandProperty steps | ft -a
```
```powershell
Get-ZabbixHost @zabSessionParams | ? name -match "host"
## not case sensitive (powershell way)
Get-ZabbixHost @zabSessionParams | ? name -match "" | measure
## count hosts 
```

##### New-ZabbixHost
```powershell
New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID "10081","10166"
## create new host
New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10 -GroupID 8 -TemplateID (Get-ZabbixHost @zabSessionParams | ? name -match "host").parentTemplates.templateid -status 1
## create new host, but disabled (-status 1)
```
```powershell
Import-Csv c:\new-servers.csv | %{New-ZabbixHost @zabSessionParams -HostName $_.Hostname -IP $_.IP -GroupID $_.GroupID -TemplateID $_.TemplateID -status $_.status}
## mass create new hosts
```
```powershell
Get-ZabbixHost @zabSessionParams | ? name -match SourceHost | New-ZabbixHost @zabSessionParams -HostName NewHost -IP 10.20.10.10
## clone host with single interface 
```
```powershell
Get-ZabbixHost @zabSessionParams | ? name -match SourceHost | New-ZabbixHost @zabSessionParams -HostName NewHostName -IP 10.20.10.10 -TemplateID (Get-ZabbixHost @zabSessionParams | ? name -match "SourceHost").parentTemplates.templateid -Interfaces (Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName SourceHost).hostid) -status 1
Get-ZabbixHost @zabSessionParams | ? name -match NewHost | Get-ZabbixHostInterface @zabSessionParams | %{Set-ZabbixHostInterface @zabSessionParams -IP 10.20.10.10 -InterfaceID $_.interfaceid -Port $_.port -HostID $_.hostid}
## clone host with multiple interfaces, then update interfaces with new IP
```

##### Set-ZabbixHost
```powershell
Get-ZabbixHost @zabSessionParams | ? name -eq "hostName" | Set-ZabbixHost @zabSessionParams -status 1
## disable one host
Get-ZabbixHost @zabSessionParams | ? name -match "hostName" | %{Set-ZabbixHost @zabSessionParams -status 1 -HostID $_.hostid -parentTemplates $_.parenttemplates}
## disable multiple hosts
```
> **Warning**:  
If host has multiple linked templates and then Set-ZabbixHost will be executed with single new template, ALL templates will be replaced by only ONE new template.
```powershell
## this will work:
Get-ZabbixHost @zabSessionParams -HostName HostName | Set-ZabbixHost @zabSessionParams -TemplateID ExistingTemplateID,ExistingTemplateID,NewTemplateID
```



##### Remove-ZabbixHost
```powershell
##!! use carefully !!##
Remove-ZabbixHost @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName ThisHostsRetired).hostid -WhatIf
## remove host(s) (case sensitive) (check only)
Remove-ZabbixHost @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName ThisHostsRetired).hostid
## remove host(s) (case sensitive)
Get-ZabbixHost  @zabSessionParams | ? name -eq RetiredHost | Remove-ZabbixHost @zabSessionParams
## remove single host (case insensitive)
Get-ZabbixHost @zabSessionParams | ? name -match "HostName-0[1-8]"  | %{Remove-ZabbixHost @zabSessionParams -HostID $_.hostid}
## delete multiple hosts
```

##### Get-ZabbixTemplate
```powershell
Get-ZabbixTemplate @zabSessionParams | select name,hosts
```

##### Get-ZabbixMaintenance
```powershell
Get-ZabbixMaintenance @zabSessionParams | select maintenanceid,name
(Get-ZabbixMaintenance @zabSessionParams -MaintenanceName "Maintenance").timeperiods
Get-ZabbixMaintenance @zabSessionParams | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | ft -a
## Get maintenance and timeperiods
Get-ZabbixMaintenance @zabSessionParams | select -Property @{n="MaintenanceName";e={$_.name}} -ExpandProperty timeperiods | select MaintenanceName,timeperiodid,timeperiod_type,@{n="start_date(UTC)";e={convertfrom-epoch $_.start_date}},@{n="period(Hours)";e={$_.period/3600}} | ft -a
## Get maintenance and timeperiods (Time in UTC)
```
```powershell
Get-ZabbixMaintenance @zabSessionParams | ? name -match "" | select Name,@{n="TimeperiodStart";e={(convertfrom-epoch $_.timeperiods.start_date).addhours(-5)}},@{n="Duration(hours)";e={$_.timeperiods.period/3600}}
## get all maintenances, display name, timeperiod (according UTC-5) and duration
```

##### New-ZabbixMaintenance
```powershell
New-ZabbixMaintenance @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "hosts").hostid -MaintenanceName "NewMaintenance" -ActiveSince (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) -ActiveTill (convertTo-epoch ((get-date).addhours(7)).ToUniversalTime()) -TimeperiodPeriod (4*3600)
 -ActiveSince (convertTo-epoch ((get-date).addhours(0)).ToUniversalTime()) == now
 -ActiveTill (convertTo-epoch ((get-date).addhours(7)).ToUniversalTime()) == now + 7 hours
 -TimeperiodPeriod (5*3600) == 5 hours
## Create new maintenance (time sent UTC, and will appear according Zabbix server)
New-ZabbixMaintenance @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match otherhost).hostid -MaintenanceName NewMaintenanceName -MaintenanceDescription NewMaintenanceDescription -ActiveSince (convertTo-epoch (get-date -date "05/25/2015 07:05")) -ActiveTill (convertTo-epoch (get-date -date "05/25/2015 17:05")) -TimeperiodPeriod (7*3600) -TimeperiodStartDate (convertTo-epoch (get-date -date "05/25/2015 09:05")
## Create new, future maintenance (case sensitive) (time will be sent in UTC). Will be set on Zabbix server according it's local time.
```

##### Remove-ZabbixMaintenance
```powershell
Remove-ZabbixMaintenance @zabSessionParams -MaintenanceID "3","4" 
Get-ZabbixMaintenance @zabSessionParams | ? name -match "Maint" | Remove-ZabbixMaintenance @zabSessionParams -WhatIf
```

##### Export-ZabbixConfig
```powershell
Export-ZabbixConfig @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match host).hostid | sc c:\zabbix-hosts-export.xml
Export-ZabbixConfig @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match "My template").templateid | sc c:\zabbix-templates-export.xml
```

##### Get-ZabbixAlert
```powershell
Get-ZabbixAlert @zabSessionParams |  ? sendto -match Email | select @{n="Time(UTC-5)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
## get alarms from last 3 hours (default params). Time display UTC-5
Get-ZabbixAlert @zabSessionParams -TimeFrom (convertTo-epoch (get-date -date (((get-date).addhours(-5)).ToString())) -UTCOffset +0) -TimeTill (convertTo-epoch (get-date -date (((get-date).addhours(-4)).ToString())) -UTCOffset +0) |  ? sendto -match Email | ? subject -match OK | select @{n="Time(UTC)";e={convertfrom-epoch $_.clock}},alertid,sendto,subject 
## get alerts with custom timewindow of 1 hour. (-timeFrom, -timeTill) 
```
```powershell
Get-ZabbixAlert @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams | ? name -match "Host|Other").hostid |  ? sendto -match Email | select @{n="Time(UTC+3)";e={(convertfrom-epoch $_.clock).addhours(-5)}},alertid,subject
## works for multiple hosts. Get alerts for host from last 3 hours (default params). Display time in UTC -5
```

##### Get-ZabbixUser
```powershell
Get-ZabbixUser @zabSessionParams | select name,alias, attempt_ip, @{n="attempt_clock (UTC-5)"; e={((convertfrom-epoch $_.attempt_clock)).addhours(-5)}},@{n="usrgrps";e={$_.usrgrps.name}}
```

##### Remove-ZabbixUser
```powershell
Get-ZabbixUser @zabSessionParams | ? alias -eq "alias" | Remove-ZabbixUser @zabSessionParams
## delete one user
Remove-ZabbixUser @zabSessionParams -UserID (Get-ZabbixUser @zabSessionParams | ? alias -match "alias").userid
## delete multiple users
```

##### Set-ZabbixUser
```powershell
Get-ZabbixUser @zabSessionParams | ? alias -match "alias"  | Set-ZabbixUser @zabSessionParams -verbose -Name NewName -Surname NewSurname -rows_per_page 100
```

##### New-ZabbixUser
```powershell
Get-Zabbixuser @zabSessionParams | ? alias -match "User" | New-ZabbixUser @zabSessionParams -Name NewName -Surname NewSurname -Alias first.last -verbose -passwd "123456"
## clone user
```

##### Get-ZabbixUserGroup
```powershell
Get-ZabbixUserGroup  @zabSessionParams | select usrgrpid,name
(Get-ZabbixUserGroup @zabSessionParams | ? name -match administrators).users | select alias,users_status
```

##### Get-ZabbixTrigger
```powershell
Get-ZabbixTrigger @zabSessionParams -TemplateID (Get-ZabbixTemplate @zabSessionParams | ? name -match Template).templateid -ExpandDescription -ExpandExpression | ft -a status,description,expression
## get triggers by template
Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixTrigger @zabSessionParams -ea silent | ? status -match 0 | ft -a status,templateid,description,expression
## get triggers by host (case sensitive)
```

##### Set-ZabbixTrigger
```powershell
Get-ZabbixTrigger @zabSessionParams -TemplateID (Get-zabbixTemplate @zabSessionParams | ? name -match "Template JMX JVM Generic").templateid | ? description -match "uses suboptimal JIT compiler" | Set-ZabbixTrigger @zabSessionParams -status 1
## disable trigger
```

##### Get-ZabbixAction
```powershell
Get-ZabbixAction  @zabSessionParams | select name
Get-ZabbixAction  @zabSessionParams | ? name -match action | select name,def_longdata,r_longdata
```

##### Set-ZabbixAction
```powershell
Get-ZabbixAction  @zabSessionParams | ? name -match actionName | Set-ZabbixAction  @zabSessionParams -status 1
## disable action
```

##### Get-ZabbixHostInterface
```powershell
Get-ZabbixHostInterface @zabSessionParams -HostID (Get-ZabbixHost @zabSessionParams -HostName ThisHost).hostid
Get-ZabbixHost @zabSessionParams -HostName HostName | Get-ZabbixHostInterface @zabSessionParams
```

##### Set-ZabbixHostInterface
```powershell
Get-ZabbixHost @zabSessionParams | ? name -match host | Get-ZabbixHostInterface @zabSessionParams | %{Set-ZabbixHostInterface @zabSessionParams -IP 10.20.10.12 -InterfaceID $_.interfaceid -HostID $_.hostid -Port $_.port}
## Modify interface settings for the single host
(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | Get-ZabbixHostInterface @zabSessionParams | ? port -match 31721 | Set-ZabbixHostInterface @zabSessionParams -main 1}
## Make interface default on all hosts
```

##### New-ZabbixHostInterface
```powershell
Get-ZabbixHost @zabSessionParams | ? name -match host | New-ZabbixHostInterface @zabSessionParams -IP 10.20.10.15 -port 31721
## Create new interface for the single host
(1..100) | %{Get-ZabbixHost @zabSessionParams | ? name -match "host0$_" | New-ZabbixHostInterface @zabSessionParams -Port 31771 -type 4 -main 1 -ip (Get-ZabbixHost @zabSessionParams | ? name -match "host0$_").interfaces.ip[0]}
## Create new JMX connection and set it default 
```

##### Remove-ZabbixHostInterface
```powershell
Get-ZabbixHost @zabSessionParams | ? name -match "host02" | Get-ZabbixHostInterface @zabSessionParams | ? port -Match 31721 | Remove-ZabbixHostInterface @zabSessionParams
## Remove interface on single host
Remove-ZabbixHostInterface @zabSessionParams -interfaceid (Get-ZabbixHost @zabSessionParams | ? name -match "host02" | Get-ZabbixHostInterface @zabSessionParams).interfaceid
## Remove all interfaces from the host
```

##### Get-ZabbixHttpTest
```powershell
Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTest | select httptestid,name
Get-ZabbixHttpTest @zabSessionParams | ? name -like "test*Name" | ? {$_.hosts.host -match "Template name"}) | select name,@{e={$_.steps.url}},@{n='host';e={$_.hosts.host}} | sort host
```

##### New-ZabbixHttpTest
```powershell
New-ZabbixHttpTest @zabSessionParams -HttpTestName NewHttpTest -HttpTestStepURL "http://{HOST.CONN}:30555/health-check/do" -HttpTestStepRequired "version" -HostID (Get-ZabbixHost @zabSessionParams -HostName HostName).hostid
## create new http test
Get-ZabbixTemplate @zabSessionParams | ? name -eq "Template Name" | Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTestSource | New-ZabbixHttpTest @zabSessionParams -HttpTestName NewHttpName
## clone http test 
```

##### Set-ZabbixHttpTest
```powershell
Get-ZabbixHttpTest @zabSessionParams -HttpTestName httpTest | Set-ZabbixHttpTest @zabSessionParams -status 1
## disable http test
```

##### Remove-ZabbixHttpTest
```powershell
Remove-ZabbixHttpTest @zabSessionParams -HttpTestID (Get-ZabbixTemplate @zabSessionParams | ? name -eq "Template Name" | Get-ZabbixHttpTest @zabSessionParams | ? name -match httpTests).httptestid
## delete http tests
```

##### Topic
```powershell

```

#### Topic
```powershell

```
