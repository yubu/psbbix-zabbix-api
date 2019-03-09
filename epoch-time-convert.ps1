Function convertFrom-epoch {
	<#
	.Synopsis
		Convert from epoch time to human
	.Description
		Convert from epoch time to human
	.Example
		convertFrom-epoch 1295113860
	.Example
		convertFrom-epoch 1295113860 | convertTo-epoch
	#>
	[CmdletBinding()]
	param ([Parameter(ValueFromPipeline=$true)]$epochdate)

	process {
		if (!$psboundparameters.count) {gh -ex $PSCmdlet.MyInvocation.MyCommand.Name | out-string | remove-emptylines; return}
		#[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($epochdate)) 
		if (("$epochdate").length -gt 10 ) {
			# (Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)
			if (("$epochdate").Contains('.')) {
				$seconds=("$epochdate").Split('.')[0]
				$millis=("$epochdate").Split('.')[1]
				$epochdate=$seconds+($millis[0..2] -join "")
				(Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)
			}
			else {(Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)}
		}
		else {(Get-Date -Date "01/01/1970").AddSeconds($epochdate)}
	}
}

Function convertTo-epoch {
    <#
	.Synopsis
		Convert time to epoch
	.Description
		Convert time to epoch
	.Example
		convertTo-epoch (get-date -date "05/24/2015 17:05")
    .Example
        convertTo-epoch (get-date -date "05/24/2015 17:05") | convertFrom-epoch
    .Example
        (get-date -date "05/24/2015 17:05") | convertTo-epoch
    .Example 
        get-date | convertTo-epoch
    .Example
        convertTo-epoch (get-date).ToUniversalTime()
    .Example
        convertTo-epoch (get-date).ToUniversalTime() | convertFrom-epoch
    .Example
        convertTo-epoch ((get-date).AddHours(2)    
	#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline=$true)]$date
	)
	
	if (!$psboundparameters.count) {help -ex convertTo-epoch  | Out-String | Remove-EmptyLines; return}
	
    $date=$date -f "mm/dd/yyyy hh:mm"
	(New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End $date).TotalSeconds
}