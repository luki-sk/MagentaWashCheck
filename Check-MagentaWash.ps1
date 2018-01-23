# 23.1.2018 - Initial release. Base functionality backbone. Few WSUS options check for functionality test

$WSUSGroup = "EON"

function Set-CheckResult {
	[CmdletBinding()]
	Param (
		[string]$Section,
		[string]$property,
		[bool]$result,
		$ValueExpected,
		$ValueCurrent
	)
	begin {
		Write-Host "SET-CHECKRESULT: $Section - $property - $result - $ValueExpected - $ValueCurrent"
		if ($ValueCurrent -eq $null) {
			Write-Host "Current value not set. setting to empty string"
			$ValueCurrent = "not set"		
		}
	
	}
process {
		if ($script:Data.$Section -eq $null) {
			Write-Host "Section $section doesnt exist. Creating"
			$script:Data.$Section = @{ }
		} else {
			Write-Host "Section $section exists"
		}
		
		if ($script:Data.$Section.$property -eq $null) {
			#Write-Host "Property $property doesnt exist. Creating"
			#$script:Data.$Section | add-member -MemberType NoteProperty -Name $Property -Value (New-Object System.Management.Automation.PSObject -Property @{ ValueExpected = $ValueExpected; ValueCurrent = $ValueCurrent; Result = $result })
		#} else {
			#Write-Host "Property $property exist. Setting"
			$script:Data.$Section.$property = New-Object System.Management.Automation.PSObject -Property @{ ValueExpected = $ValueExpected; ValueCurrent = $ValueCurrent; Result = $result }
		}
	}
}

function Check {
	[CmdletBinding()]param (
		[Parameter(Mandatory = $true, ParameterSetName = 'registry')]
		[switch]$Registry,
		[Parameter(Mandatory = $true, ParameterSetName = 'registry')]
		[string]$Path,
		[Parameter(Mandatory = $true, ParameterSetName = 'registry')]
		[string]$Key,
		[Parameter(Mandatory = $true, ParameterSetName = 'registry')]
		[string]$Value,
		[Parameter(Mandatory = $true, ParameterSetName = 'Command')]
		[switch]$command,
		[Parameter(Mandatory = $true, ParameterSetName = 'Command')]
		[string]$something
		,
		[string]$shared,
		[string]$Section,
		[string]$Property
		
	)
	Begin {
		if ($Registry) {
			Write-Host "CHECK REGISTRY: $Path - $key - $value for $section - $property"
		}
	}
	
	Process {
		if ($registry) {
			if ((get-itemproperty $path -name $key -Ea silentlycontinue).$key -like $value) {
				Write-Host 'reg value is correct'
				Set-CheckResult -Section $Section -Property $key -ValueExpected $Value -ValueCurrent ((get-itemproperty $path -name $key -Ea silentlycontinue).$key)  -Result $true
			} else {
				Write-Host 'reg value is not correct'
				Set-CheckResult -Section $Section -Property $key -ValueExpected $Value -ValueCurrent ((get-itemproperty $path -name $key -Ea silentlycontinue).$key) -Result $false
			}
		}
		
	}
}


$Data = @{}

#WSUS configuration

Check -Section "WSUS" -Property "Target group enabled" -Registry -path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "TargetGroupENabled" -Value 1

Check -Section "WSUS" -Property "Target group" -Registry -Path "Hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "TargetGroup" -Value $WSUSGroup
Check -Section "WSUS" -Property "Do Not Connect To Windows Update Internet Locations" -Registry -Path "Hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 
Check -Section "WSUS" -Property "AUOptions" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -key "AUOptions" -Value 3
Check -Section "WSUS" -Property "Detection frequency" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -key "DetectionFrequency" -value 16



<#
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "DetectionFrequencyEnabled" 1 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" 1 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "RebootWarningTimeout" 5 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "RebootWarningTimeoutEnabled" 1 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3 "dword"
set-regkey "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "UseWUServer" 1 "dword"

#>