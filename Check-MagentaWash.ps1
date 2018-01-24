# 23.1.2018 - Initial release. Base functionality backbone. Few WSUS options check for functionality test

$WSUSGroup = "EON"
$WSUSServer = "10.1.1.1"

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
	[CmdletBinding()]
	param (
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
				Set-CheckResult -Section $Section -Property $Property -ValueExpected $Value -ValueCurrent ((get-itemproperty $path -name $key -Ea silentlycontinue).$key) -Result $true
			} else {
				Write-Host 'reg value is not correct'
				Set-CheckResult -Section $Section -Property $Property -ValueExpected $Value -ValueCurrent ((get-itemproperty $path -name $key -Ea silentlycontinue).$key) -Result $false
			}
		}
		
	}
}


$Data = @{ }

#WSUS configuration
Check -Section "WSUS" -Property "Target group enabled" -Registry -path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "TargetGroupENabled" -Value 1
Check -Section "WSUS" -Property "Target group" -Registry -Path "Hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "TargetGroup" -Value $WSUSGroup
Check -Section "WSUS" -Property "Do Not Connect To Windows Update Internet Locations" -Registry -Path "Hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "DoNotConnectToWindowsUpdateInternetLocations" -Value 1
Check -Section "WSUS" -Property "AUOptions" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -key "AUOptions" -Value 3
Check -Section "WSUS" -Property "Detection frequency" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -key "DetectionFrequency" -value 16
Check -Section "WSUS" -Property "DetectionFrequencyEnabled" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "DetectionFrequencyEnabled" -Value 1
Check -Section "WSUS" -Property "NoAutoRebootWithLoggedOnUsers" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoRebootWithLoggedOnUsers" -Value 1
Check -Section "WSUS" -Property "NoAutoUpdate" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoUpdate" -Value 0
Check -Section "WSUS" -Property "RebootWarningTimeout" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "RebootWarningTimeout" -Value 5
Check -Section "WSUS" -Property "RebootWarningTimeoutEnabled" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "RebootWarningTimeoutEnabled" -Value 1
Check -Section "WSUS" -Property "ScheduledInstallDate" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "ScheduledInstallDay" -Value 0
Check -Section "WSUS" -Property "ScheduledInstallTime" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "ScheduledInstallTime" -Value 3
Check -Section "WSUS" -Property "Use Windows update server" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "UseWUServer" -Value 1
Check -Section "WSUS" -Property "WUServer" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "WUServer" -Value $WSUSServer
Check -Section "WSUS" -Property "WUStatusServer" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "WUStatusServer" -Value $WSUSServer

#SNMP TRAPS
Check -Section "SNMP" -Property "1" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\TrapConfiguration\HWmonitoring" -Key 1 -Value "127.0.0.1"
Check -Section "SNMP" -Property "hwmonitoring" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -Key "hwmonitoring" -Value "4"
Check -Section "SNMP" -Property "public" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -Key "public" "4" -Value
Check -Section "SNMP" -Property "win_hw-Q0l4xUT_lL" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -Key "win_hw-Q0l4xUT_lL" -Value "4"
Check -Section "SNMP" -Property "SysServices" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\RFC1156Agent" -Key "SysServices" -Value 73



#Connections
#Allow users to connect remotely by using Remote Desktop Services
Check -Section "Connections" -Property "fDenyTSConnections" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDenyTSConnections" -Value "0"
#Limit number of connections
Check -Section "Connections" -Property "MaxInstanceCount" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxInstanceCount" -Value  "2"
#Set rules for remote control of Remote Desktop Services user sessions
Check -Section "Connections" -Property "Shadow" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "Shadow" -Value "3"
#Restrict Remote Desktop Services users to a single Remote Desktop Services session
Check -Section "Connections" -Property "fSingleSessionPerUser" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fSingleSessionPerUser" -Value  "1"

#Device and Resource Redirection
#Allow audio and video playback redirection
Check -Section "Device and resource redirection" -Property "fDisableCam" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCam" -Value  "0"
#Allow audio recording redirection
Check -Section "Device and resource redirection" -Property "fDisableAudioCapture" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableAudioCapture" -Value  "0"
#Do not allow Clipboard redirection
Check -Section "Device and resource redirection" -Property "fDisableClip" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableClip" -Value  "0"
#Do not allow COM port redirection
Check -Section "Device and resource redirection" -Property "fDisableCcm" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCcm" -Value "1"
#Do not allow drive redirection
Check -Section "Device and resource redirection" -Property "fDisableCdm" -Registry -Path  "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCdm" -Value "1"
#Do not allow LPT port redirection
Check -Section "Device and resource redirection" -Property "fDisableLPT" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key  "fDisableLPT"-Value  "1"
#Do not allow supported Plug and Play device redirection
Check -Section "Device and resource redirection" -Property "fDisablePNPRedir" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key"fDisablePNPRedir" -Value "1"

#Printer Redirection
#Do not allow client printer redirection
Check -Section "Printer redirection" -Property "fDisableCpm" -Registry -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCpm" -Value "1"
#Do not set default client printer to be default printer in a session
Check -Section "Printer redirection" -Property "fForceClientLptDef" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fForceClientLptDef" -Value "0"

#Remote Session Environment
#Limit maximum color depth
Check -Section "Remote session environment" -Property "ColorDepth" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "ColorDepth" -Value "3"

#Security
#Always prompt for password upon connection
Check -Section "Security" -Property "fPromptForPassword" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fPromptForPassword" -Value "1"
#Require use of specific security layer for remote (RDP) connections
Check -Section "Security" -Property "SecurityLayer" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "SecurityLayer" -Value  "1"
#Require user authentication for remote connections by using Network Level Authentication
Check -Section "Security" -Property "UserAuthentication" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "UserAuthentication" -Value "0"
#Set client connection encryption level
Check -Section "Security" -Property "MinEncryptionLevel" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MinEncryptionLevel" -Value  "2"

#Session Time Limits
#End session when time limits are reached
Check -Section "Session Time Limits" -Property "fResetBroken" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fResetBroken" -Value  "0"
#Set time limit for active but idle Remote Desktop Services sessions
Check -Section "Session Time Limits" -Property "MaxIdleTime" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxIdleTime" -Value "3600000"
#Set time limit for active Remote Desktop Services sessions
Check -Section "Session Time Limits" -Property "MaxConnectionTime" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxConnectionTime" -Value "0"
#Set time limit for disconnected sessions
Check -Section "Session Time Limits" -Property "MaxDisconnectionTime" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxDisconnectionTime" -Value "900000"

#Temporary folders
#Do not delete temp folders upon exit
Check -Section "Temporary folders" -Property "DeleteTempDirsOnExit" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "DeleteTempDirsOnExit" -Value  "1"
#Do not use temporary folders per session
Check -Section "Temporary folders" -Property "PerSessionTempDir" -Registry -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "PerSessionTempDir" -Value  "1" 