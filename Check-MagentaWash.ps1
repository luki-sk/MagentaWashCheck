# 23.01.2018 - Initial release. Base functionality backbone. Few WSUS options check for functionality test
# 24.01.2018 - Added WSUS configuration, SNMP configuration and terminal services configuration
# 24.01.2018 - Added initial version of HTML report
# 24.01.2018 - Added McAfee AV check, added check of installed win features
# 26.01.2018 - Extended McAfee AV details, Added Winaudit, logW, HPSA tools. Added check of system config file. Started with HPSAM tool check
# 29.01.2018 - Added check for local Administrators group members.Added check for build-in admin name,updated functions for HPSAM to supress errors on servers where no HPSAM in installed




# check https://github.com/luki-sk/MagentaWashCheck for new version os issue reporting
$version = "0.0.5"

$ParamWSUSGroup = "EON"
$ParamWSUSServer = "10.1.1.1"
$ParamMcAfeeVersion = "VSE88P9"
$ParamMcAfeeEPO = "10.67.4.7:57398"
$paramWinauditVersion = 205
$paramWinauditServer = "164.32.27.148"
$paramWinauditPort = "2444"
$paramWinauditDatDate = 'anything'
$paramLogWVersion = "1.30"
$paramLogWServer = "6.49.35.103"
$paramLogWPort = 314
$paramSger = "nenula"
$ParamDOnumber = 'nenula'
$paramHPSAMID = 'nenula'
$ParamHPSAServer = '160.118.6.168'
$PAramHPSAPort = 3001
$ParamHPSAMServer = "2a00:da9:ff00:61d:e9::2090:6932"
$ParamLocalAdminRequired = 'osadmin'
$ParamLocalAdminAllowed = 'osadmin', 'brutus'
$ParamLocalAdminName = 'osadmin'

#telnet connection test
function Test-Telnet {
	param (
		[string]$IP,
		[int]$port,
		[int]$timeout = 2000
	)
	if ($IP -and $port) {
		$tcpobject = New-Object -TypeName System.Net.Sockets.TcpClient
		$connect = $tcpobject.BeginConnect($IP, $Port, $null, $null)
		$connection = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
		return $connection
	}
	return (
	$false
	)
}

function get-CDROMLetter {
	[CmdletBinding()]
	Param ()
	
	Process {
		$CDROMLetter = (gwmi win32_logicaldisk -Filter "drivetype=5") | %{ $_.deviceID }
		if (!$CDROMLetter) {
		return "not detected"
		} else {
		return $CDROMLetter	
		}
	}
	
}

function Get-LocalAdmins {
	[CmdletBinding()]
	Param ()
	
	Process {
		return net localgroup administrators | where { $_ -AND $_ -notmatch "command completed successfully" } | %{ $_.tolower() } | select -skip 4
	}
}

function get-LocalAdminRequired {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[string[]]$required
	)
	
	Process {
		$Users = Get-LocalAdmins
		foreach ($item in $required) {
			if (!($Users.contains($item.ToLower()))) {
				return $false
			}
		}
		return $true
	}
}


function get-LocalAdminAllowed {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[string[]]$allowed
	)
	Begin {
		$allowed = $allowed | % { $_.ToLower()}
	}
	Process {
		$Users = Get-LocalAdmins
		foreach ($item in $users) {
			if (!($allowed.contains($item))) {
				return $false
			}
		}
		return $true
	}
}

function Get-LocalBuildInAdmin {
	[CmdletBinding()]
	Param ()
	
	Process {
		$adsi = [ADSI]"WinNT://localhost"
		$Users = $adsi.Children | where { $_.SchemaClassName -eq 'user' } | select @{ n = 'User'; e = { $_.name } }, @{n = 'SID'; e = {(New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value, 0)).Value}}
		
		$BuildInAdmin = $Users | where { $_.sid -like "*-500" }
		return $BuildInAdmin.User
	}
}

function get-DOnumber {
	[CmdletBinding()]
	Param ()
	
	process {
		if ((Test-Path $ConfigFile -PathType Leaf)) {
			[string]$DO_row = Get-Content $ConfigFile | Select-String "task*"
			if ($DO_row -eq $null) {
				return "DO not defined"
			} else {
				$DO = $DO_row.Substring($DO_row.LastIndexOf("=") + 1)
				
				if ($DO -eq $null -or $DO -like "") {
					return "DO not defined"
				} else {
					return $DO
				}
			}
		} else {
			return "file missing"
		}
	}
}
function get-Sger {
	[CmdletBinding()]
	Param ()
	
	process {
		if ((Test-Path $ConfigFile -PathType Leaf)) {
			[string]$Sger_row = Get-Content $ConfigFile | Select-String "system_id*"
			if ($Sger_row -eq $null) {
				return "sger not defined"
			} else {
				$Sger = $Sger_row.Substring($Sger_row.LastIndexOf("=") + 1)
				
				if ($Sger -eq $null -or $Sger -like "") {
					return "sger not defined"
				} else {
					return $sger
				}
			}
		} else {
			return "file missing"
		}
	}
}

function Get-HPSAMID {
	[CmdletBinding()]
	Param ()
	begin {
		$MIDfile = 'C:\Program Files\Common Files\Opsware\etc\agent\mid'
	}
	Process {
		
		if (Test-Path $MIDfile) {
			$MIDContent = (Get-Content $MIDfile)[0]
			if ($MIDContent.trim() -eq $null -or $MIDContent.trim() -like "") {
				return "MID not defined"
			} else {
				return $MIDContent
			}
		} else {
			return "file missing"
		}
		
	}
	
}
function get-HPSAServer {
	[CmdletBinding()]
	Param ()
	begin {
		$ArgFile = 'C:\Program Files\Common Files\Opsware\etc\agent\opswgw.args'
	}
	Process {
		if (Test-Path $ArgFile) {
			$Content = (Get-Content $ArgFile)
			$String = ($Content.replace("opswgw.gw_list: ", "").split(","))[0]
			if ($string) {
				return New-Object System.Management.Automation.PSObject -Property @{ Server = $String.split(":")[0]; port = $String.split(":")[1] }
			} else {
				return New-Object System.Management.Automation.PSObject -Property @{ Server = "not detected"; port = "not detected" }
			}
		} else {
			return New-Object System.Management.Automation.PSObject -Property @{ Server = "file missing"; port = "file missing" }
		}
		
	}
	
}

function get-HPSAMCertificateStatus {
	[CmdletBinding()]
	Param ()
	Process {
		try {
			$result = ovcert -status
		} catch {

		}
		if ($result) {
			return $result.replace("Status: ", "")
		} else {
			return "Ovconfget commad not found"
}
	}
	
}
function Get-HPSAMServer {
	[CmdletBinding()]
	Param ()
	Process {
		Try {
			$ovconfget = ovconfget
		} Catch {
			
		}
		
		if ($ovconfget) {
			return ($ovconfget | where { $_ -like "MANAGER=*" }).Replace("MANAGER=", "")
		} else {
			return "ovconfget commad not found"
		}
	}
}
function Get-McAfeeEPO {
	[CmdletBinding()]
	Param ()
	
	begin {
		switch ($OSData.architecture) {
			"32" {
				$EPOList = (get-itemproperty "HKLM:\SOFTWARE\Network Associates\ePolicy Orchestrator\Agent" -name "ePOServerList" -Ea silentlycontinue).ePOServerList
			}
			"64"{
				$EPOList = (get-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Agent" -name "ePOServerList" -Ea silentlycontinue).ePOServerList
			}
		}
		if ($EPOList) {
			$EPOListSplitted = $EPOList.split(";")
		}
	}
	Process {
		$Result = @()
		if ($EPOListSplitted) {
			foreach ($item in $EPOListSplitted) {
				if ($item -notlike "") {
					$Result += New-Object System.Management.Automation.PSObject -Property @{ Server = $($item.split("|")[1]); Port = $($item.split("|")[2]) }
				}
			}
			return $Result
		} else {
			return $false
		}
		
	}
	
}
function Get-VmwareToolsVersion {
	
	Process {
		$path = "hklm:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
		$Subkeys = (Get-Childitem -Path $Path).Name
		foreach ($item in $Subkeys) {
			$SubPath = $item.replace("HKEY_LOCAL_MACHINE","hklm:")
			$details = Get-ItemProperty -Path $SubPath
			if ($details.DisplayName -like "VMware Tools") {
				return $details.DisplayVersion
			}
		}
		return "Not detected"
	}
}


#detect OS version and architecture
Function Get-OSVersionData {
	$os = gwmi win32_operatingsystem
	switch -wildcard ($os.version) {
		
		"10.0*" { $version = "W2k16"; $family = 'W2k16' }
		"6.3*" { $version = "W2k12R2"; $family = 'W2k12' }
		"6.2*" { $version = "W2k12"; $family = 'W2k12' }
		"6.1*" { $version = "W2k8R2"; $family = 'W2k8' }
		"6.0*" { $version = "W2k8"; $family = 'W2k8' }
	}
	
	write-output (new-object psobject -Property @{ Version = $os.version; Name = $version; Family = $family; Architecture = (($os.OSArchitecture).substring(0, 2)) })
	
}


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
		$ValueExpected.gettype()
		if ($ValueExpected -eq $null) {
			Write-Host "Expected value not set. setting to ---g"
			$ValueExpected = "---"
			$result = $null
		}
		
	}
	process {
		if ($script:Data.$Section -eq $null) {
			$script:Data.$Section = @{ }
		}
		
		if ($script:Data.$Section.$property -eq $null) {
			$script:Data.$Section.$property = New-Object System.Management.Automation.PSObject -Property @{ ValueExpected = $ValueExpected; ValueCurrent = $ValueCurrent; Result = $result }
		}
		Write-Host "**********"
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
		[Parameter(Mandatory = $true, ParameterSetName = 'feature')]
		[switch]$Feature,
		[Parameter(Mandatory = $true, ParameterSetName = 'service')]
		[switch]$service,
		[Parameter(Mandatory = $true, ParameterSetName = 'string')]
		[switch]$string,
		[Parameter(Mandatory = $true, ParameterSetName = 'string')]
		[string]$CurrentValue,
		[Parameter(Mandatory = $true, ParameterSetName = 'string')]
		[string]$ExpectedValue,
		[string]$Name,
		[string]$Value,
		[string]$Section,
		[string]$Property
	)
	Begin {
		if ($Registry) {
			Write-Host "CHECK REGISTRY: $Path - $key - $value IN $section - $property"
		} elseif ($Feature) {
			Write-Host "CHECK FEATURE: $Name IN $section - $property"
		} elseif ($service) {
			Write-Host "CHECK SERVICE: $Name - $Value IN $section - $property"
		} elseif ($String) {
			Write-Host "CHECK STRING: $Name - $Value IN $section - $property"
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
		} elseif ($Feature) {
			$status = $features | where { $_.name -like $name }
			if ($status.InstallState -eq "Installed") {
				Set-CheckResult -Section $Section -property $Property -ValueExpected "Installed" -ValueCurrent $status.InstallState -result $true
			} else {
				Set-CheckResult -Section $Section -property $Property -ValueExpected "Installed" -ValueCurrent $status.InstallState -result $false
			}
		} elseif ($service) {
			$status = Get-Service $Name -ErrorAction SilentlyContinue
			if ($status.status -like $value) {
				Set-CheckResult -Section $Section -property $Property -ValueExpected $Value -ValueCurrent $status.status -result $true
			} else {
				Set-CheckResult -Section $Section -property $Property -ValueExpected $Value -ValueCurrent $status.status -result $false
			}
		} elseif ($string) {
			if ($CurrentValue -like $ExpectedValue) {
				Set-CheckResult -Section $Section -property $Property -ValueExpected $ExpectedValue -ValueCurrent $CurrentValue -result $true
			} else {
				Set-CheckResult -Section $Section -property $Property -ValueExpected $ExpectedValue -ValueCurrent $CurrentValue -result $false
			}
		}
		
	}
}

function Get-HTMLHeader {
	return @'
	<!DOCTYPE html>
	<!--[if IE 9 ]><html class="ie9"><![endif]-->
	<head>
	<title>Server report</title>
	<META http-equiv=Content-Type content='text/html; charset=windows-1252'>
	<STYLE type=text/css>
		.container {width:80%;margin-left:10%;margin-top:30px;background-color:white}
		.panel-heading {border-bottom: 1px solid #4d627b;margin: 0 20px;height:40px}
		.panel-title {color:#4d627b;line-height: 25px;padding: 18px 0 0 0;font-size: 1.4em; text-transform: uppercase;}
		.green {color:green}
		.red {color:red}
		.title {text-align:center;padding:0; margin:10px 0; font-size: 2em; text-transform: uppercase;}
		.hostname {text-align:center;font-size:3em;padding-top:20px}		
		.date {text-align:center;font-size:0.9em;}		
		.version {text-align:center;font-size:0.9em;padding-bottom:40px}		

        * {box-sizing: border-box;}
        body {padding: 0;margin: 0; font-size: 13px;font-family: "Open Sans","Helvetica Neue",Helvetica,Arial,sans-serif; font-weight: normal;color: #7a878e ;background-color: #ecf0f5}
        p {margin: 0}
        .panel {margin-bottom: 20px}
        .panel-body {padding: 15px 20px 25px}
        table {color:#7a878e; width: 100%; max-width: 100%;border-collapse: collapse;}
        table th {border-bottom: 1px solid rgba(0,0,0,0.07);color:#4d627b;border-top:0;padding: 8px;text-align: left;}
        table td {border-top: 1px solid rgba(0,0,0,0.07);padding: 10px 8px 12px 8px;}

   	</STYLE>
</head>
<body>
<div class='container'>
'@
}
function Get-HTMLTitle {
	[CmdletBinding()]
	param ()
	return @"
	<div class='hostname'>$($env:COMPUTERNAME)</div>
	<div class='date'>generated: $(Get-Date)</div>
	<div class='version'>report version: $version</div>
"@
}
function Get-HTMLEnd {
	return @"
</div>
</body>
</html>
"@
}
function Create-HTMLSectionTitle {
	[CmdletBinding()]
	param (
		[string]$name
	)
	Process {
		return "<p class='title'>$name</p>"
	}
}
function Create-HTMLSection {
	[CmdletBinding()]
	param (
		[hashtable]$Data,
		[string]$Name
	)
	
	begin {
		$properties = @($Data.psbase.keys)
	}
	Process {
		$html = @"
        <div class="panel">
            <div class="panel-heading">
                <p class="panel-title">$name</p>
            </div>
            <div class="panel-body">
				<table>
					<thead>
						<tr>
							<th>Property</th>
							<th>Expected value</th>
							<th>Current value</th>
							<th>Result</th>
						</tr>
					</thead>
					<tbody>
"@
		foreach ($prop in $properties) {
			if ($Data.$prop.result -eq $false) {
				$class = 'red'
				$Text = 'Incorrect'
			} elseif ($Data.$prop.result -eq $true) {
				$class = 'green'
				$Text = "Correct"
			} else {
				$class = ""
				$Text = "info only"
			}
			$html += @"
						<tr>
							<td>$prop</td>
							<td>$($Data.$prop.ValueExpected)</td>
							<td>$($Data.$prop.ValueCurrent)</td>
							<td class='$class'>$text</td>
						</tr>
"@
		}
		$html += @"
					</tbody>
				</table>
			</div>
		</div>
		
"@
		return $html
		
	}
}


# CHECK START #


$OSData = get-osversiondata
$Data = @{ }

#Windows features
switch ($OSData.family) {
	'W2k8'{
		$featuresRAW = ServerManagerCmd.exe -query
		$features = @()
		foreach ($item in $featuresRAW) {
			if ($item.contains("[ ]") -or $item.contains("[X]")) {
				if ($item.contains("[ ]")) { $installed = $false } elseif ($item.contains("[X]")) { $installed = $true }
				Write-Host $item -fore cyan
				$Name = $item.substring($item.lastindexof('[') + 1, ($item.lastindexof(']') - $item.lastindexof('[') - 1))
				$features += new-object System.Management.Automation.PSObject -Property @{ 'Name' = $Name; 'InstallState' = $installed; }
			} else {
				Write-Host $item -ForegroundColor magenta
			}
		}
		Check -Section "Windows features" -Property "SNMP service" -feature -Name "SNMP-Service"
		Check -Section "Windows features" -Property "SNMP-WMI-Provider" -feature -Name "SNMP-WMI-Provider"
		Check -Section "Windows features" -Property "Telnet-client" -feature -Name "Telnet-client"
		Check -Section "Windows features" -Property "Backup" -feature -Name "Backup"
		Check -Section "Windows features" -Property "Backup-tools" -feature -Name "Backup-tools"
	}
	'W2k12'{
		$features = Get-WindowsFeature
		Check -Section "Windows features" -Property "Storage-services" -feature -Name "Storage-services"
		Check -Section "Windows features" -Property "SNMP-WMI-Provider" -feature -Name "SNMP-WMI-Provider"
		Check -Section "Windows features" -Property "Telnet-client" -feature -Name "Telnet-client"
		Check -Section "Windows features" -Property "RSAT-SNMP" -feature -Name "RSAT-SNMP"
	}
	'W2k16' {
		$features = Get-WindowsFeature
		Check -Section "Windows features" -Property "Storage-services" -feature -Name "Storage-services"
		Check -Section "Windows features" -Property "WoW64-Support" -feature -Name "WoW64-Support"
		Check -Section "Windows features" -Property "Telnet-client" -feature -Name "Telnet-client"
		Check -Section "Windows features" -Property "NET-Framework-45-Core" -feature -Name "NET-Framework-45-Core"
		Check -Section "Windows features" -Property "NET-WCF-TCP-PortSharing45" -feature -Name "NET-WCF-TCP-PortSharing45"
		Check -Section "Windows features" -Property "FS-SMB1" -feature -Name "FS-SMB1"
		Check -Section "Windows features" -Property "PowerShell" -feature -Name "PowerShell"
		Check -Section "Windows features" -Property "PowerShell-ISE" -feature -Name "PowerShell-ISE"
		Check -Section "Windows features" -Property "Windows-Server-Backup" -feature -Name "Windows-Server-Backup"
		Check -Section "Windows features" -Property "SNMP service" -feature -Name "SNMP-Service"
		Check -Section "Windows features" -Property "SNMP-WMI-Provider" -feature -Name "SNMP-WMI-Provider"
	}
}

#WSUS configuration
Check -Section "WSUS configuration" -Property "Target group enabled" -Registry -path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "TargetGroupENabled" -Value 1
Check -Section "WSUS configuration" -Property "Target group" -Registry -Path "Hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "TargetGroup" -Value $ParamWSUSGroup
Check -Section "WSUS configuration" -Property "Do Not Connect To Windows Update Internet Locations" -Registry -Path "Hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -key "DoNotConnectToWindowsUpdateInternetLocations" -Value 1
Check -Section "WSUS configuration" -Property "AUOptions" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -key "AUOptions" -Value 3
Check -Section "WSUS configuration" -Property "Detection frequency" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -key "DetectionFrequency" -value 16
Check -Section "WSUS configuration" -Property "DetectionFrequencyEnabled" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "DetectionFrequencyEnabled" -Value 1
Check -Section "WSUS configuration" -Property "NoAutoRebootWithLoggedOnUsers" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoRebootWithLoggedOnUsers" -Value 1
Check -Section "WSUS configuration" -Property "NoAutoUpdate" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoUpdate" -Value 0
Check -Section "WSUS configuration" -Property "RebootWarningTimeout" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "RebootWarningTimeout" -Value 5
Check -Section "WSUS configuration" -Property "RebootWarningTimeoutEnabled" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "RebootWarningTimeoutEnabled" -Value 1
Check -Section "WSUS configuration" -Property "ScheduledInstallDate" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "ScheduledInstallDay" -Value 0
Check -Section "WSUS configuration" -Property "ScheduledInstallTime" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "ScheduledInstallTime" -Value 3
Check -Section "WSUS configuration" -Property "Use Windows update server" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "UseWUServer" -Value 1
Check -Section "WSUS server" -Property "WUServer" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "WUServer" -Value $ParamWSUSServer
Check -Section "WSUS server" -Property "WUStatusServer" -Registry -Path "hklm:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "WUStatusServer" -Value $ParamWSUSServer

#SNMP TRAPS
Check -Section "SNMP" -Property "1" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\TrapConfiguration\HWmonitoring" -Key 1 -Value "127.0.0.1"
Check -Section "SNMP" -Property "hwmonitoring" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -Key "hwmonitoring" -Value "4"
Check -Section "SNMP" -Property "public" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -Key "public" -Value "4"
Check -Section "SNMP" -Property "win_hw-Q0l4xUT_lL" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -Key "win_hw-Q0l4xUT_lL" -Value "4"
Check -Section "SNMP" -Property "SysServices" -Registry -Path "hklm:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\RFC1156Agent" -Key "SysServices" -Value 73



#Connections
#Allow users to connect remotely by using Remote Desktop Services
Check -Section "Connections" -Property "fDenyTSConnections" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDenyTSConnections" -Value "0"
#Limit number of connections
Check -Section "Connections" -Property "MaxInstanceCount" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxInstanceCount" -Value "2"
#Set rules for remote control of Remote Desktop Services user sessions
Check -Section "Connections" -Property "Shadow" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "Shadow" -Value "3"
#Restrict Remote Desktop Services users to a single Remote Desktop Services session
Check -Section "Connections" -Property "fSingleSessionPerUser" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fSingleSessionPerUser" -Value "1"

#Device and Resource Redirection
#Allow audio and video playback redirection
Check -Section "Device and resource redirection" -Property "fDisableCam" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCam" -Value "0"
#Allow audio recording redirection
Check -Section "Device and resource redirection" -Property "fDisableAudioCapture" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableAudioCapture" -Value "0"
#Do not allow Clipboard redirection
Check -Section "Device and resource redirection" -Property "fDisableClip" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableClip" -Value "0"
#Do not allow COM port redirection
Check -Section "Device and resource redirection" -Property "fDisableCcm" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCcm" -Value "1"
#Do not allow drive redirection
Check -Section "Device and resource redirection" -Property "fDisableCdm" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCdm" -Value "1"
#Do not allow LPT port redirection
Check -Section "Device and resource redirection" -Property "fDisableLPT" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableLPT" -Value "1"
#Do not allow supported Plug and Play device redirection
Check -Section "Device and resource redirection" -Property "fDisablePNPRedir" -Registry -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisablePNPRedir" -Value "1"

#Printer Redirection
#Do not allow client printer redirection
Check -Section "Printer redirection" -Property "fDisableCpm" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fDisableCpm" -Value "1"
#Do not set default client printer to be default printer in a session
Check -Section "Printer redirection" -Property "fForceClientLptDef" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fForceClientLptDef" -Value "0"

#Remote Session Environment
#Limit maximum color depth
Check -Section "Remote session environment" -Property "ColorDepth" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "ColorDepth" -Value "3"

#Security
#Always prompt for password upon connection
Check -Section "Security" -Property "fPromptForPassword" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fPromptForPassword" -Value "1"
#Require use of specific security layer for remote (RDP) connections
Check -Section "Security" -Property "SecurityLayer" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "SecurityLayer" -Value "1"
#Require user authentication for remote connections by using Network Level Authentication
Check -Section "Security" -Property "UserAuthentication" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "UserAuthentication" -Value "0"
#Set client connection encryption level
Check -Section "Security" -Property "MinEncryptionLevel" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MinEncryptionLevel" -Value "2"

#Session Time Limits
#End session when time limits are reached
Check -Section "Session Time Limits" -Property "fResetBroken" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fResetBroken" -Value "0"
#Set time limit for active but idle Remote Desktop Services sessions
Check -Section "Session Time Limits" -Property "MaxIdleTime" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxIdleTime" -Value "3600000"
#Set time limit for active Remote Desktop Services sessions
Check -Section "Session Time Limits" -Property "MaxConnectionTime" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxConnectionTime" -Value "0"
#Set time limit for disconnected sessions
Check -Section "Session Time Limits" -Property "MaxDisconnectionTime" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "MaxDisconnectionTime" -Value "900000"

#Temporary folders
#Do not delete temp folders upon exit
Check -Section "Temporary folders" -Property "DeleteTempDirsOnExit" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "DeleteTempDirsOnExit" -Value "1"
#Do not use temporary folders per session
Check -Section "Temporary folders" -Property "PerSessionTempDir" -Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "PerSessionTempDir" -Value "1"

#Server Config file 
$ConfigFile = "C:\Windows\System32\Drivers\etc\epmf\tsi_system_info.cfg"
Check -Section "Server config tsi_system_info.cfg" -Property "File exists" -String -CurrentValue $((Test-Path $ConfigFile -PathType Leaf) -eq $true) -ExpectedValue $true
Check -Section "Server config tsi_system_info.cfg" -Property "Sger" -String -CurrentValue $(get-sger) -ExpectedValue $ParamSger
Check -Section "Server config tsi_system_info.cfg" -Property "DO number" -String -CurrentValue $(get-DOnumber) -ExpectedValue $ParamDOnumber





#McAfee AV
Check -Section "McAfee" -Property "Service status" -Service -Name "McShield" -Value "Running"

switch ($OSData.architecture) {
	"32" {
		Check -Section "McAfee" -Property "McAfee version" -Registry -Path "HKLM:\SOFTWARE\McAfee\DesktopProtection" -Key "CoreRef" -Value $ParamMcAfeeVersion
		Check -Section "McAfee" -Property "DAT file download date" -Registry -Path "HKLM:\SOFTWARE\McAfee\AVEngine" -Key "AVDatDate" -Value $paramWinauditDatDate
	}
	"64"{
		Check -Section "McAfee" -Property "McAfee version" -Registry -Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\DesktopProtection" -Key "CoreRef" -Value $ParamMcAfeeVersion
		Check -Section "McAfee" -Property "DAT file download date" -Registry -Path "HKLM:\SOFTWARE\Wow6432Node\McAfee\AVEngine" -Key "AVDatDate" -Value $paramWinauditDatDate
		
	}
}
$McAfeeEpo = Get-McAfeeEPO
Check -Section "McAfee" -Property "EPO Server" -String -CurrentValue $(($McAfeeEpo | %{ "$($_.server):$($_.port)" }) -join "<br/>") -ExpectedValue $ParamMcAfeeEPO
Check -Section "McAfee" -Property "EPO connectivity" -String -CurrentValue $(Test-Telnet -IP $McAfeeEpo[0].server -port $McAfeeEpo[0].port) -ExpectedValue $True


#Winaudit
Check -Section "WinAudit" -Property "Service status" -Service -Name "Winaudit" -Value "Running"
Check -Section "WinAudit" -Property "Winaudit version" -Registry -Path "HKLM:\SOFTWARE\T-Systems\WinAudit" -Key "Version" -Value $paramWinauditVersion
Check -Section "WinAudit" -Property "Winaudit server" -Registry -Path "HKLM:\SOFTWARE\T-Systems\WinAudit" -Key "Server" -Value $paramWinauditServer
Check -Section "WinAudit" -Property "Winaudit port" -Registry -Path "HKLM:\SOFTWARE\T-Systems\WinAudit" -Key "port" -Value $paramWinauditPort
Check -Section "WinAudit" -Property "Winaudit connectivity" -string -CurrentValue $(Test-Telnet -IP $Data.winaudit.'Winaudit server'.ValueCurrent -port $Data.winaudit.'Winaudit port'.ValueCurrent) -ExpectedValue $True

#logW
Check -Section "LogW" -Property "Service status" -Service -Name "LogW" -Value "Running"
Check -Section "LogW" -Property "LogW version" -Registry -Path "HKLM:\SOFTWARE\T-Systems\LogW" -Key "Version" -Value $paramLogWVersion
Check -Section "LogW" -Property "LogW server" -Registry -Path "HKLM:\SOFTWARE\T-Systems\LogW" -Key "LogServer_IP" -Value $paramLogWServer
Check -Section "LogW" -Property "LogW port" -Registry -Path "HKLM:\SOFTWARE\T-Systems\LogW" -Key "LogServer_Port" -Value $paramLogWPort
Check -Section "LogW" -Property "LogW connectivity" -string -CurrentValue $(Test-Telnet -IP $Data.LogW.'logw server'.ValueCurrent -port $Data.logw.'logw port'.ValueCurrent) -ExpectedValue $True

#HPSA
$HPSADetails = get-HPSAServer
Check -Section "HPSA" -Property "Service status" -Service -Name "OpswareAgent" -Value "Running"
Check -Section "HPSA" -Property "MID identifier" -String -CurrentValue $(get-HPSAMID) -ExpectedValue $ParamHPSAMID
Check -Section "HPSA" -Property "HPSA server" -String -CurrentValue $HPSADetails.server -ExpectedValue $ParamHPSAServer
Check -Section "HPSA" -Property "HPSA port" -String -CurrentValue $HPSADetails.port -ExpectedValue $ParamHPSAPort
Check -Section "HPSA" -Property "HPSA connectivity" -string -CurrentValue $(Test-Telnet -IP $HPSADetails.server -port $HPSADetails.port) -ExpectedValue $True

#HPSAM
Check -Section "HPSAM" -Property "Service status" -Service -Name "OvCtrl" -Value "Running"
Check -Section "HPSAM" -Property "Certificates status" -string -CurrentValue $(get-HPSAMCertificateStatus) -ExpectedValue "Certificate is installed."
Check -Section "HPSAM" -Property "HPSAM server" -string -CurrentValue $(Get-HPSAMServer) -ExpectedValue $ParamHPSAMServer
Check -Section "HPSAM" -Property "HPSAM connectivity" -string -CurrentValue $(Test-Telnet -IP $Data.HPSAM.'HPSAM server'.ValueCurrent -port 383) -ExpectedValue $True

#Vmware tools
Check -Section "Vmware tools" -Property "Vmware tools version" -string -CurrentValue $(Get-VmwareToolsVersion) -ExpectedValue "10.*"

#Local admininstators members
$LocalAdminsList = Get-LocalAdmins
if (get-LocalAdminRequired -required $ParamLocalAdminRequired) {
	Set-CheckResult -Section "Local administrators" -property "Required members" -ValueExpected $($ParamLocalAdminRequired -join "<br/>") -ValueCurrent $($LocalAdminsList -join "<br/>") -result $true
} else {
	Set-CheckResult -Section "Local administrators" -property "Required members" -ValueExpected $($ParamLocalAdminRequired -join "<br/>") -ValueCurrent $($LocalAdminsList -join "<br/>") -result $false
}

if (get-LocalAdminAllowed -allowed $ParamLocalAdminAllowed) {
	Set-CheckResult -Section "Local administrators" -property "Additional members" -ValueExpected $($ParamLocalAdminAllowed -join "<br/>") -ValueCurrent $($LocalAdminsList -join "<br/>") -result $true
} else {
	Set-CheckResult -Section "Local administrators" -property "Additional members" -ValueExpected $($ParamLocalAdminAllowed -join "<br/>") -ValueCurrent $($LocalAdminsList -join "<br/>") -result $false
}

Check -Section "Local administrators" -Property "Build-in admin name" -string -CurrentValue $(Get-LocalBuildInAdmin) -ExpectedValue $ParamLocalAdminName



#System
Check -Section "System" -Property "CD-ROM letter" -string -CurrentValue $(get-CDROMletter) -ExpectedValue "Z:"



#HTML
$html = Get-HTMLHeader
$html += Get-HTMLTitle
$html += Create-HTMLSectionTitle -Name "Windows features"
$html += Create-HTMLSection -Name 'Windows features' -Data $Data.'windows features'
$html += Create-HTMLSectionTitle -Name "Windows updates "
$html += Create-HTMLSection -Name 'WSUS server' -Data $Data.'wsus server'
$html += Create-HTMLSection -Name 'WSUS configuration' -Data $Data.'wsus configuration'
$html += Create-HTMLSectionTitle -Name "SNMP trap configuration"
$html += Create-HTMLSection -Name SNMP -Data $Data.SNMP
$html += Create-HTMLSectionTitle -Name "Terminal Services"
$html += Create-HTMLSection -Name "connections" -Data $Data.connections
$html += Create-HTMLSection -Name "Device and resource redirection" -Data $Data."Device and resource redirection"
$html += Create-HTMLSection -Name "Printer redirection" -Data $Data."Printer redirection"
$html += Create-HTMLSection -Name "Security" -Data $Data.Security
$html += Create-HTMLSection -Name "Session Time Limits" -Data $Data."Session Time Limits"
$html += Create-HTMLSection -Name "Temporary folders" -Data $Data."Temporary folders"
$html += Create-HTMLSectionTitle -Name "Software"
$html += Create-HTMLSection -Name "McAfee AV" -Data $Data.McAfee
$html += Create-HTMLSection -Name "WinAudit security agent" -Data $Data.Winaudit
$html += Create-HTMLSection -Name "LogW agent" -Data $Data.LogW
$html += Create-HTMLSection -Name "HPSA automation agent" -Data $Data.HPSA
$html += Create-HTMLSection -Name "HPSAM monitoring agent" -Data $Data.HPSAM
$html += Create-HTMLSection -Name "Vmware tools" -Data $Data.'Vmware tools'
$html += Create-HTMLSectionTitle -Name "User accounts"
$html += Create-HTMLSection -Name "Local Administrators" -Data $Data."Local administrators"
$html += Create-HTMLSectionTitle -Name "System"
$html += Create-HTMLSection -Name "System" -Data $Data.System


$html += Get-HTMLEnd

$html | Out-File .\HTMLMangenta.html -Encoding "ASCII"


