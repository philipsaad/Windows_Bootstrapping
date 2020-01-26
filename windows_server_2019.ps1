#Set this to what you want the Hostname of the server to be
$Hostname = ""

#Set this to automatically install and activate Windows
$WindowsProductKey = ""

#Wait for the user to provide input
Function WaitForKey {
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

#Restart the computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}

#check to see if we are running in admin mode
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Write-Error -Message "`nThe current Windows PowerShell session is not running as Administrator. Start Windows PowerShell by using the Run as Administrator option, and then try running the script again." -Category PermissionDenied
	WaitForKey
	Exit
}
	
#Activate Windows
If ($WindowsProductKey -ne $null) {
	@(Get-WmiObject -Query 'SELECT * FROM SoftwareLicensingService').ForEach({
		$_.InstallProductKey($WindowsProductKey) | Out-Null
		$_.RefreshLicenseStatus() | Out-Null
	})
	Write-Host "Activated Windows"
}


#Install Chocolatey and install all of the software we want
Invoke-RestMethod -UseBasicParsing -Uri https://chocolatey.org/install.ps1 | Invoke-Expression | Out-Null
Write-Host "Installed Chocolatey"

choco upgrade chocolatey notepadplusplus --confirm --no-progress
Write-Host "Installed applications"

#Remove Desktop background image and set to solid color: rgb(42,42,42) #2A2A2A
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value ''; Set-ItemProperty 'HKCU:\Control Panel\Colors' -Name Background -Value '42 42 42 '; Stop-Process -Name 'Explorer' -Force
Write-Host "Updated Background"

#Disable Server Manager upon start up
If ((Get-ScheduledTask -TaskName ServerManager).State -ne "Disabled") {
	Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
	Write-Host "Server Manager removed from startup"
}

Update-Help -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Updated help for all PowerShell modules"

#Uninstall Internet Explorer
If ((Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE").State -eq "Enabled") {
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Write-Output "Uninstalled Internet Explorer"
}

#Uninstall Windows Defender
If ((Get-WindowsFeature -Name Windows-Defender).InstallState -eq "Installed") {
	Uninstall-WindowsFeature -Name Windows-Defender
	Write-Output "Uninstalled Windows Defender"
}

#Set current network profile to private
If ((Get-NetConnectionProfile).NetworkCategory -ne 'Private') {
	Set-NetConnectionProfile -NetworkCategory Private
	Write-Output "Current network profile set to private"
}

#Disable Firewall for only the private network profile
If ((Get-NetFirewallProfile -Profile Private).Enabled -eq $true) {
	Set-NetFirewallProfile -Profile Private -Enabled False
	Write-Output "Firewall Disabled"
}

#Enabling Remote Desktop
If ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) {
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Write-Host "Remote Desktop enabled"
}

#Install Microsoft Edge Chromium
$ProgressPreference = 'SilentlyContinue'
$EdgeBuildVersion = ((Invoke-WebRequest https://msedge.api.cdp.microsoft.com/api/v1/contents/Browser/namespaces/Default/names/msedge-stable-win-x64/versions/latest?action=select -Method POST -ContentType 'application/json' -Body '{"targetingAttributes": {}}' | ConvertFrom-Json).ContentID.Version)
Invoke-RestMethod -Uri (Invoke-WebRequest "https://www.microsoft.com/en-us/edge/business/Product/GetArtifacturl?productname=Stable%20$EdgeBuildVersion&osname=Windows&osversion=x64" -UseBasicParsing).Content -OutFile MicrosoftEdgeEnterpriseX64.msi
Start-Process -FilePath msiexec -ArgumentList /i, MicrosoftEdgeEnterpriseX64.msi, /qn, /norestart -Wait
Remove-Item -Path '.\MicrosoftEdgeEnterpriseX64.msi' -Force

#Remove all shortcuts from the desktop
Remove-Item "$env:PUBLIC\Desktop" -Include *.lnk -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Desktop" -Include *.lnk -Force -Recurse -ErrorAction SilentlyContinue
Write-Host "Cleaned up Desktop Icons"

#Rename computer
If ($Hostname -ne $null) {
	If ([Environment]::MachineName -ne $Hostname) {
		Rename-Computer -NewName $Hostname -Force | Out-Null
		Write-Host "Renamed computer"
	}
}

#Wait for the user to provide input
WaitForKey

#Restart the computer
Restart