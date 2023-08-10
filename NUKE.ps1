# NUKE_v1.0 ➡️ https://github.com/JoshIsEpic/
# Setup + Debloat for CodeNinjas

$user = (whoami).split("\")[1]
$AdminPassword = "CodeNinjas"

$tweaks = @(

	# Require administrator privileges

	"RequireAdmin",
	"CreateRestorePoint",
	"InstallFTTProgs",

	# 3rd Party Programs
	
	"InstallChrome",
	"Install7Zip",

	# Windows Apps

	"UninstallCortana",
	"UninstallMicrosoftNews",
	"UninstallMSNWeather",
	"UninstallGetHelp",
	"UninstallMicrosoftTips",
	"UninstallMicrosoftSolitaireCollection",
	"UninstallMicrosoftStickyNotes",
	"UninstallPaint",
	"UninstallPowerAutomate",
	"UninstallStoreExperienceHost",
	"UninstallMicrosoftToDo",
	"UninstallVP9VideoExtensions",
	"UninstallWebMediaExtensions",
	"UninstallWindowsAlarmsClock",
	"UninstallWindowsCamera",
	"UninstallFeedbackHub",
	"UninstallWindowsMaps",
	"UninstallWindowsVoiceRecorder",
	"UninstallXbox",
	"UninstallXboxTCUI",
	"UninstallXboxGameBarPlugin",
	"UninstallXboxGameBar",
	"UninstallXboxIdentityProvider",
	"UninstallXboxGameSpeechWindow",
	"UninstallYourPhone",
	"UninstallGrooveMusic",
	"UninstallMoviesTV",
	"UninstallMicrosoftTeams",
	"UninstallWindowsWebExperiencePack",
	"UninstallMailCalendar",
	"UninstallMicrosoftStore",
	"UninstallWindowsTerminal",

	# Uninstall Edge
	"PreventEdgeReinstall",
	"RemoveEdge",

	# Privacy & Telemetry

	"DisableDiagTrackService",
	"MinimalDiagnosticDataLevel",
	"DisableErrorReporting",
	"NeverFeedbackFrequency",
	"DisableSigninInfo",
	"DisableLanguageListAccess",
	"DisableAdvertisingID",
	"DisableWindowsTips",
	"HideSettingsSuggestedContent",
	"DisableAppsSilentInstalling",
	"DisableWhatsNewInWindows",
	"DisableTailoredExperiences",
	"DisableBingSearch",

	# UI & Personalization
    
	"SetDesktopBackground",
	"SetLockscreenImage",
	"SetThemeDark",
	"ShowFileExtensions",

	# OneDrive

	"UninstallOneDrive",

	# System

	"DisableWin32LongPathLimit",

	# Start menu

	"HideRecentlyAddedApps",
	"ElevatedRunPowerShellShortcut",
	"PinChrome",

	#Migrate Admin
	"MigrateAdmin",

	# Restart
	"Restart"

)

# Require Admin
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

#Check if winget is installed
Function InstallFTTProgs {
	# Check if winget is installed
	if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
		Write-Output "Winget Already Installed."
	}  
	else {
		# Installing winget from the Microsoft Store
		Write-Output "Winget not found, installing it now."
		Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
		$nid = (Get-Process AppInstaller).Id
		Wait-Process -Id $nid
		Write-Output "Winget Installed"    
	}
	
}

# Create Restore Point
Function CreateRestorePoint {
	Write-Output "Creating Restore Point incase something bad happens"
	Enable-ComputerRestore -Drive "C:\"
	Checkpoint-Computer -Description "PreNUKE" -RestorePointType "MODIFY_SETTINGS"
}

# Install Google Chrome
Function InstallChrome {
	Write-Output "Installing Google Chrome"
	winget install -e -h --id Google.Chrome --force
}

# Install 7-Zip
Function Install7Zip {
	Write-Output "Installing 7-Zip"
	winget install -e -h --id 7zip.7zip --force
}

# Uninstall Cortana
Function UninstallCortana {
	Write-Output "Trying to uninstall Cortana"
	winget uninstall "Cortana"
}

# Uninstall Microsoft News
Function UninstallMicrosoftNews {
	winget uninstall "Microsoft News"
	Write-Output "Trying to uninstall Microsoft News"
}

# Uninstall MSNWeather
Function UninstallMSNWeather {
	Write-Output "Trying to uninstall MSN Weather"
	winget uninstall "MSN Weather"
}

# Uninstall Get Help
Function UninstallGetHelp {
	Write-Output "Trying to uninstall Get Help"	
	winget uninstall "Get Help"	
}

# Uninstall Microsoft Tips
Function UninstallMicrosoftTips {
	Write-Output "Trying to uninstall Microsoft Tips"	
	winget uninstall "Microsoft Tips"	
}

# Uninstall Microsoft Solitaire Collection
Function UninstallMicrosoftSolitaireCollection {
	Write-Output "Trying to uninstall Microsoft Solitaire Collection"	
	winget uninstall "Microsoft Solitaire Collection"
}

# Uninstall Microsoft Sticky Notes
Function UninstallMicrosoftStickyNotes {
	Write-Output "Trying to uninstall Microsoft Sticky Notes"	
	winget uninstall "Microsoft Sticky Notes"
}

# Uninstall Paint
Function UninstallPaint {
	Write-Output "Trying to uninstall Paint"
	winget uninstall "Paint"
}

# Uninstall Power Automate
Function UninstallPowerAutomate {
	Write-Output "Trying to uninstall Power Automate"	
	winget uninstall "Power Automate"	
}

# Uninstall Store Experience Host
Function UninstallStoreExperienceHost {
	Write-Output "Trying to uninstall Store Experience Host"
	winget uninstall "Store Experience Host"	
}

# Uninstall Microsoft To Do
Function UninstallMicrosoftToDo {
	Write-Output "Trying to uninstall Microsoft To Do"
	winget uninstall "Microsoft To Do"	
}

# Uninstall VP9 Video Extensions
Function UninstallVP9VideoExtensions {
	Write-Output "Trying to uninstall VP9 Video Extensions"	
	winget uninstall "VP9 Video Extensions"
}

# Uninstall Web Media Extensions
Function UninstallWebMediaExtensions {
	Write-Output "Trying to uninstall Web Media Extensions"
	winget uninstall "Web Media Extensions"	
}

# Uninstall Windows Alarms Clock
Function UninstallWindowsAlarmsClock {
	Write-Output "Trying to uninstall Windows Alarms & Clock"
	winget uninstall "Windows Alarms & Clock"
}

# Uninstall Windows Camera
Function UninstallWindowsCamera {
	Write-Output "Trying to uninstall Windows Camera"
	winget uninstall "Windows Camera"
}

# Uninstall Feedback Hub
Function UninstallFeedbackHub {
	Write-Output "Trying to uninstall Feedback Hub"
	winget uninstall "Feedback Hub"	
}

# Uninstall Windows Maps
Function UninstallWindowsMaps {
	Write-Output "Trying to uninstall Windows Maps"
	winget uninstall "Windows Maps"	
}

# Uninstall Windows Voice Recorder
Function UninstallWindowsVoiceRecorder {
	Write-Output "Trying to uninstall Windows Voice Recorder"	
	winget uninstall "Windows Voice Recorder"	
}

# Uninstall Xbox
Function UninstallXbox {
	Write-Output "Trying to uninstall Xbox"
	winget uninstall "Xbox"	
}

# Uninstall Xbox TCUI
Function UninstallXboxTCUI {
	Write-Output "Trying to uninstall Xbox TCUI"
	winget uninstall "Xbox TCUI"	
}

# Uninstall Xbox Game Bar Plugin
Function UninstallXboxGameBarPlugin {
	Write-Output "Trying to uninstall Xbox Game Bar Plugin"
	winget uninstall "Xbox Game Bar Plugin"
}

# Uninstall Xbox Game Bar
Function UninstallXboxGameBar {
	Write-Output "Trying to uninstall Xbox Game Bar"
	winget uninstall "Xbox Game Bar"	
}

# Uninstall Xbox Identity Provider
Function UninstallXboxIdentityProvider {
	Write-Output "Trying to uninstall Xbox Identity Provider"
	winget uninstall "Xbox Identity Provider"
}

# Uninstall Xbox Game Speech Window
Function UninstallXboxGameSpeechWindow {
	Write-Output "Trying to uninstall Xbox Game Speech Window"
	winget uninstall "Xbox Game Speech Window"	
}

# Uninstall Your Phone
Function UninstallYourPhone {
	Write-Output "Trying to uninstall Your Phone"
	winget uninstall "Your Phone"
}

# Uninstall Groove Music
Function UninstallGrooveMusic {
	Write-Output "Trying to uninstall Groove Music"
	winget uninstall "Groove Music"	
}

# Uninstall Movies & TV
Function UninstallMoviesTV {
	Write-Output "Trying to uninstall Movies & TV"
	winget uninstall "Movies & TV"	
}

# Uninstall Microsoft Teams
Function UninstallMicrosoftTeams {
	Write-Output "Trying to uninstall Microsoft Teams"	
	winget uninstall "Microsoft Teams"
}

# Uninstall Windows Web Experience Pack
Function UninstallWindowsWebExperiencePack {
	Write-Output "Trying to uninstall Windows Web Experience Pack"	
	winget uninstall "Windows Web Experience Pack"	
}

# Uninstall Mail and Calendar
Function UninstallMailCalendar {
	Write-Output "Trying to uninstall Mail and Calendar"
	winget uninstall "Mail and Calendar"	
}

# Uninstall Microsoft Store
Function UninstallMicrosoftStore {
	Write-Output "Trying to uninstall Microsoft Store"
	winget uninstall "Microsoft Store"
}

# Uninstall Windows Terminal
Function UninstallWindowsTerminal {
	Write-Output "Trying to uninstall Windows Terminal"
	winget uninstall "Windows Terminal"
}

# Prevent Edge From Reinstalling
Function PreventEdgeReinstall {
	Write-Output "Trying to preventing Edge from reinstalling ..."
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -PropertyType DWord	
}

# Uninstall Edge
Function RemoveEdge {
	Write-Output "Trying to remove Edge from Windows ..."
	taskkill /f /im msedge.exe
	Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft\Edge" -Force -Recurse
	Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft\EdgeCore" -Force -Recurse
	Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft\EdgeUpdate" -Force -Recurse
	Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft\Temp" -Force -Recurse
}

# Disable the Connected User Experiences and Telemetry (DiagTrack) service, and block connection for the Unified Telemetry Client Outbound Traffic
Function DisableDiagTrackService {
	Write-Output "Disabling DiagTrack Service ..."
	# Connected User Experiences and Telemetry
	Get-Service -Name DiagTrack | Stop-Service -Force
	Get-Service -Name DiagTrack | Set-Service -StartupType Disabled

	# Block connection for the Unified Telemetry Client Outbound Traffic
	Get-NetFirewallRule -Group DiagTrack | Set-NetFirewallRule -Enabled False -Action Block
}

# Set the diagnostic data collection to minimum
Function MinimalDiagnosticDataLevel {
	Write-Output "Setting Minimal Diagnostic Data Level ..."
	if (Get-WindowsEdition -Online | Where-Object -FilterScript { $_.Edition -like "Enterprise*" -or $_.Edition -eq "Education" }) {
		# Diagnostic data off
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
	}
	else {
		# Send required diagnostic data
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 1 -Force
	}
	if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack)) {
		New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name MaxTelemetryAllowed -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack -Name ShowedToastAtLevel -PropertyType DWord -Value 1 -Force
}

# Turn off Windows Error Reporting
Function DisableErrorReporting {
	Write-Output "Disabling Error Reporting ..."
	if ((Get-WindowsEdition -Online).Edition -notmatch "Core") {
		Get-ScheduledTask -TaskName QueueReporting | Disable-ScheduledTask
		New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force
	}

	Get-Service -Name WerSvc | Stop-Service -Force
	Get-Service -Name WerSvc | Set-Service -StartupType Disabled
}

# Change the feedback frequency to "Never"
Function NeverFeedbackFrequency {
	Write-Output "Setting Never Feedback Frequency ..."
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force
}

# Do not use sign-in info to automatically finish setting up device after an update
Function DisableSigninInfo {
	Write-Output "Disabling Signin Info ..."
	$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript { $_.Name -eq $env:USERNAME }).SID
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force	
}

# Do not let websites show me locally relevant content by accessing my language list
Function DisableLanguageListAccess {
	Write-Output "Disabling Language List Access ..."
	New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force
}

# Do not let apps show me personalized ads by using my advertising ID
Function DisableAdvertisingID {
	Write-Output "Disabling Advertising ID ..."
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force		
}

# Do not get tip and suggestions when I use Windows
Function DisableWindowsTips {
	Write-Output "Disabling Windows Tips ..."
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 0 -Force
}

# Hide from me suggested content in the Settings app
Function HideSettingsSuggestedContent {
	Write-Output "Hiding Settings Suggested Content ..."
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force
}

# Turn off automatic installing suggested apps
Function DisableAppsSilentInstalling {
	Write-Output "Disabling Apps Silent Installing ..."
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force		
}

# Disable suggestions on how I can set up my device
Function DisableWhatsNewInWindows {
	Write-Output "Disabling Whats New In Windows ..."
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force
}

# Do not let Microsoft use your diagnostic data for personalized tips, ads, and recommendations
Function DisableTailoredExperiences {
	Write-Output "Disabling Tailored Experiences ..."
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force		
}

# Disable Bing search in the Start Menu
Function DisableBingSearch {
	Write-Output "Disabling Bing Search ..."
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -PropertyType DWord -Value 1 -Force		
}

# Set Desktop Background
Function SetDesktopBackground {
	Write-Output "Trying to set desktop background ..."

	# Download image
	Invoke-WebRequest -o "C:\Users\$user\Pictures\background.png" "https://cdn.discordapp.com/attachments/1126640370692919327/1126640547491237988/Shuriken_black.png"

	# Set background image
	Set-ItemProperty -path "HKCU:Control Panel\Desktop" -Name WallPaper -Value "C:\Users\$user\Pictures\background.png" -Type String -Force
}

function SetLockscreenImage {
	Write-Output "Trying to set lockscreen image"

	#Download image
	Invoke-WebRequest -o "C:\Users\$user\Pictures\lockscreen.png" "https://cdn.discordapp.com/attachments/1126640370692919327/1126640547109535784/eyes.png"

	#Add Registry String
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name SetLockscreenImage -Value "C:\Users\$user\Pictures\lockscreen.png" -Type String -Force

}
# Set Theme Dark
Function SetThemeDark {
	Write-Output "Trying to set theme to dark ..."

	# Set Theme to Dark Mode
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0 -Type DWord -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Value 0 -Type DWord -Force
}

function ShowFileExtensions {
	Write-Output "Trying to enforce show file extensions ..."

	#Changes policy to not hide file extensions
	Set-Itemproperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -value 0
}

# Uninstall OneDrive
Function UninstallOneDrive {
	Write-Output "Uninstalling OneDrive ..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}

# Disable the Windows 260 character path limit
Function DisableWin32LongPathLimit {
	Write-Output "Disabling Win32 Long Path Limit ..."
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force
}

# Hide recently added apps in the Start menu
Function HideRecentlyAddedApps {
	Write-Output "Hiding Recently Added Apps ..."
	if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer)) {
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
	}
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -PropertyType DWord -Value 1 -Force
}

# Run the Windows PowerShell shortcut from the Start menu as Administrator
Function ElevatedRunPowerShellShortcut {
	Write-Output "Setting Elevated Run PowerShell Shortcut ..."
	[byte[]]$bytes = Get-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" -Encoding Byte -Raw
	$bytes[0x15] = $bytes[0x15] -bor 0x20
	Set-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" -Value $bytes -Encoding Byte -Force
}

# Pin Chrome to task bar
Function PinChrome {
	"Trying to pin Chrome ..."
	Invoke-WebRequest -o "syspin.exe" "http://www.technosys.net/download.aspx?file=syspin.exe"

	<#
    Syspin Documentation from technosys.net

    Usage :
    syspin ["file"] #### or syspin ["file"] "commandstring"
    5386  : Pin to taskbar
    5387  : Unpin from taskbar
    51201 : Pin to start
    51394 : Unpin from start

    Samples :
    syspin "%PROGRAMFILES%\Internet Explorer.exe" 5386
    syspin "C:\Windows\notepad.exe" "Pin to taskbar"
    syspin "%WINDER%\System32\calc.exe" "Unpin from taskbar"
    syspin "%WINDER%\System32\calc.exe" 51201

    Note :
    You cannot pin any metro app or batch Files
    #>

	.\syspin.exe "C:\Program Files\Google\Chrome\Application\chrome.exe" 5386
	Remove-Item syspin.exe
}

function MigrateAdmin {
	Write-Output "Migrating Admin account ..."
	net user "Admin" $AdminPassword /ADD
	net localgroup Administrators "Admin" /ADD
	net localgroup Administrators "$user" /DELETE
}

# Restart
Function Restart {
	Start-Sleep(5)
	shutdown /r /t 0
}

# Call tweak functions
$tweaks | ForEach-Object { Invoke-Expression $_ }
Read-Host -Prompt "Press Enter to exit"