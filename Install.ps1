# Install_v1.0 ➡️ https://github.com/JoshIsEpic/
# Installs software used at CodeNinjas

$ID = "your-center-id-here" #example: cn-tx-new-braunfels

$run = @(

    #Check for winget
    "RequireAdmin",
    "InstallFTTProgs",

    #Games
    "MinecraftEDU",
    "MCreator",
    "Roblox",

    #Tools
    "Blender",
    "Python",
    "SpikePrime",

    #Links
    "LnkDojo",
    "LnkImpact"
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

#Install Minecraft EDU
function MinecraftEDU {
    Write-Output "Trying to install Minecraft EDU..."
    winget install -e -h --id="9NBLGGH4R2R6" --source="msstore" --force
}

#Install MCreator
function MCreator {
    Write-Output "Trying to install MCreator..."
    winget install -e -h --id="MCreator.MCreator" --source="winget" --force
}

#Install Roblox
function Roblox {
    Write-Output "Trying to Install Roblox..."
    Invoke-WebRequest "https://setup.rbxcdn.com/RobloxPlayerLauncher.exe" -o "RobloxInstaller.exe"
    Start-Process "RobloxInstaller.exe"
}

#Install Blender
function Blender {
    Write-Output "Trying to install Blender..."
    winget install -e -h --id="BlenderFoundation.Blender.LTS" --source="winget" --force
}

#Install Python 3.8
function Python {
    winget install -e -h --id="Python.Python.3.8" --source="winget" --force
}

#Install Lego Spike PPIME
function SpikePrime {
    winget install -e -h --id="9NG9WXQ85LZM" --source="msstore" --force
}

#Link Dojo to Desktop
function LnkDojo {
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\$env:USERNAME\Desktop\Dojo.lnk")
    $Shortcut.TargetPath = "https://dojo.code.ninja/welcome/$ID/"
    Invoke-WebRequest "https://cdn.discordapp.com/attachments/1126640370692919327/1139283438281687171/dojo.ico" -o "C:\Users\$env:USERNAME\Documents\dojo.ico"
    $shortcut.IconLocation = "C:\Users\$env:USERNAME\Documents\dojo.ico"
    $Shortcut.Save()
}

#Link Impact to Desktop
function LnkImpact {
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\$env:USERNAME\Desktop\Impact.lnk")
    $Shortcut.TargetPath = "https://impact.codeninjas.com/login/"
    Invoke-WebRequest "https://cdn.discordapp.com/attachments/1126640370692919327/1139283438600466624/impact.ico" -o "C:\Users\$env:USERNAME\Documents\impact.ico"
    $shortcut.IconLocation = "C:\Users\$env:USERNAME\Documents\impact.ico"
    $Shortcut.Save()
}

$run | ForEach-Object { Invoke-Expression $_ }
Read-Host -Prompt "Press Enter to exit"