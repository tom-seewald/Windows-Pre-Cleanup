# Power Settings

	Write-Host "Adjusting power configuration for maximum performance..."	

	Write-Host "`n"

	# High Performance
		powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

	# Disable timeouts while plugged in
		powercfg /change /monitor-timeout-ac 0
		powercfg /change /disk-timeout-ac 0
		powercfg /change /standby-timeout-ac 0
		powercfg /change /hibernate-timeout-ac 0

# Detect Windows version and apply appropriate settings

	$majorver=[System.Environment]::OSVersion.Version.Major
	$minorver=[System.Environment]::OSVersion.Version.Minor

	$ver=$(echo $majorver"."$minorver)

	If ($ver -eq "10.0")
	     {  Write-Host "Windows 10 detected"
		Write-Host "`n"
		Write-Host "Applying settings..."

			# Windows 10

				# ThemeTool.exe needs .NET 3.5 which is not installed by default on Windows 10

				# Check if .NET 3.5 is installed
		
				$35status = Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -eq "NetFx3"} | ForEach-Object { $_.State }

				# If .NET 3.5 is not installed, install it

					if ( $35status -ne "Enabled" ) { Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName NetFx3 | Out-Null }

				# Set to the Default Theme using ThemeTool.exe
					Start-Process "$env:p2eincfilepath\ThemeTool.exe" -ArgumentList "changetheme $env:windir\Resources\Themes\aero.theme"
					sleep 5

				# Set Taskbar to the bottom of the screen and disable auto-hide
					Start-Process regedit -ArgumentList "/s","$env:p2eincfilepath\Taskbar10.reg"
			
				# Set default wallpaper
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundHistoryPath0" -Value "$env:windir\Web\Wallpaper\Windows\img0.jpg"
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value "$env:windir\Web\Wallpaper\Windows\img0.jpg"

				# ON  - Set wallpaper type to a static image
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundType" -Value "0"

				# ON  - Automatically pick an accent color based on wallpaper
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoColorization" -Value "1"

				# ON  - Enable taskbar transparency
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value "1"

				# OFF - Show color on Start, Taskbar and action center
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -Value "0"

				# OFF - Show color on Title Bar
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Value "0"

				# ON  - Light mode
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value "1"

				# ON  - Lock the Taskbar
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSizeMove" -Value "0"

				# OFF - Use small Taskbar buttons
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value "0"

				# ON  - Desktop Mode (0=Tablet, 1=Desktop, 2=Auto-detect)
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "SignInMode" -Value "1"

				# ON  - Ask before switching between Tablet or Desktop mode
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "ConvertibleSlateModePromptPreference" -Value "1"
	
				# Set Visual Effects to "Let Windows choose what is best for my computer"
					Start-Process "$env:p2eincfilepath\appearance.exe"
				
				# ON - Font smoothing
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2"

				# OFF - Hide inactive tray icons
					New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value "0" -PropertyType DWORD -Force | Out-Null
		
				# ON  - Powershell on quickstart menu
					Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value "0"

				# Restart Explorer
					Stop-Process -ProcessName Explorer

				# ON - Windows Update
					sc.exe config wuauserv start= "delayed-auto" | Out-Null
					Restart-Service -Force wuauserv			

				# Reset Winsock Catalog
					netsh winsock reset | Out-Null

				# ON - Windows Firewall and default settings
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-Service MpsSvc -StartupType "Automatic"

				# Restart the Firewall for changes to go into effect

					Restart-Service -Force MpsSvc

				Write-Host "`n"
				Write-Host "Settings have been applied!"
				Write-Host "`n"
		}
	

	If ($ver -eq "6.3")
	     {  Write-Host "Windows 8.1 detected"
		Write-Host "`n"
		Write-Host "Applying settings..."

			# Windows 8.1

				# ThemeTool.exe needs .NET 3.5 which is not installed by default on 8.1
				# Check if .NET 3.5 is installed
		
				$35status = Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -eq "NetFx3"} | ForEach-Object { $_.State }

				# If .NET 3.5 is not installed, install it

					if ( $35status -ne "Enabled" ) { Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName NetFx3 | Out-Null }

				# Set to the Default Theme using ThemeTool.exe
					Start-Process "$env:p2eincfilepath\ThemeTool.exe" -ArgumentList "changetheme $env:windir\Resources\Themes\aero.theme"
					sleep 5

				# ON  - Automatically pick an accent color based on wallpaper
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoColorization" -Value "1"

		 		# Set default wallpaper
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value "$env:windir\Web\Wallpaper\Windows\img0.jpg"

				# Set Visual Effects to "Let Windows choose what is best for my computer"
					Start-Process "$env:p2eincfilepath\appearance.exe"
				
				# ON - Font smoothing
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2"

				# Set Taskbar to the bottom of the screen and disable auto-hide
					Start-Process regedit -ArgumentList "/s","$env:p2eincfilepath\Taskbar.reg"
	
				# ON - Lock the Taskbar
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSizeMove" -Value "0"

				# OFF - Use small Taskbar buttons
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value "0"
			
				# OFF - Hide inactive tray icons
					New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value "0" -PropertyType DWORD -Force | Out-Null

				# Set default start menu color
					Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationColor" -Value  ([byte[]](0xc0,0x55,0xc9,0xed))

				# ON  - Powershell on quickstart menu
					Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value "0"

				# ON - Go to Desktop instead of Startpage at logon
					Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name "OpenAtLogon" -Value "0"

				# Restart Explorer
					Stop-Process -ProcessName Explorer

				# ON - Windows Update and enable recommended settings
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "IncludeRecommendedUpdates" -Value "1"
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "ElevateNonAdmins" -Value "1"
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value "4"
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "CachedAUOptions" -Value "4"

					sc.exe config wuauserv start= "delayed-auto" | Out-Null

					Restart-Service -Force wuauserv			

				# Reset Winsock Catalog
					netsh winsock reset | Out-Null

				# ON - Windows Firewall and default settings
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-Service MpsSvc -StartupType "Automatic"

				# Restart the Firewall for changes to go into effect

					Restart-Service -Force MpsSvc

				Write-Host "`n"
				Write-Host "Settings have been applied!"
				Write-Host "`n"
		}

	If ($ver -eq "6.2")
	     {  Write-Host "Windows 8 detected - you ***MUST*** upgrade to 8.1 - Windows 8 is not supported and no longer receives security updates!" 
		Write-Host "`n"
		Write-Host "Aborting script!"
		exit 
	     }

	If ($ver -eq "6.1")
	     {  Write-Host "Windows 7 detected"
		Write-Host "`n"
		Write-Host "Applying settings..."

			# Windows 7

				# Set to the Default Theme using ThemeTool.exe
					Start-Process "$env:p2eincfilepath\ThemeTool.exe" -ArgumentList "changetheme $env:SystemRoot\Resources\Themes\aero.theme"
					sleep 5

				# ON - Set wallpaper type to a static image
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundType" -Value "0"

				# Set Visual Effects to "Let Windows choose what is best for my computer"
					Start-Process "$env:p2eincfilepath\appearance.exe"
				
				# ON - Font smoothing
					Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2"

				# Set Taskbar to the bottom of the screen and disable auto-hide
					regedit /s "$env:p2eincfilepath\Taskbar.reg"

				# OFF - Use small Taskbar buttons
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value "0"
	
				# ON - Lock the Taskbar
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSizeMove" -Value "0"
			
				# OFF - Hide inactive tray icons
					New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value "0" -PropertyType DWORD -Force | Out-Null

				# Restart Explorer
					Stop-Process -ProcessName Explorer

				# ON - Windows Update and enable recommended settings
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "IncludeRecommendedUpdates" -Value "1"
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "ElevateNonAdmins" -Value "1"
					Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value "4"

					sc.exe config wuauserv start= "delayed-auto" | Out-Null

					Restart-Service -Force wuauserv			

				# Reset Winsock Catalog
					netsh winsock reset | Out-Null

				# ON - Windows Firewall and default settings
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "EnableFirewall" -Value "1"
					Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DisableNotifications" -Value "0"
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DefaultInboundAction" -Value "1" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DefaultOutboundAction" -Value "0" -PropertyType DWORD -Force | Out-Null
					New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "DisableNotifications" -Value "1" -PropertyType DWORD -Force | Out-Null

					Set-Service MpsSvc -StartupType "Automatic"

				# Restart the Firewall for changes to go into effect

					Restart-Service -Force MpsSvc

				Write-Host "`n"
				Write-Host "Settings have been applied!"
				Write-Host "`n"
		}



# Prompt for reboot, required to apply all settings

$reboot_prompt = Read-Host "Reboot computer for changes to go into effect? (Yes/No)"

	while("Yes","y","No","n" -notcontains $reboot_prompt)

		{

      			$reboot_prompt = Read-Host "(Yes/No)"

		}

	If ($reboot_prompt -eq "Yes" -or $reboot_prompt -eq "y") {
		Write-Host "Rebooting!"
		shutdown -r -t 1
		exit}
	If ($reboot_prompt -eq "No" -or $reboot_prompt -eq "n") { 
		Write-Host "Script complete!"
		exit}

exit
