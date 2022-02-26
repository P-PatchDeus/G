@echo off
title WinBooster
color a
cls 
@echo off
title Ultra FPS Guclendirici (Yapimci: by Wortex)
color a
set/p a=Fps'ini boostlamama izin vermek için enter bas
wmic process where name="javaw.exe" CALL setpriority "high priority"
wmic process where name="svchost.exe" CALL setpriority "above normal"
wmic process where name="firefox.exe" CALL setpriority "above normal"
netsh interface ipv4 set interface "Ethernet" metric=9999
netsh interface ipv6 set interface "Ethernet" metric=9999
netsh Interface ip add dns "Wi-Fi" index=1 1.1.1.1
netsh Interface ip add dns "Wi-Fi" index=2 1.0.0.1
netsh Interface ip add dns "Ethernet" index=1 1.1.1.1
netsh Interface ip add dns "Ethernet" index=2 1.0.0.1
wmic process where ProcessId=%pid% CALL setpriority "idle"
wmic process where name="mqsvc.exe" CALL setpriority "high priority"
wmic process where name="mqtgsvc.exe" CALL setpriority "high priority"
wmic process where name="Hasten.exe" CALL setpriority "realtime"
ipconfig /flushdns
)
sc stop Application Layer Gateway Service
sc config Application Layer Gateway Service start=disabled
sc stop Bluetooth Handsfree Service
sc config Bluetooth Handsfree Service start=disabled
sc stop Bluetooth Support Service
sc config Bluetooth Support Service start=disabled
sc stop BranchCache
sc config BranchCache start=disabled
sc stop Certificate Propagation
sc config Certificate Propagation start=disabled
sc stop Credential Manager
sc config Credential Manager start=disabled
sc stop Diagnostics Tracking Service
sc config Diagnostics Tracking Service start=disabled
sc stop Distributed Link Tracking Client 
sc config Distributed Link Tracking Client start=disabled
sc stop Family Safety 
sc config Family Safety start=disabled
sc stop Homegroup Listener
sc config Homegroup Listener start=disabled
sc stop Homegroup Provider
sc config Homegroup Provider start=disabled
sc stop Human Interface Device Service
sc config Human Interface Device Service start=disabled
sc stop Hyper-V
sc config Hyper-V start=disabled
sc stop Internet Connection Sharing
sc config Internet Connection Sharing start=disabled
sc stop Internet Explorer ETW Collector Service
sc config Internet Explorer ETW Collector Service start=disabled
sc stop IP Helper
sc config IP Helper start=disabled
sc stop Liveupdate
sc config Liveupdate start=disabled
sc stop Microsoft iSCSI Initiator Service
sc config Microsoft iSCSI Initiator Service start=disabled
sc stop Microsoft Keyboard Filter
sc config Microsoft Keyboard Filter start=disabled
sc stop Net.Tcp Port Sharing Service
sc config Net.Tcp Port Sharing Service start=disabled
sc stop Netlogon
sc config Netlogon start=disabled
sc stop Network Access Protection Agent
sc config Network Access Protection Agent start=disabled
sc stop Offline Files
sc config Offline Files start=disabled
sc stop Peer Name Resolution Protocol
sc config Peer Name Resolution Protocol start=disabled
sc stop Peer Networking Identity Manager 
sc config Peer Networking Identity Manager start=disabled
sc stop SNMP Trap
sc config SNMP Trap start=disabled
sc stop SSDP Discovery
sc config SSDP Discovery start=disabled
sc stop Storage Service
sc config Storage Service start=disabled
sc stop Windows Biometric Service
sc config Windows Biometric Service start=disabled
sc stop Workstation
sc config Workstation start=disabled
sc stop WMI Performance Adapter
sc config WMI Performance Adapter start=disabled
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\Skype.com" /v "https" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\AeLookupSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\AudioSrv" /v "DependOnService" /t REG_MULTI_SZ /d "AudioEndpointBuilder\0RpcSs" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\CertPropSvc" /v "start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\CscService" /v "start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\lmhosts" /v "start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\iphlpsvc" /v "start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\MMCSS" /v "start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\msahci" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\p2pimsvc" /v "start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\PcaSvc" /v "start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platforms" /v "NoGenTicket" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
cls
color 2
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
del c:\WIN386.SWP
cls
/s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\history
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
deltree /y c:\windows\spool\printers
del c:\WIN386.SWP
