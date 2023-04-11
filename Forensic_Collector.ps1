#Requires -RunAsAdministrator
<#
Description: PowerShell script to assist with the collection of forensic artifacts. 

Author: Mike Dunn

Creation Date: 02/23/2023

Version: 1

NOTE: Requires a Resource Folder that contains an Offline Velociraptor executable, a copy of the KAPE folder, a copy of Chainsaw folder, and a copy of LOKI folder.
#>

Write-Host "Checking Directory"
$file = Get-ChildItem -Filter "Forensic_Collector.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1
if($file){
        Write-Host "You are in the proper Directory"
        Write-Host "Continuing to Menu"
}else{
        Write-Host "Searching for proper Directory"
        $file = Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Recurse -Exclude C:\Windows\System32 -Filter "Forensic_Collector.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1}
        Set-Location -Path $file.Directory.FullName -ErrorAction SilentlyContinue
        Write-Host "Directory has been set, Continuing to Menu"
        Start-Sleep -Seconds 2
}

$hostname = hostname
if(Test-Path ".\Forensic_Results_$hostname"){
    Write-Host "File Already Exists"
}else{
    New-Item -Path . -Name "Forensic_Results_$hostname" -ItemType Directory
}

$sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$netInfo = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -ne $null}
$userInfo = Get-CimInstance -ClassName Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true}

$outputFile = "system_info.txt"

Set-Content -Path $outputFile -Value "System Information:`n`n"
Add-Content -Path $outputFile -Value "Model: $($sysInfo.Model)"
Add-Content -Path $outputFile -Value "Manufacturer: $($sysInfo.Manufacturer)"
Add-Content -Path $outputFile -Value "Operating System: $($osInfo.Caption)"
Add-Content -Path $outputFile -Value "Version: $($osInfo.Version)"
Add-Content -Path $outputFile -Value ""

Add-Content -Path $outputFile -Value "Network Information:`n`n"
foreach ($netAdapter in $netInfo) {
    Add-Content -Path $outputFile -Value "Adapter Name: $($netAdapter.Description)"
    Add-Content -Path $outputFile -Value "IP Address: $($netAdapter.IPAddress[0])"
    Add-Content -Path $outputFile -Value "Subnet Mask: $($netAdapter.IPSubnet[0])"
    Add-Content -Path $outputFile -Value "Default Gateway: $($netAdapter.DefaultIPGateway)"
    Add-Content -Path $outputFile -Value "MAC Address: $($netAdapter.MACAddress)"
    Add-Content -Path $outputFile -Value "DNS Servers: $($netAdapter.DNSServerSearchOrder -join ', ')"
    Add-Content -Path $outputFile -Value ""
}

Add-Content -Path $outputFile -Value "User Account Information:`n`n"
foreach ($user in $userInfo) {
    Add-Content -Path $outputFile -Value "Username: $($user.Name)"
    Add-Content -Path $outputFile -Value "Full Name: $($user.FullName)"
    Add-Content -Path $outputFile -Value "Enabled: $($user.Disabled -ne $true)"

    $sid = $user.SID
    $userObject = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $groupList = $userObject.Translate([System.Security.Principal.NTAccount]).Value
    Add-Content -Path $outputFile -Value "Group Memberships: $($groupList -join ', ')"

    try {
        $acl = Get-Acl -Path "C:\Users\$($user.Name)\" -ErrorAction SilentlyContinue
        $permissionList = $acl.AccessToString
        Add-Content -Path $outputFile -Value "Permissions: $($permissionList -join ', ')"
    }
    catch {
        Add-Content -Path $outputFile -Value "Permissions: Unable to retrieve"
    }

    Add-Content -Path $outputFile -Value ""
}

Move-Item -Path .\$outputFile -Destination .\Forensic_Results_$hostname -ErrorAction SilentlyContinue

Function Triage{
    Invoke-Expression .\Resources\Triage.exe #Offline Velociraptor Collector was renamed to Triage.exe
    Move-Item -Path .\*.zip -Destination ".\Forensic_Results_$hostname\Triage_$hostname.zip"
    Remove-Item -Path ".\Collector*.log"
    Clear-Host
}

Function Logs{
    Write-Host "Copying Windows Log Files, Please wait..."
    New-Item -Path ".\Forensic_Results_$hostname" -ItemType Directory -Name Logs
    Copy-Item -Path C:\Windows\System32\winevt\Logs\*.* -Destination ".\Forensic_Results_$hostname\Logs" -Recurse
}

Function Chainsaw{
    Invoke-Expression .\Resources\Chainsaw\chainsaw.bat #a batch file was created to assist with the CMD execution of the forensic tool
        while(Get-Process -Name chainsaw -ErrorAction SilentlyContinue){
            Start-Sleep -Seconds 5
        }
    Move-Item -Path .\*.csv -Destination ".\Forensic_Results_$hostname"
    Clear-Host
}

Function Kape{
    Invoke-Expression .\Resources\KAPE\Kape.bat #a batch file was created to assist with the CMD execition of the forensic tool
        while(Get-Process -Name kape){
            Start-Sleep -Seconds 5
        }
    Move-Item -Path .\*.vhd -Destination ".\Forensic_Results_$hostname\Kape_Evidence_$hostname.vhd"
    Remove-Item -Path ".\*.txt"
    Clear-Host
}

Function Compress{
    Compress-Archive -Path ".\Forensic_Results_$hostname" -DestinationPath ".\UPLOAD_THIS_$hostname.zip"
    Remove-Item -Path ".\Forensic_Results_$hostname" -Recurse -Force
    Clear-Host
}

Function Loki {
    Invoke-Expression .\Resources\Loki\Loki.bat #a batch file was created to assist with the CMD execution of the forensic tool
        while(Get-Process -Name loki){
            Start-Sleep -Seconds 5
        }
    Move-Item -Path .\*.log -Destination ".\Forensic_Results_WIN-UKCDAFSJ3F7\Loki_$hostname.log"
    Clear-Host
}

Function Main{
Write-Host `t "___________                                 __" -ForegroundColor Yellow              
Write-Host `t "\_   _____/__________   ____   ____   _____|__| ____" -ForegroundColor Yellow       
Write-Host `t " |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\" -ForegroundColor Yellow      
Write-Host `t " |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ " -ForegroundColor Yellow     
Write-Host `t " \___  / \____/|__|    \___  >___|  /____  >__|\___  >" -ForegroundColor Yellow     
Write-Host `t "     \/                    \/     \/     \/        \/" -ForegroundColor Yellow      
Write-Host `t "_________        .__  .__                 __" -ForegroundColor Yellow               
Write-Host `t "\_   ___ \  ____ |  | |  |   ____   _____/  |_  ___________" -ForegroundColor Yellow
Write-Host `t "/    \  \/ /  _ \|  | |  | _/ __ \_/ ___\   __\/  _ \_  __ \" -ForegroundColor Yellow
Write-Host `t "\     \___(  <_> )  |_|  |_\  ___/\  \___|  | (  <_> )  | \/" -ForegroundColor Yellow
Write-Host `t " \______  /\____/|____/____/\___  >\___  >__|  \____/|__|" -ForegroundColor Yellow  
Write-Host `t "        \/                      \/     \/" -ForegroundColor Yellow

    Write-Host "1. Triage"
    Write-Host "2. Chainsaw"
    Write-Host "3. Kape"
    Write-Host "4. Triage/Chainsaw and Archive Folder  <------- Recommended Option"
    Write-Host "5. All Options and Archive Folder"
    Write-Host "6. Loki - Yara Scan"
    Write-Host "7. Quit"

    $Choice = Read-Host "Choose a number to launch the action"

    Switch($Choice){
        '1' {Triage ; Main}
        '2' {Chainsaw ; Main}
        '3' {Kape ; Main}
        '4' {Logs ; Triage ; Chainsaw ; Compress ; Main}
        '5' {Triage ; Chainsaw ; Kape ; Compress ; Main}
        '6' {Loki ; Main}
        '7' {Clear-Host ; Write-Host "Exiting Script"}
        default{Clear-Host ; Write-Host `t "You have to choose a number from the list" -ForegroundColor Red ; Main}
    }
}

Main