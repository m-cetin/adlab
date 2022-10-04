function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}

# env variables
$current_domain_name = (Get-ADDomain | Select-Object -Property DNSRoot).DNSRoot
$execute_from_current_path = [System.Environment]::CurrentDirectory
$dc = (Get-ADComputer -Filter * -Properties Name).Name[0]
$client1 = (Get-ADComputer -Filter * -Properties Name).Name[1]
$client2 = (Get-ADComputer -Filter * -Properties Name).Name[2]
$domain_admin_pass = Get-RandomPassword 12 

# questions
$title    = 'AD Lab Setup'
$question = 'Are you sure you want to proceed to build an test lab?'
$choices  = '&Yes', '&No'
$UserAdmin = "Administrator"
$Passwordz = ConvertTo-SecureString -String $domain_admin_pass -AsPlainText -Force
$CredentialAdmin = [pscredential]::new($UserAdmin,$Passwordz)

function Connect-RDP {
    param (
        [Parameter(Mandatory=$true)]
        $ComputerName,

        [System.Management.Automation.Credential()]
        $Credential
    )

    # take each computername and process it individually
    $ComputerName | ForEach-Object {
        # if the user has submitted a credential, store it
        # safely using cmdkey.exe for the given connection

        if ($PSBoundParameters.ContainsKey('Credential'))
        {
            # extract username and password from credential

            $User = $Credential.UserName
            $Password = $Credential.GetNetworkCredential().Password

            # save information using cmdkey.exe
            cmdkey.exe /generic:$_ /user:Administrator /pass:$domain_admin_pass
        }

        # initiate the RDP connection
        # connection will automatically use cached credentials
        # if there are no cached credentials, you will have to log on
        # manually, so on first use, make sure you use -Credential to submit

        # logon credential
        mstsc.exe /v $_ /f /console /admin 
    }
}

Try{
Write-Host "Checking your password policy"
$complexity_enabled = (Get-ADDefaultDomainPasswordPolicy | Select-Object -Property ComplexityEnabled).ComplexityEnabled
if ($complexity_enabled -eq "True"){
    Write-Host "[-] Need to change your policy. Please re-run the script again after restarting the computer!" -ForegroundColor Yellow
    set-addefaultdomainpasswordpolicy -ComplexityEnabled $false -Identity $current_domain_name
    $decision = $Host.UI.PromptForChoice("Restart Required!", "Do you want to restart now?", $choices, 0)
    if ($decision -eq 0) {
        Write-Host '[+] Confirmed!' -ForegroundColor Green
        Restart-Computer
    } else {
        Write-Host '[-] Cancelled' -ForegroundColor Red 
        exit
    }
    }
else{
    Write-Host "[+] Password Policy is fine!" -ForegroundColor Green
}
}
Catch{
Write-Host "Something went wrong!"
}

Try{
$lang = (Get-WinUserLanguageList).LocalizedName
if ($lang -like "*Deutsch*"){
    Write-Host "[+] Detected German as Windows language!" -ForegroundColor Green
    $lang_f = 0
}
if ($lang -contains "*English*" -or $lang -contains "*English (United States)*"){
    Write-Host "[+] Detected English as Windows language!" -ForegroundColor Green
    $lang_f = 1
}

if ($lang_f -ne 1 -and $lang_f -ne 0){
    Write-Host "[-] Language not detected!" -ForegroundColor Red
    Write-Host "quitting.."
    exit
}

}
Catch{
Write-Host "could not determine language on host"; exit}

Try{
Write-Host "[+] Checking requirements"
$ad_computer_count = (Get-ADComputer -Filter * | Select-Object -Property Name | measure).count
if ($ad_computer_count -eq 3){
    Write-Host "[+] Found 3 computers in the Active Directory!" -ForegroundColor Green
}
else{
    Write-Host "[-] This lab needs 1 Domain Controller and 2 clients. Please make sure to install all of them and join them to the domain!" -ForegroundColor Yellow
    Write-Host "[-] quitting.." -ForegroundColor Yellow
    exit
}

}
Catch{Write-Host "error, something went wrong"; exit}

Try{
net user Administrator $domain_admin_pass
Write-Host "This script will setup an Active Directory lab. Please make sure to snapshot your environment before you proceed."
Write-Host "Please make sure both clients are running!" -ForegroundColor Yellow
Write-Host "This is the backup password of the domain admin in case you need it:" -ForegroundColor Yellow
Write-Host $domain_admin_pass -ForegroundColor Yellow
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
if ($decision -eq 0) {
    Write-Host '[+] Confirmed!' -ForegroundColor Green
} else {
    Write-Host '[-] Cancelled' -ForegroundColor Red 
    exit
}
}
Catch{Write-Host "something went wrong"; exit}

# setting up the lab 

Try{
$user_principal_name = "mark" + $current_domain_name

# tmp
net user mark /delete /domain
net user jake /delete /domain

New-AdUser -Name "Mark Down" -LogonWorkstations $client1 -Enabled $True -ChangePasswordAtLogon $false -AccountPassword (ConvertTo-SecureString "tinkerbell" -AsPlainText -force) -passThru -SamAccountName 'mark' -UserPrincipal $user_principal_name | Out-Null 
Set-ADAccountControl  -doesnotrequirepreauth $true -Identity mark 
Write-Host "[+] Created new users" -ForegroundColor Green
Set-WSManQuickConfig -Force
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any
$c = new-CimSession -ComputerName $client1
if ($lang_f -eq 0){
Invoke-Command -ScriptBlock { net user gast /active:yes } -ComputerName $client1 -Throttle 1000
New-SmbShare -Name Users -Path D:\important_data -CimSession $c | Grant-SmbShareAccess -AccountName „Jeder“ -AccessRight Full -Force
}
if ($lang_f -eq 1){
Invoke-Command -ScriptBlock { net user guest /active:yes } -ComputerName $client1 -Throttle 1000
New-SmbShare -Name Users -Path D:\important_data -CimSession $c | Grant-SmbShareAccess -AccountName „Everyone“ -AccessRight Full -Force
}

Invoke-Command -ScriptBlock { netsh firewall set service type = remotedesktop mode = disable } -ComputerName $client1 -Throttle 1000
Invoke-Command -ScriptBlock { netsh firewall set service type = remotedesktop mode = disable } -ComputerName $client2 -Throttle 1000
Invoke-Command -ScriptBlock { netsh advfirewall firewall add rule name="Open SSH Port 22" dir=in action=allow protocol=TCP localport=22 remoteip=any } -ComputerName $client1 -Throttle 1000

#$user_principal_name2 = "jake" + $current_domain_name
#New-AdUser -Name "Jake Harper" -LogonWorkstations "$client1,$client2" -Enabled $True -ChangePasswordAtLogon $false -AccountPassword (ConvertTo-SecureString "Str0ngP@ss!" -AsPlainText -force) -passThru -SamAccountName 'jake' -UserPrincipal $user_principal_name2 | Out-Null 
net user jake "Str0ngP@ss!" /domain /add
if ($lang_f -eq 0){
Invoke-Command -ScriptBlock { net localgroup Administratoren jake /add } -ComputerName $client1
Invoke-Command -ScriptBlock { net localgroup Administratoren jake /add } -ComputerName $client1
}
if ($lang_f -eq 1){
Invoke-Command -ScriptBlock { net localgroup Administrators jake /add } -ComputerName $client1
Invoke-Command -ScriptBlock { net localgroup Administrators jake /add } -ComputerName $client1
}

$User = "jake"
$Password = ConvertTo-SecureString -String "Str0ngP@ss!" -AsPlainText -Force
$Credential = [pscredential]::new($User,$Password)
Start-Sleep -s 5
Invoke-Command -ScriptBlock { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { Set-MpPreference -DisableRealtimeMonitoring $true } -ComputerName $client1
Invoke-Command -ScriptBlock { Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { Start-Service sshd } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { Set-Service -Name sshd -StartupType 'Automatic' } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { mkdir C:\Microsoft; mkdir C:\temp; mkdir C:\IIS\ } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { echo "Get-Process" >> C:\Microsoft\listProcess.ps1 } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass C:\Microsoft\listProcess.ps1"; $Task = New-ScheduledTask -Action $Action -Description "Microsoft frequent updater"; $dt= ([DateTime]::Now); $timespan=$dt.AddYears(3) -$dt; $Trigger = New-ScheduledTaskTrigger -Once -At 9am -RandomDelay (New-TimeSpan -Minutes 1) -RepetitionDuration $timespan -RepetitionInterval (New-TimeSpan -Minutes 1); Register-ScheduledTask -Action $action -TaskName "Frequent Updater" -Trigger $trigger -RunLevel Highest –Force; Start-ScheduledTask -TaskName "Frequent Updater"} -ComputerName $client1 -Credential $Credential | Out-Null
Invoke-Command -ScriptBlock { Set-ExecutionPolicy Bypass -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')); choco install -y python3 } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False } -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { pushd C:\IIS; iwr https://github.com/lemidia/shopping-website-javascript/archive/refs/heads/master.zip -OutFile shop.zip; Expand-Archive -Path .\shop.zip -DestinationPath .\shop; choco install -y --force nodejs; choco install -y --force python2} -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { pushd C:\IIS\shop\shopping-website-javascript-master; C:\Python310\python.exe -m http.server 8080 --bind 0.0.0.0} -AsJob -ComputerName $client1 -Credential $Credential
Invoke-Command -ScriptBlock { pushd C:\IIS\shop\shopping-website-javascript-master; iwr https://github.com/dropways/deskapp/archive/refs/heads/master.zip -OutFile admin.zip; Expand-Archive -Path .\admin.zip -DestinationPath .\admin; pushd .\admin\deskapp-master; npm install deskapp; echo "Oh oh oh oh SCP" > .\config.json; pushd C:\IIS\shop\shopping-website-javascript-master; C:\Python310\python.exe -m http.server 9000 --bind 0.0.0.0} -ComputerName $client1 -Credential $Credential -AsJob

Write-Host "[+] first client successfully setup!" -ForegroundColor Green

if ($lang_f -eq 0){
Invoke-Command -ScriptBlock { net localgroup Administratoren jake /add } -ComputerName $client2
}
if ($lang_f -eq 1){
Invoke-Command -ScriptBlock { net localgroup Administrators jake /add } -ComputerName $client2
}
Invoke-Command -ScriptBlock { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False } -ComputerName $client2 -Credential $Credential
Invoke-Command -ScriptBlock { Set-MpPreference -DisableRealtimeMonitoring $true } -ComputerName $client2 -Credential $Credential

Invoke-Command -ScriptBlock { mkdir "C:\Quod erat demonstrantum"; mkdir "C:\Quod erat demonstrantum\this service\"; copy C:\Windows\System32\cmd.exe "C:\Quod erat demonstrantum\this service\service.exe" } -ComputerName $client2 -Credential $Credential
Invoke-Command -ScriptBlock { sc.exe create "Quod" binPath= "C:\Quod erat demonstrantum\this service\service.exe" start= auto } -ComputerName $client2 -Credential $Credential
Invoke-Command -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0 } -ComputerName $client2 -Credential $Credential


if ($lang_f -eq 0){
Invoke-Command -ScriptBlock { net localgroup Administratoren jake /delete } -ComputerName $client2
}
if ($lang_f -eq 1){
Invoke-Command -ScriptBlock { net localgroup Administrators jake /delete } -ComputerName $client2
}
#net user Administrator $domain_admin_pass 
Write-Host "[+] Please login once" -ForegroundColor Yellow
Connect-RDP -ComputerName $client2 #-Credential $CredentialAdmin
Write-Host "[+] second client successfully setup" -ForegroundColor Green
Write-Host "[+] All clients are ready!" -ForegroundColor Green
}
Catch{Write-Host "something went wrong"}

Try{
Write-Host "[+] Cleaning up.." -ForegroundColor Green
$all_users = (Get-ADUser -Filter * | Select-Object -Property SamAccountName).SamAccountName
foreach ($i in $all_users){if ($i -ne "Administrator" -and $i -ne "Gast" -and $i -ne "krbtgt" -and $i -ne "jake" -and $i -ne "mark" -and $1 -ne "Guest"){Write-Host "[-] Detected unusual user $i" -ForegroundColor Green; Write-Host ""; Write-Host "[+] Deleting your suspicious users" -ForegroundColor Green; net user $i /delete /domain}}
Write-Host "[+] Creating required flags"
Invoke-Command -ScriptBlock { echo "{you_got_in}" > C:\Users\jake\Desktop\user.txt } -ComputerName $client1
Invoke-Command -ScriptBlock { echo "{first_catch!}" > C:\Users\Administrator\Desktop\flag.txt } -ComputerName $client1
Invoke-Command -ScriptBlock { echo "{another_catch!}" > C:\Users\jake\Desktop\user.txt } -ComputerName $client2
Invoke-Command -ScriptBlock { echo "{getting_closer}" > C:\Users\Administrator\Desktop\flag.txt } -ComputerName $client2
echo "{congratz_you_won!}" > C:\Users\Administrator\Desktop\flag.txt
}
Catch{Write-Host "something went wrong!"}

Write-Host "[+] Setup finished!" -ForegroundColor Green
Write-Host "[+] Created 5 flags. Collect all!" -ForegroundColor Green
Write-Host "[+] Please restart all computers and log off" -ForegroundColor Yellow
Write-Host "[+] Systems to attack from your kali:" -ForegroundColor Green
Foreach ($i in (Get-ADComputer -Filter * -Properties Name).Name){
     (Get-ADComputer $i -Properties IPv4Address).IPv4Address
}
