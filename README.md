# Active Directory Lab Setup

This powershell script creates a vulnerable Active Directory Lab to exercise AD attacks by using 1 domain controller and 2 clients. This script will delete existing non default users, create 5 different flags to capture and is based upon common AD attack paths. Do not use in production environment.

# Prerequisites

You need 1 domain controller and exactly 2 clients. I used the following setup.

+ [VMWare Workstation Pro 15](https://www.vmware.com/de/products/workstation-pro/workstation-pro-evaluation.html)
+ [Windows Server 2019, x64 bit, German or English](https://www.microsoft.com/de-de/evalcenter/download-windows-server-2019?filetype=ISO)
+ [Windows 10 Enterprise, x64 bit, German or English](https://www.microsoft.com/de-de/evalcenter/evaluate-windows-10-enterprise) x2

# Requirements

Make sure the domain controller and both clients are running. On both clients, run the commands:

```
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'
Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP' -RemoteAddress Any
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

Also, disable the real time protection, the tamper protection and the cloud protection.

![image](https://user-images.githubusercontent.com/102237861/190895172-633bcc23-d055-4ca3-9dcb-f810abd4db2b.png)

# Usage

After running the commands above, use the adlab-setup.ps1 script as domain administrator at your domain controller (Windows server). You might run it twice in order your domain controller needs a restart. This script will **change the password of your domain admin**, so please make sure to note the newly created password. Otherwise you might lock yourself out.

![image](https://user-images.githubusercontent.com/102237861/190895306-b3eb0de7-6314-4e74-ab84-cf8c9bcd0367.png)

At the end of the script, you need to manually login with your newly created password as domain admin. Make sure to kick out the other user to have one successfuly login.

![image](https://user-images.githubusercontent.com/102237861/190895538-fc2f1f7d-987a-4f76-bc98-c6363aea9307.png)

Restart all machines after the setup is done, note the IPs and start hacking from your Linux system. This lab contains 5 different flags to capture.

# Scope

Man in the middle attacks like LLMNR/NBT-NS spoofing are out of scope.
