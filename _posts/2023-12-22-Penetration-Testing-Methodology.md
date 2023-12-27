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

In this post I am going to share some of my penetration testing process that I use both when I am performing general pentest or tackling Boot2Root machines.

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
nmap -sC -sV 10.150.150.18
```

> -sC specifies that Nmap scripts should be used to try and obtain more detailed information. <br><br>-sV instructs Nmap to perform a version scan. 

In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version.

![](/assets/images/nmap.png)

By default, Nmap will only scan the 1,000 most common ports by default. To scan all 65,535 ports, we can use the -p- tag.

Nmap is incredibly powerful with other features for attacking network services such as banner grabbing. Using Nmap script also allows us to check for specific vulnerability such as Citrix NetScaler (CVE-2019–19781). 

We are barely scratching the surface!

#### Rustscan

To quickly scan all ports in a machine, Rustscan is preferred for me as it will take a long time in Nmap.

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

Be sure to add your newly discovered subdomain to the etc/hosts file.

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
We can also utilize online exploit databases such as ExploitDB, Rapid7 DB, or Vulnerability Lab.

### Searchsploit
Searchsploit enables us to search for public vulnerabilities/exploits for any application.

```
searchsploit eternalblue
```

### Metasploit
Metasploit contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. 
To run Metasploit, we can use the msfconsole command:
```
msfconsole
```

Once we have Metasploit running, we can search for our target application with the search exploit command.
```
msf6 > search exploit eternalblue
```

Once we have identified the exploit we want to use, we can simply key in the command 'use' follow by the number identified for the exploit:

```
use 6
```

Before we can run the exploit, we need to configure its options. To view the options available to configure, we can use the show options command:

```
show options
```

Any option with Required set to yes needs to be set for the exploit to work. In this case, we only have two options to set: RHOSTS, which means the IP of our target (this can be one IP, multiple IPs, or a file containing a list of IPs). We can set them with the set command:

```
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
LHOST => tun0
```

Once we have both options set, we can start the exploitation. We can use the run or exploit command to run the exploit:

```
msf6 exploit(windows/smb/ms17_010_psexec) > exploit
```

## Post Exploitation

### Privilege Escalation