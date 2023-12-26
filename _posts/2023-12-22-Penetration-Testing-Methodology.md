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

## Introduction
In this post I am going to share some of my penetration testing process that I use both when I am performing general pentest or tackling Boot2Root machines.

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

> The -sC tag specifies that Nmap scripts should be used to try and obtain more detailed information. The -sV parameter instructs Nmap to perform a version scan. 

In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version.

![](/assets/images/nmap.png)

By default, Nmap will only scan the 1,000 most common ports by default. To scan all 65,535 ports, we can use the -p- tag.

#### Rustscan

To quickly scan all ports in a machine, Rustscan is preferred for me as it will take a long time in Nmap.

```
rustscan -a 10.150.150.18 --range 1-65535 --ulimit 5000
```

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
Talk about adding new subdomain to the etc/hosts file.

> Seclists

To be continued.