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

In this post I am going to discuss some of the penetration testing process that I use while tackling Boot2Root machines.

## Reconnaissance/ Information Gathering

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

Often times, our target machine will usually have ports 80 (HTTP) and 443 (HTTPS) open. These means we may visit the target ip address on our browser and we should see a web application running.

