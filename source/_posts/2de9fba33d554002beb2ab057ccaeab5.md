---
layout: post
title: TryHackMe/Easy/Expose
abbrlink: 2de9fba33d554002beb2ab057ccaeab5
tags:
  - sqli
  - web
  - linux
  - lfi
categories:
  - Labs
  - TryHackMe
  - 1. Easy
  - Expose
date: 1696487691361
updated: 1716658080591
---

<https://tryhackme.com/room/expose>

This challenge is an initial test to evaluate your capabilities in red teaming skills. Start the VM by clicking the `Start Machine` button at the top right of the task. You will find all the necessary tools to complete the challenge, like Nmap, sqlmap, wordlists, PHP shell, and many more in the AttackBox.

*Exposing unnecessary services in a machine can be dangerous. Can you capture the flags and pwn the machine?*

# Enumeration

## \[+] 10.10.236.55 - expose.thm

Using `echo` and `>>` to append the IP address with the domain name to my `/etc/hosts` file. Then `export` the IP address to the environment variable `RHOSTS` so I can use `$RHOSTS` instead of typing the IP address every time.

First I run a quick scan with [rustscan](https://github.com/RustScan/RustScan) and a longer [nmap](https://nmap.org/) stealth scan with `-Pn` mode enabled which will treat all hosts as online:

```
$ sudo echo '10.10.236.55 expose.thm' >> /etc/hosts
$ export RHOSTS=10.10.236.55
$ rustscan -a $RHOSTS --ulimit 5000 -b 4500 -t 2000 --range 1-65535 -- -sC -sV
$ sudo nmap -v -Pn -sS -p- -A --min-rate=1000 -T4 $RHOSTS -oN nmap.txt
```

## \[+] Port 1337 - HTTP

Using [feroxbuster](https://github.com/epi052/feroxbuster) to fuzz for directories and files:

```
$ feroxbuster -u http://expose.thm:1337/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x json,txt,js,xml -s 200,301,302,403 -o p-1337-www-ferox.txt

[...]
301      GET        9l       28w      326c http://expose.thm:1337/admin/assets => http://10.10.236.55:1337/admin/assets/
200      GET       11l       23w      212c http://expose.thm:1337/admin/assets/script.js
200      GET       14l       19w      173c http://expose.thm:1337/admin/assets/styles.css
200      GET        1l      243w    12646c http://expose.thm:1337/admin/assets/core.js
200      GET        7l     1210w    80599c http://expose.thm:1337/admin/assets/bootstrap.bundle.min.js
200      GET        6l     2272w   220780c http://expose.thm:1337/admin/assets/bootstrap.min.css
200      GET    10993l    45090w   293671c http://expose.thm:1337/admin/assets/jquery-3.6.3.js
301      GET        9l       28w      324c http://expose.thm:1337/javascript => http://expose.thm:1337/javascript/
301      GET        9l       28w      324c http://expose.thm:1337/phpmyadmin => http://expose.thm:1337/phpmyadmin/
[...]
301      GET        9l       28w      323c http://10.10.236.55:1337/admin_101 => http://expose.thm:1337/admin_101/
301      GET        9l       28w      332c http://expose.thm:1337/admin_101/includes => http://expose.thm:1337/admin_101/includes/
301      GET        9l       28w      331c http://expose.thm:1337/admin_101/modules => http://expose.thm:1337/admin_101/modules/
[...]
```

We find three possible admin portals at `/admin`, `/admin_101` and `/phpmyadmin`.

### \[-] expose.thm/admin

Here we have a login form but the clue suggests this might not be the right one:

![5980d81148a3b4cb128bef2c8c00a291.png](/resources/1e567a0fbae44fdf8880cfeaf5b8c066.png)

If we try to login with test credentials nothing happens.

To confirm this, we can open the Developer Tools in Firefox by pressing F12 and clicking the "Continue" button. If this were a real login portal there should be some activity but here we can see there is none:

![79a5aa4c4c313e7ec9d4b36585d28563.png](/resources/72e82c0f69f1492482d3da70f0746c4a.png)

We can also open the website using [ZAP](https://www.zaproxy.org/) and check the history tab to see if there are any other requests being made after clicking the "Continue" button. And there are only two requests that were made upon accessing the website:

![386a77ad03f3df360e642372cd3c04e0.png](/resources/c323fd886453499a8904903c45b74f1e.png)

### \[-] expose.thm/admin\_101

This page looks the same as `/admin` but there is an e-mail address already filled in:

![098b17f7bdf546687db6da4c73e9e659.png](/resources/1ecf02cba329400aac38aff681f75c45.png)

When we click the "Continue" button the website sends a request:

![0a51d2edd7ec0065e55a029dd854c7c5.png](/resources/ea57b1856c864e0d97cf85665a00d63f.png)

And after a couple of seconds we get the pop up message, "error":

![2d703487dfd0ad1b4ef5549df6a043db.png](/resources/8643661dc99c4860b59f72d64dcf601b.png)

If we check the request in ZAP we find the SQL command in the response:

![fb1a7cfbc331535d41e4fb39dd569307.png](/resources/f53c3bd035074536ae4869e3cd9c6793.png)

We can check for [SQL injection](https://portswigger.net/web-security/sql-injection) by inserting a single quote `'` in the e-mail address `'hacker@root.thm` and we get a different pop up message, "undefined":

![6e69fd7e44181b64d2138a2f6c1cfab1.png](/resources/9ed0b05efaa446de9e7e242ad6dd5b6c.png)

In ZAP, the response shows an MySQL error message:

![4bb02782cb7b59c812bc6e76545a9cf6.png](/resources/cf765f848f3547b59c170515227ea05e.png)

We can right-click on the request text area then highlight Save Raw > Request and click on "All" to save the request:

![3c09ff5cc8829287555421971c7bffd3.png](/resources/34902323d35d4f26ae66e19ff77d66f8.png)

Now we can use a tool like [sqlmap](https://github.com/sqlmapproject/sqlmap) for SQL injection by using this raw request file we just saved.

Here we specify that we want to use a request file with `-r <filename>` and to list the databases with `--dbs`:

```
$ sqlmap -r req.raw --dbs
```

There will be some prompts from `sqlmap`, we can just use the default/suggested settings which are capitalized:

```
are you sure that you want to continue with further target testing? [Y/n]
$ Y
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]
$ Y
injection not exploitable with NULL values. Do you want to try with a random integer value for option ' -- union-char'? [Y/n]
$ Y
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
$ N
```

We can also just let `sqlmap` dump everything but this might take a long time depending on the target's database. The option `--batch` will skip all prompts, `--dump-all` will dump every database found and `--threads=10` will increase the number of concurrent requests (max is 10):

```
$ sqlmap -r req.raw --batch --dump-all --threads=10
```

The databases that are available:

![b15c7a7841d55eb543322dbce4355cd3.png](/resources/9b0f84984be34d64adef0336172f9743.png)

First we'll explore the "expose" database using `-D expose` and list all the tables with `--tables`:

```
$ sqlmap -r raw.req -D expose --tables
```

![aed9f0eff6325eddda83cc60f073c7c6.png](/resources/1eff521b65d849efa7c226e5fe39c742.png)

Then we select the table we want, in this case "user" with `-T user` and list all the columns with `--columns`:

```
$ sqlmap -r req.raw -D expose -T user --columns
```

![6eb14230e726c746be09cb93c4f16e78.png](/resources/ef92f8aa30774414991b83563a3b2587.png)

The columns that seem interesting are "email", "id" and "password". We can select them with `-C email,id,password` and use `--dump` to dump all available entries for these columns:

```
$ sqlmap -r req.raw -D expose -T user -C email,id,password --dump
```

![b57f1501de16591660d587d9f0b8c099.png](/resources/897ac586ac544890b182e9b12391511b.png)

Here we dump the entries for the other table "config":

```
$ sqlmap -r req.raw -D expose -T config -C id,url,password --dump
```

![225d8e3720e3ac15ce7bf92a09831b4f.png](/resources/6d23b69a66a44d7391c1cddd8316c24d.png)

### \[-] expose.thm:1337/file1010111

When the page loads we are prompted to enter a password:

![8036b709035ea95c53300fe1ba817d94.png](/resources/a2bf9409c8294a42b9e61c37d1fef58d.png)

The password we found from `sqlmap` was hashed using [MD5](https://en.wikipedia.org/wiki/MD5). We can use a site like [hashes.com](https://hashes.com/en/decrypt/hash) to find the plaintext of the hash:

![4bed91e85be5d09a49ac96e5d178b0e9.png](/resources/da770dd22fed4ffc9a4808c8b6c77035.png)

After entering the password we find the next clue:

![c6e479d940823b516c2302fa5e7dcf6a.png](/resources/070d2a74cc2c408db99ab8bcf9c2a363.png)
*"Parameter Fuzzing is also important :) or Can you hide DOM elements?"*

Checking the source code we find another clue:

![c0fbd1d60e89f8d35d5503e72aa65073.png](/resources/f248368398a34b44a0bffa32297e58c4.png)
*"Hint: Try file or view as GET parameters?"*

If we visit the URL `http://expose.thm:1337/file1010111/index.php?file=1` we get a blank index.php page which tells us it's trying to display a file that doesn't exist or is empty:

![83839d66f8a36944d712fef7b3fb0e66.png](/resources/cbd3f00878654384aac6f60817573ec0.png)

We can try to see if this parameter is vulnerable to [Local File Inclusion (LFI)](https://en.wikipedia.org/wiki/File_inclusion_vulnerability).

Changing the `file=1` parameter to `file=/etc/passwd` we get the contents of the "passwd" file in response:

![415e12ddb61c5cfd08960b225d1e6c31.png](/resources/14c9d3fb9873484d91f2a83d0c680450.png)

### \[-] expose.thm:1337/upload-cv00101011

This page is also password protected:

![cfb5d4169362e8636b9ef167f82db8cf.png](/resources/e99e7dbd5bd4427d98cfb9613bfd696d.png)
*"Hint: It is the name of machine user starting with letter "z""*

After entering the username we found from accessing the "passwd" file, we are now able to upload files:

![8236b58b9486196222484de39c7f2947.png](/resources/3b2b126894f74836b6bb903f403d55cb.png)

# Initial Foothold

### \[-] www-data

If we check the source code for `expose.thm:1337/upload-cv00101011` we can see there is client-side filtering for the file type we can upload:

![4b26a11d2b229d99eb08f2d51ac234a4.png](/resources/0fa4c4c166e6458ca1c79be62f2fe52f.png)

The filter is only allowing JPG or PNG files, but since this validation is client-side we can bypass it by uploading a malicious file as a JPG or PNG then capture the request in ZAP and modify it to it's original extension.

We can use a PHP Reverse Shell to get a reverse connection to our attacker machine. I'll use the website [revshells.com](https://www.revshells.com/) to generate the script.

We just have to enter our attacker machine's IP and the port we want to use, then select the PHP reverse shell script by Ivan Sineck, "PHP Ivan Sincek" and click the floppy disk icon to save the payload:

![923ffd86045421c58da1bb590d4f97da.png](/resources/efbcfe5c5650425d8aa8f4308f31807b.png)

When prompted we change the payload extension from `.sh` to `.png`:

![29fcf05e9fa3a62c8fa12163e526972e.png](/resources/5160c2b1b7824dbaae0dd2e1c948f9c8.png)

To get a reverse shell, we first start a listener on our attacker machine using [nc](https://linux.die.net/man/1/nc):

```
$ nc -lvnp 4444
```

Next we turn on "Set break on all requests and responses" in ZAP by clicking the green circle icon, which will turn red when activated:

![f7d21a2f1b7553885a53e98af982c805.png](/resources/9d53b2a34fd3418283029ffb90f7c8fb.png)

Back to the file upload, we select our "payload.png" file and click "Upload":

![540aad47d151e5b477ca6631d88a400d.png](/resources/0da946ff540d4dc1a0aa32feeef57f62.png)

In ZAP we can see the request and modify the filetype from "payload.png" to "payload.php":

![467d918262295206a42a5e719c0d46b3.png](/resources/f433d76244fe4eca8d9acc5e7a21bd03.png)

And click the arrow to forward the request:

![f06aa1736395603f5204693545cdeb75.png](/resources/db82a41e14bc43a3b03c9fff2c9fa34e.png)

After uploading the payload we receive a message confirming a successful upload and a hint on where to find the file location:

![322b1612762a2c4fc06fe35f47197313.png](/resources/f862c7dcd9c841fcb24428039a9cd289.png)
*"File uploaded successfully! Maybe look in source code to see the path"*

When we check the source code we find the directory `/upload_thm_1001`:

![b5386fc461224a14eaa4530dbd4365c7.png](/resources/4bea10e5996b4cafb4f5e4bb8efcf5a7.png)

Now when we visit the URL `http://expose.thm:1337/upload-cv00101011/upload_thm_1001/payload.php` the page will hang, but if we check the listener on the attacker machine we should have a reverse shell:

![8788b7e0737788b8797b7c5963188d70.png](/resources/551e6d4fe2ee4cf2b7f8beae0aa327a7.png)

Checking the `/home/<user>` directory, we find a flag, but we don't have permissions to read it and credentials to SSH into the machine as this user:

```
$ ls -lah
```

![ce7d29e294cb542523e6374ca74b4ed3.png](/resources/571a80c25e9b40b0af6cc6a659ef4207.png)

```
$ cat ssh_creds.txt
```

![93564499c506bb9cbf54cc0b520eb8cd.png](/resources/1aee440d5814485fa72e338aa7d3ee5c.png)

# Privilege Escalation

## \[+] Port 22 - SSH

### \[-] z...

We can login as the user with `ssh`:

```
$ ssh@$RHOSTS
```

And now we are able to read the flag in `/home/<user>/flag.txt`:

```
$ cat flag.txt
```

![fc40b6a0b78656145f8f72a3124ce355.png](/resources/5407ed16480f415baf7ab4c8e964f523.png)

### \[-] root

We can use the `find` command to search for any binaries with the [SUID bit](https://www.redhat.com/sysadmin/suid-sgid-sticky-bit) set:

```
$ find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null
```

The `find` binary actually has the SUID bit set and we can use this to escalate our privileges to root:

![354c42ece08bf79d2a42e86f98ba0561.png](/resources/0137e70f8f0441d7b45efd4c47a17d61.png)

Checking [GTFObins](https://gtfobins.github.io/gtfobins/find/#suid) on how to exploit this:

From GTFObins, *"If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges."*

So we just need to run the command:

`find . -exec /bin/sh -p \; -quit`

And we maintain root privileges:

![8d1eece2b0cef4e7b767247ee709c6c1.png](/resources/723192af2b5e496d934d7ad529173f17.png)

The final flag is in `/root/flag.txt`:

```
$ cat /root/flag.txt
```

![96b06de8690d7f81c648d26c43ce90d7.png](/resources/85f6dbadc5824b4da3b4a8fc66c615ac.png)
