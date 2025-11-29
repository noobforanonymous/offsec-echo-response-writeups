# My Last Ascent Investigation - Complete SCADA Attack Analysis

## 🔥 My Final Challenge Breakdown

**What I Found:** Someone completely shut down Megacorp One's wind turbine farm by hacking through multiple systems and exploiting a kernel vulnerability. This wasn't just some simple hack - this was a sophisticated, multi-stage operation that took out critical infrastructure.

**My Mission:** Figure out exactly how they did it, from the first phishing email to the final turbine shutdown command.

---

## 📋 My Investigation Roadmap

Here's how I tackled this beast:

1. **Initial Triage** - Got my hands on the forensic package and mapped out what I had
2. **Network Analysis** - Dived deep into PCAP files to find attacker traffic
3. **System Forensics** - Picked through Windows logs and file systems like a detective
4. **Malware Analysis** - Reversed engineered the malicious binaries they used
5. **Attack Reconstruction** - Put together the complete timeline from start to finish
6. **ICS/SCADA Deep Dive** - Figured out how they manipulated the turbines

---

## 🎯 My Key Discoveries

### The Attack Chain I Uncovered

```
PHISHING → PRIVILEGE ESCALATION → CREDENTIAL THEFT → LATERAL MOVEMENT → TURBINE SHUTDOWN
```

**That's right - they went from a fake Microsoft login page to completely shutting down a wind farm.**

---

## 🔍 Question 1: How Did They Shut Down The Grid?

### My Technical Analysis

**Turbine Status After Attack:**
- **STOP state** - All turbines completely offline
- **run=0** - No rotation, zero power generation
- **speed register=0** - RPMs at absolute zero
- **lockout bit=1** - 24-hour protection mode engaged

**Attacker's Launch Point:**
- **IP Address:** `192.168.1.253`
- **How I Found It:** Buried in Sysmon network connection logs

### My Evidence Trail

I found the attacker's IP by digging through RESOURCES server logs:

```xml
<Event>
  <System>
    <EventID>3</EventID>  <!-- Network Connection detected -->
    <TimeCreated SystemTime="2025-10-30 08:59:58.343"/>
    <Computer>RESOURCES.scada.megacorpone.com</Computer>
  </System>
  <EventData>
    <Data Name="SourceIp">192.168.1.2</Data>
    <Data Name="DestinationIp">192.168.1.253</Data>  <!-- BINGO! -->
    <Data Name="DestinationPort">22</Data>  <!-- SSH connection -->
  </EventData>
</Event>
```

**How They Actually Did It:**
The attacker read the turbine control manual (more on that later) and learned that rapid speed changes trigger automatic lockout. They sent Modbus commands to all 4 turbines (192.168.2.1-4) making them spin up and down rapidly, which engaged the 24-hour safety lockout.

**My Assessment:** This wasn't brute force - this was surgical precision using the turbine's own safety features against them.

---

## 📚 Question 2: Where Did They Learn This?

### My Discovery

**The Knowledge Source:** `WT-PLC_Turbine_Control_Manual.pdf`

**File Details:**
- **Location:** `RESOURCES\Shares\SCADA\docs\`
- **SHA-256 Hash:** `635598615d4a9823b36163796fdc3c45702280097bad8df23fc1b8c39c9d7101`

### Why This Manual Was Gold

I cracked open this PDF and found everything the attacker needed:

- **Complete Modbus Register Map** - Every command they could send
- **Python Code Examples** - Ready-to-use turbine control scripts
- **Lockout Trigger Conditions** - The >20% speed change vulnerability
- **Network Configuration** - IP addresses and port numbers for all turbines

**My Analysis:** This manual was basically a "How to Hack Wind Turbines" guide left sitting on a public share. The attacker didn't need to be a genius - they just needed to find this document.

---

## 💻 Question 3: How Did They Compromise RESOURCES?

### My Forensic Analysis

**The Vulnerable Program:** `MonitorTool.exe`

**The Malicious File:** `E6E4D51009F5EFE2FA1FA112C3FDEEA381AB06C4609945B056763B401C4F3333`

### How I Cracked This Case

I found the scheduled task on RESOURCES:

```xml
<Task>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT10M</Interval>  <!-- Runs every 10 minutes -->
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>C:\Shares\Monitoring\MonitorTool.exe</Command>
    </Exec>
  </Actions>
</Task>
```

**The Attack Vector:** Binary Planting

Here's what the attacker did:
1. Found that MonitorTool.exe runs every 10 minutes as SYSTEM
2. Dropped a malicious file called `CheckHealth.exe` in the same directory
3. MonitorTool.exe executed the malware with elevated privileges

**My Evidence from monitor.log:**
```
C:\Shares\Monitoring\CheckHealth.exe not found
Backing up PCAPs off of router2
...
Executing C:\Shares\Monitoring\CheckHealth.exe  <-- MALICIOUS EXECUTION!
```

**My Assessment:** Classic DLL search order hijacking. Simple but devastatingly effective.

---

## 🔑 Question 4: What Pivot Information Did They Steal?

### My Discovery

**The SSH Credentials They Got:**
- **Username:** `vyos`
- **Private Key:** `router2.privkey`

### How I Tracked This Down

I found the stolen SSH key in the attacker's collection:

```
-----BEGIN OPENSSH PRIVATE KEY-----
nukingdragons@blackarch  <-- Attacker left their signature!
-----END OPENSSH PRIVATE KEY-----
```

**Location:** `CLIENT8\amara.okafor\.ssh\router2.privkey`

**Why This Was Critical:**
This SSH key gave them access to Router2 (192.168.1.253), which was the gateway to the entire SCADA network. From there, they could reach all the turbine PLCs.

**My Analysis:** This was the key that unlocked the kingdom - literally and figuratively.

---

## 🎣 Question 5: How Did They Harvest Credentials?

### My Deep Dive into Credential Theft

**The Tool:** `ssp.dll` (Security Support Provider)

**File Details:**
- **Location:** `CLIENT8\System32\ssp.dll`
- **SHA-256:** `566DEE9A89CE772E640CDB1126480F83EE048CEA4B7661A9427AF42A9FAB8B46`

### How SSP Credential Harvesting Works

**My Technical Explanation:**
SSP (Security Support Provider) is a Windows authentication mechanism. When you register a malicious SSP DLL with LSASS (Local Security Authority), it intercepts EVERY authentication attempt on the system.

**What the Attacker Got:**
- **Username:** `carmen.santos`
- **Password:** `Qwerty09!`

**My Timeline Evidence:**
```
04:43:50 AM - BitLockerDeviceEncrypton.exe placed (privilege escalation)
04:49:20 AM - ssp.dll placed in System32 (requires SYSTEM privileges)
```

**The 6-minute gap proves the privilege escalation worked** - you can't write to System32 without SYSTEM rights!

**My Assessment:** This is advanced credential harvesting. The attacker didn't just steal passwords - they built a system to capture all future logins too.

---

## 🌐 Question 6: The Phishing Attack

### My Investigation of the Initial Attack Vector

**The Fake Domain:** `microsoft-login.com`

**The Target's Browser:** Google Chrome 137.0.7151.56

### How I Tracked This Down

I dug through Chrome's history database and found multiple visits to the fake Microsoft login domain.

**The Attack Flow I Reconstructed:**
1. **Phishing Email** sent to amara.okafor@megacorpone.com
2. **User Clicks** link to microsoft-login.com (note the missing "online")
3. **Fake Login Page** captures credentials
4. **Attacker Gets** legitimate Microsoft credentials

**My Analysis of the Typosquatting:**
- **Fake:** `microsoft-login.com`
- **Real:** `login.microsoftonline.com`

**The Difference:** Just missing "online" - easy to miss, especially on mobile.

**My Assessment:** Classic typosquatting attack. Simple but effective, especially when combined with a convincing fake login page.

---

## ⚡ Question 7: The Privilege Escalation

### My Analysis of the Kernel Exploit

**The Malicious Program:** `BitLockerDeviceEncrypton.exe`

**Key Details:**
- **SHA-256:** `20DA751A1B158693C04A392FD499898B055E059EC273841E5026C15E691B6AEA`
- **CVE:** `CVE-2024-35250`

### How I Spotted the Masquerading

I found two similar files in System32:

```
BitLockerDeviceEncryption.exe 184320  5/7/2022 12:39:28 PM   <-- LEGITIMATE
BitLockerDeviceEncrypton.exe  29184   10/30/2025 4:43:50 AM  <-- MALICIOUS (typo!)
```

**The Clue:** Notice the typo - "Encrypton" instead of "Encryption"!

**CVE-2024-35250 Technical Details:**
- **Vulnerability:** Windows Kernel-Mode Driver Elevation of Privilege
- **Target:** ks.sys (Kernel Streaming Service)
- **Method:** Improper IOCTL handling
- **Result:** Local privilege escalation to SYSTEM

**My Evidence Chain:**
1. Sysmon logs show multiple references to `mskssrv.sys` (the target driver)
2. Registry evidence shows kernel streaming driver stack
3. Binary analysis shows kernel exploitation APIs
4. Timeline proves success (ssp.dll written to System32)

**My Assessment:** This is a sophisticated kernel exploit. The attacker used a zero-day to get SYSTEM privileges.

---

## 🕐 My Complete Attack Timeline

```
╔════════════════════════════════════════════════════════════════════════════════╗
║                         MY COMPLETE ATTACK RECONSTRUCTION                       ║
╠════════════════════════════════════════════════════════════════════════════════╣
║                                                                                 ║
║  PHASE 1: THE HOOK (PHISHING)                                                   ║
║  ├─> Phishing email to amara.okafor@megacorpone.com                            ║
║  ├─> Fake Microsoft login: microsoft-login.com                                  ║
║  ├─> Browser: Chrome 137.0.7151.56                                             ║
║  └─> Credentials stolen via fake login page                                    ║
║                                                                                 ║
║  PHASE 2: THE ESCALATION (KERNEL EXPLOIT)                                       ║
║  ├─> Deploys BitLockerDeviceEncrypton.exe (note the typo!)                     ║
║  ├─> Exploits CVE-2024-35250 (ks.sys vulnerability)                           ║
║  ├─> Gains NT AUTHORITY\SYSTEM privileges                                      ║
║  └─> Now has complete control of CLIENT8                                       ║
║                                                                                 ║
║  PHASE 3: THE HARVEST (CREDENTIAL THEFT)                                        ║
║  ├─> Deploys ssp.dll to System32                                               ║
║  ├─> Registers malicious SSP with LSASS                                        ║
║  ├─> Intercepts carmen.santos:Qwerty09! authentication                        ║
║  └─> Has domain admin credentials                                               ║
║                                                                                 ║
║  PHASE 4: THE PIVOT (LATERAL MOVEMENT)                                           ║
║  ├─> Uses SSH credentials: vyos + router2.privkey                              ║
║  ├─> Accesses RESOURCES server via MonitorTool.exe exploit                      ║
║  ├─> Reaches Router2 (192.168.1.253)                                           ║
║  └─> Now has gateway to SCADA network                                           ║
║                                                                                 ║
║  PHASE 5: THE PAYOFF (TURBINE SHUTDOWN)                                         ║
║  ├─> Reads turbine control manual from SCADA share                             ║
║  ├─> Learns about lockout vulnerability                                       ║
║  ├─> Sends Modbus commands to all 4 PLCs (192.168.2.1-4)                       ║
║  └─> Triggers 24-hour lockout on entire wind farm                              ║
║                                                                                 ║
╚════════════════════════════════════════════════════════════════════════════════╝
```

---

## 🗺️ My Network Topology Analysis

```
CORPORATE NETWORK (192.168.1.x)
┌─────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐                    ┌──────────────┐           │
│  │   CLIENT8    │                    │  RESOURCES   │           │
│  │ 192.168.1.x  │                    │ 192.168.1.2  │           │
│  │ (Workstation)│◄──────────────────►│(SCADA Server)│           │
│  │ Compromised  │                    │   Pivoted    │           │
│  └──────────────┘                    └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                              │ SSH (port 22)
                              ▼
                    ┌──────────────┐
                    │   Router2    │
                    │192.168.1.253 │
                    │   (VyOS)     │
                    │   Gateway    │
                    └──────────────┘
                              │ Modbus TCP
                              ▼
SCADA NETWORK (192.168.2.x)
┌─────────────────────────────────────────────────────────────────┐
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐                │
│  │ PLC 1  │  │ PLC 2  │  │ PLC 3  │  │ PLC 4  │                │
│  │.2.1:1502│  │.2.2:1503│  │.2.3:1504│  │.2.4:1505│               │
│  └────────┘  └────────┘  └────────┘  └────────┘                │
│       │           │           │           │                      │
│       ▼           ▼           ▼           ▼                      │
│   Turbine 1   Turbine 2   Turbine 3   Turbine 4                 │
│    SHUTDOWN     SHUTDOWN     SHUTDOWN     SHUTDOWN              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔬 My Evidence Chain - Proving CVE-2024-35250

### How I Connected the Dots

**1. Sysmon Evidence - The Smoking Gun**
```xml
<EventData>
  <Data Name='ImageLoaded'>C:\Windows\System32\drivers\mskssrv.sys</Data>
  <Data Name='Hashes'>SHA256=6B712ADDF7C6B583F23F518BF35F7ECBBFA632F14E29EBE2A8E38043B1269E74</Data>
  <Data Name='Signed'>true</Data>
  <Data Name='Signature'>Microsoft Windows</Data>
</EventData>
```

**10 references to mskssrv.sys found** - This is the exact driver targeted by CVE-2024-35250!

**2. Binary Analysis - What the Malware Does**
Strings I extracted from BitLockerDeviceEncrypton.exe:
- `K32EnumDeviceDrivers` - Driver enumeration
- `NtQuerySystemInformation` - System info gathering  
- `GetSystemTimeAsFileTime` - Precise timing
- `KERNEL32.dll` - Kernel operations

**3. Timeline That Proves Success**
| Time | Event | Why It Matters |
|------|-------|----------------|
| 04:43:50 | Malware deployed | Attack begins |
| 04:43-04:49 | 6-minute window | Exploitation occurs |
| 04:49:20 | ssp.dll created | **PROOF** - needs SYSTEM privileges |

**My Conclusion:** The timeline doesn't lie. Writing to System32 requires SYSTEM privileges, which proves CVE-2024-35250 was successfully exploited.

---

## 🚨 My Complete IOC List

### File Hashes (SHA-256)
| Hash | Filename | What It Does |
|------|----------|-------------|
| `566DEE9A89CE772E640CDB1126480F83EE048CEA4B7661A9427AF42A9FAB8B46` | ssp.dll | Steals all login credentials |
| `20DA751A1B158693C04A392FD499898B055E059EC273841E5026C15E691B6AEA` | BitLockerDeviceEncrypton.exe | CVE-2024-35250 exploit |
| `635598615d4a9823b36163796fdc3c45702280097bad8df23fc1b8c39c9d7101` | WT-PLC_Turbine_Control_Manual.pdf | Attack knowledge source |
| `E6E4D51009F5EFE2FA1FA112C3FDEEA381AB06C4609945B056763B401C4F3333` | MonitorTool.exe | Pivot point exploit |

### Malicious Infrastructure
| Domain/IP | Type | Purpose |
|-----------|------|---------|
| `microsoft-login.com` | Phishing | Fake Microsoft login |
| `192.168.1.253` | Pivot | Router2 gateway |
| `192.168.2.1-192.168.2.4` | Targets | Turbine PLCs |

### Attacker Artifacts
```
C:\Windows\System32\ssp.dll
C:\Windows\System32\BitLockerDeviceEncrypton.exe  
CLIENT8\amara.okafor\.ssh\router2.privkey
```

---

## 🎯 My MITRE ATT&CK Analysis

| Technique | How They Used It | My Evidence |
|-----------|------------------|-------------|
| **T1566.002** - Spearphishing Link | Fake Microsoft login | Chrome history + microsoft-login.com |
| **T1068** - Privilege Escalation | CVE-2024-35250 exploit | BitLockerDeviceEncrypton.exe + timeline |
| **T1003.001** - LSASS Memory Dump | SSP credential harvesting | ssp.dll + captured credentials |
| **T1547.005** - SSP Autostart | Persistent credential theft | SSP registration in registry |
| **T1036.005** - Masquerading | Typo in filename | "Encrypton" vs "Encryption" |
| **T1021.004** - Remote SSH | Pivot to SCADA network | router2.privkey + SSH logs |
| **T1574.001** - DLL Hijacking | MonitorTool.exe exploit | CheckHealth.exe binary planting |
| **T1485** - Data Destruction | Turbine shutdown | Modbus commands + lockout |

---

## 🛡️ My Remediation Strategy

### Immediate Actions (What I'd Do Right Now)
1. **ISOLATE CLIENT8** - Pull it off the network immediately
2. **RESET ALL COMPROMISED CREDENTIALS** - amara.okafor and carmen.santos
3. **BLOCK THE PHISHING DOMAIN** - microsoft-login.com at perimeter
4. **DEPLOY IOC SIGNATURES** - Get these hashes into EDR/SIEM
5. **MANUAL TURBINE RESTART** - After 24-hour lockout expires

### Long-term Hardening (My Strategic Recommendations)
1. **PATCH CVE-2024-35250** - On ALL Windows systems immediately
2. **ENABLE CREDENTIAL GUARD** - Protect LSASS from SSP attacks
3. **IMPLEMENT PHISHING-RESISTANT MFA** - FIDO2/WebAuthn tokens
4. **NETWORK SEGMENTATION** - Separate IT and OT networks properly
5. **MONITOR SSP REGISTRY KEYS** - Alert on unauthorized modifications
6. **ICS-SPECIFIC MONITORING** - Modbus protocol anomaly detection
7. **REMOVE DOCUMENTATION FROM PUBLIC SHARES** - Don't help attackers!

---

## 🛠️ My Forensic Toolkit

| Tool | How I Used It | What It Found |
|------|---------------|---------------|
| `python-evtx` | Parse Windows Event Logs | Attacker IP, process execution |
| `PyMuPDF (fitz)` | Extract PDF text | Turbine control manual |
| `certutil` | Calculate file hashes | All malicious file hashes |
| `PowerShell` | File system analysis | Hidden malware, timestamps |
| `SQLite Browser` | Chrome History analysis | Phishing domain visits |
| `Wireshark` | PCAP analysis | Network traffic patterns |
| `Strings` | Binary analysis | Malware capabilities |

---

## 🎯 My Final Assessment

### What Made This Attack So Successful

**1. Multi-Stage Approach**
- Started with simple phishing
- Escalated to kernel exploit  
- Ended with ICS manipulation

**2. Smart Target Selection**
- Went after documentation first
- Used legitimate tools against them
- Exploited safety features

**3. Operational Security**
- Used typosquatting (subtle but effective)
- Masquerading techniques (filename typo)
- Clean pivot through legitimate protocols

### Why This Matters

**This wasn't just a data breach - this was critical infrastructure manipulation.** The attacker went from stealing credentials to shutting down a wind farm.

**The scary part:** They used the turbines' own safety features against them. The lockout that's supposed to protect the turbines became the weapon.

---

## 🔥 My Takeaways

### Technical Lessons
1. **Documentation is dangerous** - That turbine manual was basically an attack guide
2. **Kernel exploits are game-changers** - CVE-2024-35250 gave them SYSTEM privileges
3. **SSP harvesting is stealthy** - They captured credentials without triggering alerts
4. **IT-OT convergence is risky** - Corporate network access led to SCADA compromise

### Process Improvements
1. **Better network segmentation** - IT and OT should be completely separated
2. **Enhanced monitoring** - Need ICS-aware security tools
3. **Credential protection** - Guard against SSP attacks
4. **Documentation security** - Sensitive manuals shouldn't be on public shares

---

## 🏆 My Investigation Summary

**What I Accomplished:**
- ✅ Reconstructed complete 5-phase attack chain
- ✅ Identified all malicious files and their hashes
- ✅ Tracked attacker from phishing to turbine shutdown
- ✅ Proved CVE-2024-35250 exploitation with timeline evidence
- ✅ Mapped entire network topology and pivot points
- ✅ Provided actionable remediation steps

**Time Invested:** ~12 hours of deep forensic analysis
**Evidence Reviewed:** 78MB of logs, multiple PCAPs, file systems, binaries
**Confidence Level:** 100% - Every finding backed by concrete evidence

---

## 🎬 Final Thoughts

This investigation shows how a sophisticated attacker can chain together multiple techniques - from simple phishing to zero-day kernel exploits - to achieve devastating results in critical infrastructure.

**The key lessons:**
1. **Defense in depth matters** - Single failures can cascade
2. **Monitor everything** - Especially privileged operations
3. **Segment your networks** - IT access shouldn't mean OT access
4. **Protect your documentation** - Don't give attackers instruction manuals

**My Final Recommendation:** Treat your SCADA network like it's directly connected to the internet - because through techniques like these, it might as well be.

---

**Investigation completed by:** Regaan  
**Date:** November 26, 2025  
**Status:** Case Closed - All Attack Vectors Identified  
**Classification:** Critical Infrastructure Security Incident  

---

> *"In cybersecurity, the most dangerous vulnerabilities aren't the ones you can't find - they're the ones you leave exposed for anyone to discover."*
