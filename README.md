# Windows Privilege Escalation Surface Scanner

**Author:** Sahaj Malla  
**Language:** PowerShell  
**Type:** Defensive Security / Enumeration Tool

## 🚀 Overview

This project is a lightweight **Windows Privilege Escalation Surface Scanner**. It is designed to identify two specific, high-risk attack vectors often used by attackers to escalate privileges from a standard User to `SYSTEM` level:

1.  **Weak Named Pipe Permissions** (Impersonation Attacks)
2.  **Vulnerable Third-Party Kernel Drivers** (BYOVD - Bring Your Own Vulnerable Driver)

This tool is purely for **educational analysis and defensive auditing**. It helps security researchers and administrators find "open doors" before attackers do.

---

## 🧠 The Vulnerabilities Explained

### 1. Named Pipe Impersonation ("The Open Backdoor")
**The Concept:** Named Pipes are mechanisms for processes to talk to each other locally.
* **The Flaw:** If a privileged service (like an Antivirus) creates a pipe with a **Weak ACL** (e.g., "Everyone" can Write) and connects to user requests without checking for **Impersonation Levels**, it creates a vulnerability.
* **The Exploit:** An attacker creates a malicious pipe server. They trick a `SYSTEM` service into connecting to it. The attacker then uses `ImpersonateNamedPipeClient()` to steal the service's `SYSTEM` token, effectively becoming the administrator.

### 2. Kernel Driver IOCTL ("The Confused Deputy")
**The Concept:** Drivers operate in **Kernel Mode (Ring 0)** with full access to hardware and memory. They talk to user apps via **IOCTL** (Input/Output Control) codes.
* **The Flaw:** Many third-party drivers (Antivirus, GPU, Gaming utilities) fail to validate user input. They blindly trust pointers provided by the user.
* **The Exploit:** An attacker sends a malicious IOCTL request saying, "Write this data to this memory address." If the driver doesn't check the address (`ProbeForWrite`), it acts as a "confused deputy," overwriting critical kernel memory (like the Token list) to grant the attacker root privileges.



---

## 💻 How to Use

1.  **Open PowerShell as Administrator** (Required to read System ACLs).
2.  **Enable Script Execution** (for this session only):
    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    ```
3.  **Run the Scanner:**
    ```powershell
    .\PrivEscScanner.ps1
    ```

### Interpreting Results
* **[!] WEAK PIPE FOUND (Red):** These are potential entry points for Impersonation attacks.
* **[*] Loaded Driver (Yellow):** These are non-Microsoft drivers. Security researchers would target these for Reverse Engineering (using IDA Pro) to find IOCTL bugs.

---

## 🛡️ Mitigation (The Fix)

How do developers prevent these bugs?

**1. Fixing Named Pipes:**
Clients connecting to pipes should forbid impersonation using the `SECURITY_IDENTIFICATION` flag.
```cpp
// Secure Connection in C++
CreateFile(..., SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, ...);
