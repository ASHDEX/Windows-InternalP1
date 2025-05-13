# 🛡️ **Virtualization-Based Security (VBS) in Windows**

**VBS** creates a new memory-isolated environment inside Windows by using the **Hyper-V hypervisor**.

- Normally, Windows runs all user-mode and kernel-mode code in the same trust boundary.
    
- With VBS, parts of the operating system, sensitive services, and sensitive memory (like credentials, keys, etc.) are **protected** from the normal operating system — even if the OS kernel is compromised.
    

VBS introduces **Virtual Trust Levels (VTLs)**:

- **VTL 0**: Normal world (Windows Kernel, drivers, user applications).
    
- **VTL 1**: Secure world (Secure Kernel and Trustlets).
    

The Secure Kernel operates at VTL 1 and acts almost like a microkernel specialized in **security enforcement**.

---

# 🔒 **Device Guard and Credential Guard**

Two key security features built on VBS:

- **Device Guard**: Prevents unauthorized code from running, protects kernel integrity.
    
- **Credential Guard**: Protects authentication secrets (like NTLM hashes and Kerberos tickets) by isolating them inside VTL 1 — making it inaccessible to malware even if the rest of Windows is compromised.
    

---

# 🧩 **What are Trustlets?**

Trustlets are **user-mode isolated applications** running inside **Isolated User Mode (IUM)** within VTL 1.

Think of them as **mini-programs** specially designed to:

- Be super minimal and secure.
    
- Only perform trusted operations.
    
- Only talk to the Secure Kernel, not the normal OS.
    

---

# 📦 **Structure of a Trustlet**

1. **PE File** (Portable Executable — like any .exe or .dll).
    
2. **Restricted Imports**: Only allowed to import from very limited Windows system libraries:
    
    - `ntdll.dll`
        
    - `kernelbase.dll`
        
    - `advapi32.dll`
        
    - `rpcrt4.dll` (RPC Runtime)
        
    - `bcryptprimitives.dll` (Crypto)
        
    - `c runtime (ucrtbase.dll)`
        
3. **Iumbase.dll**: Special library provided by Secure Kernel for system services like:
    
    - Mailslots
        
    - Cryptographic services
        
    - Secure storage APIs
        
4. **Policy Metadata** (`.tPolicy` section):
    
    - Embedded structure `s_IumPolicyMetadata`.
        
    - Contains:
        
        - Trustlet ID
            
        - Allowed capabilities
            
        - Policy settings (e.g., if crash dumps are allowed)
            
        - Version control
            
5. **Certificate with IUM EKU**:
    
    - Trustlets must be digitally signed.
        
    - Special Enhanced Key Usage (EKU): `1.3.6.1.4.311.10.3.37`
        
    - Prevents tampering — any change invalidates signature.
        

---

# 🛫 **How is a Trustlet Launched?**

Windows doesn’t launch Trustlets the normal way.

Instead:

- **CreateProcess** is called with special parameters (`PS_CP_SECURE_PROCESS`).
    
- Must specify Trustlet ID in the launch attributes.
    
- The Secure Kernel verifies:
    
    - The executable's Trustlet ID matches policy metadata.
        
    - The digital signature is valid.
        

✅ Only then is the Trustlet allowed to launch inside **IUM**.

---

# 🧬 **Trustlet Identity Mechanisms**

Each Trustlet has multiple types of identities:

|Identity|Description|
|---|---|
|**Trustlet ID**|Hardcoded number unique per Trustlet.|
|**Trustlet Instance ID**|Random 16-byte number generated at runtime for isolation.|
|**Collaboration ID**|Allows different Trustlets or instances to share storage.|
|**Security Version Number (SVN)**|Versioning for cryptographic signing (important for proving trust).|
|**Scenario ID**|Used when creating shared secure kernel objects, like shared sections.|

📝 These IDs ensure that Trustlets are:

- Strictly isolated.
    
- Controlled.
    
- Secure in their interactions.
    

---

# 🛠️ **What Can Trustlets Do? (Services They Access)**

Trustlets have access to **special Secure Kernel APIs** that normal processes cannot touch.

|Service|Purpose|
|---|---|
|**Secure Devices**|Access secure ACPI/PCI devices (e.g., biometric sensors).|
|**Secure Sections**|Share memory securely within/between Trustlets.|
|**Mailboxes**|Simple communication with VTL 0 components (up to 4 KB slots).|
|**Identity Keys (IDK)**|Get unique machine-specific encryption/signing keys.|
|**Cryptographic Services**|Encrypt/decrypt, generate random numbers, verify trust measurements.|
|**Secure Storage**|Save/retrieve secure blobs of data tied to Trustlet identity.|

These services support major Windows features like:

- Windows Hello Secure Biometrics
    
- Virtual TPM (vTPM)
    
- Credential Guard secure secrets storage
    

---

# 🔧 **Additional System APIs Available to Trustlets**

Trustlets also need basic operating system functionality. The Secure Kernel provides **limited**, **sanitized** versions of:

- Thread management
    
- Memory allocation
    
- IPC (Advanced Local Procedure Calls — ALPC)
    
- Basic synchronization (events, semaphores)
    
- Secure Boot information access
    
- Exception handling
    
- TLS slot management (needed for thread-specific data)
    

**Important**:  
They **cannot**:

- Load arbitrary DLLs.
    
- Access normal file system.
    
- Perform registry operations.
    
- Make unrestricted system calls.
    

---

# 🔥 **Key Security Properties**

- **Immutability**: Changing the policy metadata corrupts the Trustlet's signature → Windows refuses to run it.
    
- **Isolation**: Trustlets run in a separate trust level (VTL 1) under Secure Kernel control.
    
- **Verification**: Launch attributes and signed metadata ensure only trusted code can run.
    
- **Limited Surface**: Only carefully allowed system calls prevent attack surfaces.
    

---

# 🧠 **Summary**

|Concept|Details|
|---|---|
|**VBS**|Creates isolated memory spaces using the hypervisor.|
|**Secure Kernel**|Microkernel that controls VTL 1, enforces security.|
|**Trustlets**|Minimal, signed, tightly controlled user-mode processes running inside IUM (VTL 1).|
|**Launch**|Requires secure attributes, verified signatures, matching Trustlet IDs.|
|**Capabilities**|Secure devices, cryptography, storage, identity management, minimal system services.|
# 🛠️ **Visual Diagram**

Here's a **simple diagram** of how everything fits together:

plaintext

CopyEdit

`+-------------------------------------------------------------+ | Hypervisor (Hyper-V)                                         | |                                                             | | +----------------------+   +-----------------------------+ | | | Virtual Trust Level 0 |   | Virtual Trust Level 1 (VTL 1)| | | | (Normal Windows)      |   | (Secure Kernel + Trustlets)  | | | |                      |    |                             | | | | Windows Kernel        |   | SecureKernel.exe             | | | | Device Drivers        |   |                             | | | | Applications (e.g.,   |   |  +--- Trustlet: LsaIso.exe   | | | | Chrome, Word, etc.)    |   |  +--- Trustlet: SecureSystem| | | |                        |   |  +--- Trustlet: BioIso.exe  | | | +----------------------+   +-----------------------------+ | |                                                             | +-------------------------------------------------------------+`

---

# 🧠 **How the pieces interact**

- **Hyper-V** ensures that **VTL 0** and **VTL 1** memory spaces are isolated.
    
- **SecureKernel.exe** runs trusted services inside **VTL 1**.
    
- **Trustlets** (like **LsaIso.exe**) are launched and verified by Secure Kernel using secure signatures and attributes.
    
- Trustlets:
    
    - Can **communicate** only via tightly controlled channels.
        
    - Use **secure APIs** like `IumSecureStoragePut` or `IumGetIdk`.
        
    - Are **isolated** even from each other unless a **Collaboration ID** is shared.
        

**Normal apps or malware in VTL 0 cannot touch VTL 1!**  
Even with admin or SYSTEM rights.

---

# 🛡️ **Why This is Powerful**

✅ Prevents credential theft (no dumping LSASS memory anymore).  
✅ Protects sensitive devices (biometrics, TPM) from driver-level malware.  
✅ Enforces integrity: Trustlets can’t be tampered with or modified without invalidating the signature.  
✅ Reduces attack surface: Only minimal secure APIs are exposed.

---

# 📚 **Summary Table**

|Area|Description|
|---|---|
|**Hyper-V**|Provides the hypervisor layer for VBS isolation.|
|**VTL 0**|Regular Windows Kernel, Apps, Drivers (Normal World).|
|**VTL 1**|Secure Kernel + Trustlets (Isolated Secure World).|
|**Trustlets**|Minimal apps running inside VTL 1, protected, signed.|
|**Trustlet Examples**|LsaIso.exe, SecureSystem.exe, BioIso.exe, etc.|
|**API Examples**|Secure Device APIs, Secure Storage, Cryptographic Services|
# 🛡️ **Virtualization-Based Security (VBS) in Windows**

**VBS** creates a new memory-isolated environment inside Windows by using the **Hyper-V hypervisor**.

- Normally, Windows runs all user-mode and kernel-mode code in the same trust boundary.
    
- With VBS, parts of the operating system, sensitive services, and sensitive memory (like credentials, keys, etc.) are **protected** from the normal operating system — even if the OS kernel is compromised.
    

VBS introduces **Virtual Trust Levels (VTLs)**:

- **VTL 0**: Normal world (Windows Kernel, drivers, user applications).
    
- **VTL 1**: Secure world (Secure Kernel and Trustlets).
    

The Secure Kernel operates at VTL 1 and acts almost like a microkernel specialized in **security enforcement**.

---

# 🔒 **Device Guard and Credential Guard**

Two key security features built on VBS:

- **Device Guard**: Prevents unauthorized code from running, protects kernel integrity.
    
- **Credential Guard**: Protects authentication secrets (like NTLM hashes and Kerberos tickets) by isolating them inside VTL 1 — making it inaccessible to malware even if the rest of Windows is compromised.
    

---

# 🧩 **What are Trustlets?**

Trustlets are **user-mode isolated applications** running inside **Isolated User Mode (IUM)** within VTL 1.

Think of them as **mini-programs** specially designed to:

- Be super minimal and secure.
    
- Only perform trusted operations.
    
- Only talk to the Secure Kernel, not the normal OS.
    

---

# 📦 **Structure of a Trustlet**

1. **PE File** (Portable Executable — like any .exe or .dll).
    
2. **Restricted Imports**: Only allowed to import from very limited Windows system libraries:
    
    - `ntdll.dll`
        
    - `kernelbase.dll`
        
    - `advapi32.dll`
        
    - `rpcrt4.dll` (RPC Runtime)
        
    - `bcryptprimitives.dll` (Crypto)
        
    - `c runtime (ucrtbase.dll)`
        
3. **Iumbase.dll**: Special library provided by Secure Kernel for system services like:
    
    - Mailslots
        
    - Cryptographic services
        
    - Secure storage APIs
        
4. **Policy Metadata** (`.tPolicy` section):
    
    - Embedded structure `s_IumPolicyMetadata`.
        
    - Contains:
        
        - Trustlet ID
            
        - Allowed capabilities
            
        - Policy settings (e.g., if crash dumps are allowed)
            
        - Version control
            
5. **Certificate with IUM EKU**:
    
    - Trustlets must be digitally signed.
        
    - Special Enhanced Key Usage (EKU): `1.3.6.1.4.311.10.3.37`
        
    - Prevents tampering — any change invalidates signature.
        

---

# 🛫 **How is a Trustlet Launched?**

Windows doesn’t launch Trustlets the normal way.

Instead:

- **CreateProcess** is called with special parameters (`PS_CP_SECURE_PROCESS`).
    
- Must specify Trustlet ID in the launch attributes.
    
- The Secure Kernel verifies:
    
    - The executable's Trustlet ID matches policy metadata.
        
    - The digital signature is valid.
        

✅ Only then is the Trustlet allowed to launch inside **IUM**.

---

# 🧬 **Trustlet Identity Mechanisms**

Each Trustlet has multiple types of identities:

|Identity|Description|
|---|---|
|**Trustlet ID**|Hardcoded number unique per Trustlet.|
|**Trustlet Instance ID**|Random 16-byte number generated at runtime for isolation.|
|**Collaboration ID**|Allows different Trustlets or instances to share storage.|
|**Security Version Number (SVN)**|Versioning for cryptographic signing (important for proving trust).|
|**Scenario ID**|Used when creating shared secure kernel objects, like shared sections.|

📝 These IDs ensure that Trustlets are:

- Strictly isolated.
    
- Controlled.
    
- Secure in their interactions.
    

---

# 🛠️ **What Can Trustlets Do? (Services They Access)**

Trustlets have access to **special Secure Kernel APIs** that normal processes cannot touch.

|Service|Purpose|
|---|---|
|**Secure Devices**|Access secure ACPI/PCI devices (e.g., biometric sensors).|
|**Secure Sections**|Share memory securely within/between Trustlets.|
|**Mailboxes**|Simple communication with VTL 0 components (up to 4 KB slots).|
|**Identity Keys (IDK)**|Get unique machine-specific encryption/signing keys.|
|**Cryptographic Services**|Encrypt/decrypt, generate random numbers, verify trust measurements.|
|**Secure Storage**|Save/retrieve secure blobs of data tied to Trustlet identity.|

These services support major Windows features like:

- Windows Hello Secure Biometrics
    
- Virtual TPM (vTPM)
    
- Credential Guard secure secrets storage
    

---

# 🔧 **Additional System APIs Available to Trustlets**

Trustlets also need basic operating system functionality. The Secure Kernel provides **limited**, **sanitized** versions of:

- Thread management
    
- Memory allocation
    
- IPC (Advanced Local Procedure Calls — ALPC)
    
- Basic synchronization (events, semaphores)
    
- Secure Boot information access
    
- Exception handling
    
- TLS slot management (needed for thread-specific data)
    

**Important**:  
They **cannot**:

- Load arbitrary DLLs.
    
- Access normal file system.
    
- Perform registry operations.
    
- Make unrestricted system calls.
    

---

# 🔥 **Key Security Properties**

- **Immutability**: Changing the policy metadata corrupts the Trustlet's signature → Windows refuses to run it.
    
- **Isolation**: Trustlets run in a separate trust level (VTL 1) under Secure Kernel control.
    
- **Verification**: Launch attributes and signed metadata ensure only trusted code can run.
    
- **Limited Surface**: Only carefully allowed system calls prevent attack surfaces.
    

---

# 🧠 **Summary**

| Concept           | Details                                                                             |
| ----------------- | ----------------------------------------------------------------------------------- |
| **VBS**           | Creates isolated memory spaces using the hypervisor.                                |
| **Secure Kernel** | Microkernel that controls VTL 1, enforces security.                                 |
| **Trustlets**     | Minimal, signed, tightly controlled user-mode processes running inside IUM (VTL 1). |
| **Launch**        | Requires secure attributes, verified signatures, matching Trustlet IDs.             |
| **Capabilities**  | Secure devices, cryptography, storage, identity management, minimal system services |
# 🛡️ **Deep Dive: Trustlet Secure Services in VBS**

---

# 🔗 **1. Secure I/O (SecureIo APIs)**

**Functions:**

- `SecureIo`
    
- `IumProtectSecureIo`
    
- `IumQuerySecureDeviceInformation`
    
- `IopUnmapSecureIo`
    
- `IumUpdateSecureDeviceState`
    

### 🛠 Purpose:

Trustlets can interact **directly with hardware devices** like:

- ACPI devices (e.g., secure fingerprint readers)
    
- PCI devices (e.g., TPM chips, secure smart cards)
    

But these devices are **exclusively owned by the Secure Kernel** — VTL 0 drivers cannot access them directly.

Trustlets can:

- **Map registers** of a secure device into their VTL 1 address space.
    
- Perform **DMA (Direct Memory Access)** operations to interact with the device securely.
    

🧠 **Example**:  
A Trustlet acting as a **Secure USB Smartcard Reader** driver uses this to talk to a PCI-attached device in a secure way.

👉 Trustlets doing this are built using the **Secure Device Framework (SDF)** hosted in `SDFHost.dll`.

✅ **Secure Biometrics (Windows Hello)** heavily relies on this to interact with webcams, fingerprint sensors, etc.

---

# 📦 **2. Secure Sections (Memory Sharing)**

**Functions:**

- `IumCreateSecureSection`
    
- `IumFlushSecureSectionBuffers`
    
- `IumGetExposedSecureSection`
    
- `IumOpenSecureSection`
    

### 🛠 Purpose:

Secure Sections allow **secure memory sharing**.

- **Between VTL 1 Trustlets and VTL 0 drivers** (carefully exposed memory pages).
    
- **Between Trustlets** in VTL 1.
    

A Trustlet that wants to **share memory** needs to have the **Secure Section capability** defined in its **policy metadata**.

🧠 **Example**:  
Suppose a Trustlet wants to securely share biometric scan data with a VTL 0 driver — it uses a **Secure Section** to expose the data in a controlled way.

✅ **Key point**: VTL 0 access is **controlled by Secure Kernel**, not freely readable.

---

# ✉️ **3. Mailboxes (Lightweight Communication)**

**Function:**

- `IumPostMailbox`
    

### 🛠 Purpose:

Allows a Trustlet to set up **up to eight small mail slots** (~4 KB each).

- Data can be retrieved by VTL 0 components **using a secret mailbox key**.
    
- Provides **lightweight, secure communication** between a Trustlet and a normal kernel driver.
    

🧠 **Example**:

- `Vid.sys` (a normal Windows driver) in VTL 0 **retrieves secrets** (such as vTPM keys) from the `Vmsp.exe` Trustlet using mailboxes.
    

✅ Useful for passing small secrets or tokens securely.

---

# 🔑 **4. Identity Keys (IDKs)**

**Function:**

- `IumGetIdk`
    

### 🛠 Purpose:

Trustlets can retrieve **unique keys** bound to the machine.

- Either a **decryption key** or **signing key**.
    
- **Only retrievable inside VTL 1** by a trusted Trustlet.
    
- Not available to normal processes.
    

🧠 **Example**:  
Credential Guard uses **IDKs** to **uniquely encrypt credentials** so that even if the machine is cloned, the credentials remain protected.

✅ Helps **prove machine identity** and prevents replay or theft.

---

# 🔒 **5. Cryptographic Services (IumCrypto)**

**Function:**

- `IumCrypto`
    

### 🛠 Purpose:

Allows a Trustlet to:

- **Encrypt/decrypt** data using:
    
    - **Per-boot session keys**.
        
    - **Random numbers** generated by Secure Kernel.
        
- Obtain **TPM binding handles**.
    
- Check **Secure Kernel FIPS mode** (Federal Information Processing Standard compliance).
    
- Generate a **signed trust report** including:
    
    - SHA-2 hash
        
    - SVN (Security Version Number)
        
    - Debugger status
        
    - Metadata dump
        

🧠 **Example**:  
Before a Trustlet stores sensitive data, it can **cryptographically attest** itself — proving it hasn’t been tampered with.

✅ Works like a **TPM (Trusted Platform Module)** but at the **software Trustlet level**.

---

# 📂 **6. Secure Storage APIs**

**Functions:**

- `IumSecureStorageGet`
    
- `IumSecureStoragePut`
    

### 🛠 Purpose:

Trustlets can **save** and **retrieve** **secure storage blobs** (encrypted data).

- Scoped either by:
    
    - **Trustlet Instance ID** (unique per instance).
        
    - **Collaboration ID** (shared between trusted Trustlets).
        

🧠 **Example**:  
Credential Guard may **store user credentials** in a **secure blob** accessible only to **that running Trustlet** or a trusted group.

✅ **Isolated and encrypted**, even if the disk is stolen or the OS is compromised.

---

# 📚 **Summary of Services**

|Category|API Functions|Purpose|
|---|---|---|
|Secure Devices|SecureIo, IumProtectSecureIo, etc.|Access secure PCI/ACPI devices securely.|
|Secure Sections|IumCreateSecureSection, etc.|Share memory securely with VTL 0 or within VTL 1.|
|Mailboxes|IumPostMailbox|Share small secrets with VTL 0 components.|
|Identity Keys|IumGetIdk|Obtain unique machine-bound keys.|
|Cryptography|IumCrypto|Securely encrypt/decrypt, attest Trustlets.|
|Secure Storage|IumSecureStorageGet/Put|Store/retrieve protected data blobs.|
# 🛡️ **How a Trustlet is Launched and Attested in Windows VBS**

---

# 1. **Request to Launch Trustlet**

A **trusted Windows component** (like LSASS for `LsaIso.exe`) calls **CreateProcess** —  
but **not the normal way**.  
Instead, it uses a special process attribute:

- `PS_ATTRIBUTE_SECURE_PROCESS`
    
- Along with a **Trustlet launch structure**.
    

This launch structure includes:

- Trustlet's intended **Trustlet ID** (e.g., 1 for `LsaIso.exe`).
    
- Trustlet's **Signing Level**.
    
- Extra Secure Launch flags (such as disabling crash dumps if needed).
    

---

# 2. **Secure Kernel Intercepts the Launch**

The request **goes to the Secure Kernel** inside VTL 1.  
It **pauses** the normal launch and begins **validation**.

The Secure Kernel does the following:

|Check|Details|
|---|---|
|**Signature Verification**|It checks if the Trustlet executable is **properly signed** with a certificate containing the **IUM EKU** (`1.3.6.1.4.311.10.3.37`).|
|**Policy Metadata Extraction**|It parses the `.tPolicy` section to read `s_IumPolicyMetadata`.|
|**Trustlet ID Match**|The ID in the process attribute must match the ID in policy metadata.|
|**Security Options**|Validates the policy options — e.g., whether debugging is allowed.|
|**Security Version Number (SVN)**|For Trustlets needing cryptographic proof (Credential Guard, TPM services).|

✅ If all checks pass, the launch continues.  
❌ If any check fails (e.g., wrong signature, ID mismatch), **launch is aborted**.

---

# 3. **Trustlet Instance Created**

The Secure Kernel then:

- Generates a **16-byte random Trustlet Instance ID**.
    
- (Optional) Sets a **Collaboration ID** if collaboration is allowed.
    

This instance ID is **unique** per launch and ties the Trustlet securely to:

- Its own storage (Secure Storage).
    
- Its own device access.
    
- Its cryptographic operations.
    

---

# 4. **Secure Process Container Created**

The Trustlet process:

- Is launched inside a **Secure User Mode (IUM) container**.
    
- Has a restricted set of permissions:
    
    - **Cannot access normal system resources** (no unrestricted file system, no arbitrary memory access).
        
    - **Only allowed limited sanitized system calls** through `Iumbase.dll` to the Secure Kernel.
        

---

# 5. **Secure Services Initialization**

The Trustlet can now initialize:

- Secure Storage blobs (protected with the instance ID).
    
- Secure Device mappings (if it's a hardware-interfacing Trustlet).
    
- Secure Mailboxes for small communications.
    
- Cryptographic operations via Secure Kernel random numbers, IDKs.
    

---

# 6. **Attestation and Measurement (Optional)**

Some sensitive Trustlets (e.g., Credential Guard) perform **self-attestation**:

- Call `IumCrypto` services.
    
- Generate an **IDK-signed** report.
    
- Report includes:
    
    - SHA-2 Hash of Trustlet code
        
    - Trustlet ID
        
    - SVN (Security Version)
        
    - Debugger attachment status
        
    - Policy metadata dump
        
    - Optional custom Trustlet data
        

This **cryptographic measurement** can be:

- Sent to a remote system (e.g., a domain controller) to **prove integrity**.
    
- Used locally to **ensure no tampering** occurred.
    

✅ It acts like a **software TPM attestation** for Trustlets.

---

# 7. **Trustlet Starts Working**

Finally, the Trustlet can:

- Serve its function (like isolating credentials for Credential Guard).
    
- Perform cryptographic work.
    
- Access secure devices.
    
- Communicate (securely) with VTL 0 components if needed (only through secure APIs).
    

---

# 📈 **Complete Launch Flow Summary**

plaintext

CopyEdit

`[Launch Request with PS_ATTRIBUTE_SECURE_PROCESS]          ↓ [Secure Kernel Verifies Signature, Trustlet ID, Policy]         ↓ [Secure Kernel Creates Trustlet Instance ID]         ↓ [Secure Container Process Created]         ↓ [Trustlet Initializes Secure Storage, Devices, Crypto]         ↓ [Trustlet Optionally Attests Itself]         ↓ [Trustlet Begins Secure Operations inside VTL 1]`

---

# 🧠 **Key Security Concepts Achieved**

✅ **Tamper-resistance**: Trustlet’s code and configuration are cryptographically verified.  
✅ **Isolation**: Trustlets run in VTL 1 and can’t be accessed from VTL 0.  
✅ **Integrity measurement**: Cryptographic report proves the Trustlet is legitimate.  
✅ **Controlled access**: Trustlets can only do specific, safe operations — no arbitrary behavio

# 🧨 **Typical Attack: Dumping LSASS to Steal Passwords**

In older (non-VBS) Windows versions, attackers often:

- Gain **Admin** or even **SYSTEM** privileges.
    
- Use tools like **Mimikatz** or **ProcDump**.
    
- **Attach to LSASS.exe** (Local Security Authority Subsystem Service).
    
- **Dump its memory**, extract:
    
    - NTLM password hashes
        
    - Kerberos tickets
        
    - Cleartext passwords
        

👹 **Result**: Full compromise of the machine and sometimes the entire network/domain.

---

# 🛡️ **How Credential Guard Trustlet Stops This**

In Windows 10/11 with VBS + Credential Guard enabled:

|Step|Normal System (without VBS)|VBS System (Credential Guard)|
|---|---|---|
|**1. Malware gains SYSTEM rights**|✅ Malware can access anything.|✅ Malware gains SYSTEM but...|
|**2. Malware targets LSASS.exe**|✅ LSASS stores secrets in normal memory.|🚫 **Secrets are NOT in LSASS anymore!**|
|**3. Secrets Access**|✅ Memory dump succeeds; passwords stolen.|🚫 Memory dump of LSASS shows **nothing useful**.|
|**4. Why?**|LSASS had direct credential storage.|Credentials are isolated inside **LsaIso.exe Trustlet** running in VTL 1.|
|**5. Malware tries VTL 1 attack**|N/A (no isolation).|🚫 Malware is stuck in VTL 0. Hypervisor stops access to VTL 1 memory.|

---

# 🔥 **Detailed Flow: Why Malware Fails**

1. **Normal LSASS.exe process** still runs, but...
    
2. When authentication material (e.g., Kerberos tickets, passwords) is needed:
    
    - LSASS **asks LsaIso.exe** running inside **VTL 1**.
        
    - Secrets **never exist in normal Windows memory**.
        
3. LsaIso.exe:
    
    - Runs as a **Trustlet**.
        
    - Memory mapped only in **VTL 1** (normal drivers, processes, kernel code in VTL 0 can't see it).
        
4. Even if malware:
    
    - Has SYSTEM.
        
    - Injects into LSASS.exe.
        
    - Hooks system calls.
        
    
    👉 It **still cannot**:
    
    - Read the secrets.
        
    - Hook the Trustlet.
        
    - Access VTL 1 memory.
        
5. The **Hypervisor** hardware-enforces the boundary:  
    **VTL 0 cannot read/write VTL 1 memory. Period.**
    

---

# 🔍 **Visualization: Attack Fails**

plaintext

CopyEdit

`Malware in VTL 0  ─────►  Attempts Memory Read ─────►  [BLOCKED]                                                   │                                                   ▼ LsaIso.exe (Trustlet) in VTL 1 ─ Secrets are safe`

✅ No passwords stolen.  
✅ No NTLM hashes extracted.  
✅ No Kerberos tickets hijacked.

---

# 🧠 **Why It's So Powerful**

- Even with **full admin rights**, the attacker cannot reach **VTL 1 memory**.
    
- No more "dump LSASS and rule the domain."
    
- Shifts Windows security to a **hardware-enforced boundary** — not just software defenses.
    
- Malware must now either:
    
    - Break Hyper-V (extremely difficult).
        
    - Find vulnerabilities in Trustlets (very rare, due to their minimal design).
        

---

# 🚀 **Summary**

|Feature|Impact|
|---|---|
|Trustlets|Isolate sensitive operations.|
|Secure Kernel|Enforces VTL isolation.|
|Credential Guard|Moves credentials out of LSASS.exe into LsaIso.exe Trustlet.|
|Attack Result|Malware fails to dump credentials even with SYSTEM rights.|
