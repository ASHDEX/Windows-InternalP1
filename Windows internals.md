
### Explanation of `CreateProcess`

`CreateProcess` is a Windows API function used to create a new process and its primary thread. The statement implies:

- **Simplicity**: `CreateProcess` is considered the most straightforward method to spawn a new process.
    
- **Access Token**: By default, the new process uses the same access token (i.e., security context) as the calling process, unless explicitly specified otherwise.
    

This is in contrast to other more advanced process creation methods, such as:

- `CreateProcessAsUser`: lets you specify a different user token.
    
- `CreateProcessWithTokenW`: similar, but works only on Vista+ and requires specific privileges.
    
- `NtCreateUserProcess`: a lower-level (and more complex) native API used internally by Windows.
### **Expectations of Process Creation APIs**

Functions like:

- `CreateProcess`
    
- `CreateProcessAsUser`
    
- `CreateProcessWithTokenW`
    
- `NtCreateUserProcess`
    

...all require the **target file to be a valid Portable Executable (PE)**—which includes:

- `.exe` files (even without the `.exe` extension explicitly used)
    
- Batch files (`.bat`)
    
- 16-bit `.com` applications
    

These APIs **do not** interpret non-executable files like `.txt` or `.docx` in terms of what application should open them.


### **Role of the Windows Shell**

This is where **`ShellExecute`** and **`ShellExecuteEx`** come in:

- They **abstract the logic of “open this file with the right app”**, based on:
    
    - File **extension**
        
    - Windows **registry configuration** under:
        
        nginx
        
        CopyEdit
        
        `HKEY_CLASSES_ROOT`
        
- Example: Opening `file.txt` will automatically associate it with `Notepad.exe`, if the registry is configured accordingly.



### **ShellExecute → CreateProcess → NtCreateUserProcess**

The flow:

1. **User invokes** `ShellExecute("file.txt")`
    
2. Shell figures out it should run `Notepad.exe file.txt`
    
3. It internally constructs a command like:
    
    c
    
    CopyEdit
    
    `Notepad.exe file.txt`
    
4. Then, it **calls `CreateProcess`**, which in turn:
    
5. Invokes **`CreateProcessInternal`**, a private API
    
6. Which finally calls **`NtCreateUserProcess`** (exported from `ntdll.dll`) to transition to **kernel mode**.
    

---

## 🔍 Additional Notes

- `CreateProcessInternal` is **not documented for public use**—it's a private internal API used by higher-level wrappers.
    
- `NtCreateUserProcess` is a **Native API** and part of **Ntdll.dll**—not meant to be used directly by applications but is accessible via tools like Sysinternals or reverse engineering.

## Key Parameters of `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithTokenW`, and `CreateProcessWithLogonW`

### 1. **Security Token**

- `CreateProcessAsUser` and `CreateProcessWithTokenW` require a **token handle**, which determines **under whose security context** the new process runs.
    
- `CreateProcessWithLogonW` instead takes a:
    
    - **Username**
        
    - **Domain**
        
    - **Password**
        

This allows for impersonation and privilege separation.

---

### 2. **Executable Path and Command-Line Arguments**

- Critical for locating and running the desired binary.
    
- The `lpApplicationName` and `lpCommandLine` parameters specify what to launch and how.
    

---

### 3. **Security Attributes**

- Define security descriptors for:
    
    - The **process object**
        
    - The **thread object**
        
- These determine who can access or manipulate them.
    

---

### 4. **Handle Inheritance Flag**

- A **Boolean flag** determines whether handles in the creating process that are marked **`bInheritHandle = TRUE`** should be inherited by the new process.
    
- Relevant to resource sharing like files, pipes, or sockets.
    
- Related documentation: _Chapter 8, “System mechanisms”_ (covers handle tables and inheritance rule
- .
### `CREATE_SUSPENDED`

- The new thread is **created but paused**.
    
- The parent must explicitly call `ResumeThread()` to start it.
    

### - `DEBUG_PROCESS`

- The creating process **acts as a debugger** for the new process.
    
- It will receive debug events like breakpoints or exceptions.
    

### - `EXTENDED_STARTUPINFO_PRESENT`

- Indicates use of the **`STARTUPINFOEX`** structure (instead of plain `STARTUPINFO`).
    
- Allows setting **advanced attributes**, often used with process mitigation policies or AppContainers.


## 🌐 Environment and Directory

- **Environment block**:
    
    - Can be custom or inherited from the parent process.
        
- **Current directory**:
    
    - If not specified, the child inherits the parent’s working directory.
        
    - Used when loading DLLs or files without absolute paths.
        

---

## 🧱 STARTUPINFO / STARTUPINFOEX Structures

### `STARTUPINFO`

- Defines window appearance, standard handles, and other UI properties for console or GUI apps.
    

### `STARTUPINFOEX`

- Extends `STARTUPINFO` with **attribute lists**, including:
    
    - Process mitigation options
        
    - Handle inheritance lists
        
    - AppContainer information
        
    - Pseudo-console attachment
        
- Attributes are populated via `UpdateProcThreadAttribute()`


## 📦 PROCESS_INFORMATION Structure

Returned by the API and includes:

- `hProcess`: handle to the new process
    
- `hThread`: handle to the primary thread
    
- `dwProcessId`: new process ID
    
- `dwThreadId`: new thread ID
    

These handles allow the parent process to:

- Suspend/resume threads
    
- Query exit codes
    
- Terminate the process, etc.

## Creating a Modern (Store/UWP) Application Process

### ✅ Traditional Process Creation ≠ Sufficient

Calling `CreateProcess()` alone **does not work** for launching **modern Windows Store apps** (formerly known as Metro/Universal Windows Platform apps). These apps are managed by the Windows app model and require **additional metadata and environment configuration**.

---

## 🧩 Key Requirements for Store App Process Creation

### 1. **Mandatory Command-Line Arguments**

Many Store apps expect specific command-line parameters—such as the **AppUserModelId**, **activation context**, or **launching arguments**—otherwise they may fail silently.

### 2. **Undocumented Process Attribute**

To successfully start a Store app via `CreateProcess`, a **specific process attribute** must be used:

c

CopyEdit

`PROC_THREAD_ATTRIBUTE_PACKAGE_FULL_NAME`

- This is set using `UpdateProcThreadAttribute`.
    
- The attribute holds the **full name of the application package** (Store app).
    
- It's **undocumented** in official Microsoft API docs but known from reverse engineering and tools like Process Monitor or internal sources.
    

Without this attribute, Store apps won’t launch properly due to security and sandboxing constraints.

---

## 🧱 COM-Based Alternative: `IApplicationActivationManager`

Microsoft provides an **official and supported way** to launch Store apps through a **COM interface**:

### `IApplicationActivationManager`

- Found in `ShObjIdl.h`
    
- Implemented by the **`CLSID_ApplicationActivationManager`** COM class
    

### Key Method: `ActivateApplication`

cpp

CopyEdit

`HRESULT ActivateApplication(   LPCWSTR appUserModelId,   LPCWSTR arguments,   ACTIVATEOPTIONS options,   DWORD *processId );`

#### Parameters:

- **`appUserModelId`**: Logical identifier of the app (resolvable from the package name)
    
- **`arguments`**: Optional arguments passed to the app
    
- **`options`**: Launch flags
    
- **`processId`**: Receives the PID of the launched process
    

---

## 🔄 Mapping Package to AppUserModelId

To get the **AppUserModelId** (needed for `ActivateApplication()`), you typically call functions like:

- `GetAppUserModelIdFromPackageFamilyName`
    
- Or enumerate installed packages via:
    
    - `PackageManager` API (for WinRT)
        
    - `SHQueryUserNotificationState` (less common)
        

This ID might look like:

text

CopyEdit

`Microsoft.WindowsCalculator_8wekyb3d8bbwe!App`


## 🔁 Universal Endpoint: All Roads Lead to Psp*

Regardless of how a process is created:

- User-mode via `CreateProcess`
    
- Native process via `RtlCreateUserProcess`
    
- WSL via Pico provider
    
- PowerShell via WMI
    
- Even from a kernel driver
    

**Eventually**, the creation path **funnels into** `PspAllocateProcess` and `PspInsertProcess`.


## 🧱 Internal Representation: The EPROCESS Structure

Each active process in Windows is represented by a kernel-mode structure called **`EPROCESS`**, which resides in **system address space** and serves as the central data structure for the OS to manage processes.

### 🔑 Key Attributes of EPROCESS:

- Process identifiers (PID, parent PID)
    
- Access token (security context)
    
- Process flags and state
    
- Thread list head
    
- Handles to kernel and user-mode data structures
    

---

## 🔄 Related Structures and Subsystems

### 1. **ETHREAD**

- Every thread in the process is represented by an **ETHREAD** structure.
    
- Like EPROCESS, it exists in **system space**.
    
- Manages:
    
    - Thread state and priority
        
    - Kernel stack
        
    - Wait queues and synchronization objects
        

_(See Chapter 4: “Threads” for full details.)_

---

### 2. **PEB (Process Environment Block)**

- One **major exception** to system-space residency.
    
- Exists in **user-mode address space**, so that user-mode code can:
    
    - Access environment variables
        
    - Inspect loaded modules
        
    - Read command-line arguments
        
- Automatically initialized by the **loader** during process startup.
    

---

### 3. **Working Set List**

- Memory management structure.
    
- Stores pages actively being used by the process.
    
- Only valid in the **context of the current process**.
    
- Exists in process-specific system space.
    

_(See Chapter 5: “Memory Management” for deeper coverage.)_

---

## 🪟 Integration with Windows Subsystem Components

### 1. **CSR_PROCESS**

- A user-mode structure maintained by `Csrss.exe` (Client/Server Runtime Subsystem).
    
- Tracks:
    
    - Console windows
        
    - Subsystem-specific data
        
    - Process communication with Windows subsystem services
        

### 2. **W32PROCESS**

- Created in **kernel-mode** when a process calls a **USER or GDI function**.
    
- Triggers on functions like:
    
    - `CreateWindowEx()`
        
    - `GetMessage()`
        
- Stored in `Win32k.sys` and handles GUI thread management and windowing.
    

### 3. **DXGPROCESS**

- Initialized by `Dxgkrnl.sys` when a process uses **DirectX-based GDI or GPU acceleration**.
    
- Contains:
    
    - GPGPU usage data
        
    - Shader and buffer information
        
    - GPU memory management and scheduling metadata
        

---

## 🎯 Object Manager and Process Visibility

- **EPROCESS** structures are **wrapped as kernel "process objects"** by the Executive's **Object Manager**.
    
- Unlike named objects (files, events, etc.), **processes are unnamed**, and:
    
    - **Don’t show up** in tools like WinObj (Sysinternals)
        
    - But can be explored under `\ObjectTypes\Process` for type definitions
        

---

## 🔐 Process Handles and External Access

- A **handle** to a process exposes a limited view of the **EPROCESS** data, through APIs such as:
    
    - `OpenProcess`
        
    - `GetExitCodeProcess`
        
    - `ReadProcessMemory` / `WriteProcessMemory` (if permitted)
        

---

## 🛡️ Extensibility: Process Notifications and Monitoring

### 1. **Process-creation callbacks**

- Drivers and security components can register with:
    
    - `PsSetCreateProcessNotifyRoutine`
        
    - `PsSetCreateProcessNotifyRoutineEx`
        
    - `PsSetCreateProcessNotifyRoutineEx2`
        
- These allow third-party modules to:
    
    - Monitor process creation
        
    - Attach metadata
        
    - Maintain per-process state
        
    - **Block process creation** based on policies (e.g., anti-malware)
        

### 2. **Anti-malware Integration**

- Security tools can leverage this to:
    
    - Enforce hash-based blacklisting
        
    - Intercept suspicious process trees
        
    - Apply behavioral controls at process instantiation time
        

---

## 📏 Performance Consideration

The **overhead of a process** includes:

- EPROCESS and ETHREAD
    
- Subsystem structures like CSR_PROCESS, W32PROCESS, DXGPROCESS
    
- Third-party and driver-registered structures
    

While you **can’t directly measure total overhead**, it’s **non-trivial** and can affect system performance in environments with many concurrent processes (e.g., sandboxing platforms, security scanning systems).

---

## ✅ Summary

|Component|Description|Memory Scope|
|---|---|---|
|EPROCESS|Core process structure|Kernel-mode|
|ETHREAD|Per-thread structure|Kernel-mode|
|PEB|User-accessible process metadata|User-mode|
|Working Set List|Active memory page list|System per-process|
|CSR_PROCESS|Subsystem tracking (Csrss)|User-mode|
|W32PROCESS|GUI process tracking (Win32k.sys)|Kernel-mode|
|DXGPROCESS|GPU-related data (DirectX)|Kernel-mode|
## 🔐 What Are Protected Processes?

Protected Processes were introduced in **Windows Vista** and **Windows Server 2008** as a special type of process that enforces **additional security boundaries** beyond those of normal user-mode processes.

### ❗ Problem Addressed:

Under the traditional Windows security model, **administrators (or any user/process with `SeDebugPrivilege`)** could access virtually any other process on the system. This includes:

- Reading/writing memory
    
- Injecting code
    
- Suspending/resuming threads
    
- Querying information
    

This behavior, although logical for administrative control, is incompatible with **Digital Rights Management (DRM)** requirements from the media industry, which aim to **prevent unauthorized copying or inspection of high-value digital content**.

---

## 🛡 Key Characteristics of Protected Processes

- **Restricted Access**: Even processes running with administrator-level privileges cannot access protected processes in the usual ways (e.g., injecting code or reading memory).
    
- **Controlled Creation**: Only applications with binaries signed using a **Windows Media Certificate** can create true protected processes.
    
- **Media Foundation API**: Developers can utilize the **Media Foundation (MF)** API to create and manage protected processes for DRM-compliant media playback.
    

---

## 🧩 Use Cases and Examples

1. **Audio Device Graph Isolation (`audiodg.exe`)**
    
    - Used for decoding protected music content.
        
    - Runs as a protected process to prevent snooping or tampering during audio processing.
        
2. **Media Foundation Protected Pipeline (`mfpmp.exe`)**
    
    - Supports protected video playback pipelines.
        
    - Doesn't run by default, but when it does, it functions under the protected process model.
        
3. **Windows Error Reporting (`werfaultsecure.exe`)**
    
    - Special WER client that can access protected processes during crashes to generate reports.
        
4. **System Process (`System`)**
    
    - Marked as protected in part because components like `Ksecdd.sys` (kernel security support provider) store sensitive decryption material in kernel space.
        

---

## ⚙️ Protection Model Summary

|Aspect|Standard Process|Protected Process|
|---|---|---|
|Can be debugged by admin?|Yes|No|
|Can have memory read/written by another process?|Yes|No|
|Requires special digital certificate to run?|No|Yes (Windows Media Certificate)|
|Created by any application?|Yes|Only allowed under specific conditions|
## 🧠 Kernel-Level Architecture of Protected Processes

At the kernel level, Windows implements **robust mechanisms** to isolate protected processes from tampering—even from administrators and debugging tools. The protection mechanisms span **process creation flow**, **access control enforcement**, and **anti-tampering techniques**.

---

### 🔧 1. **Process Creation in Kernel Mode**

The creation of both standard and protected processes is primarily handled in **kernel mode** to:

- Prevent **user-mode code injection** attacks during process initialization.
    
- Maintain **security policy enforcement** by ensuring sensitive flags and attributes (e.g., those in `EPROCESS`) are set securely and atomically.
    

---

### 🔐 2. **EPROCESS Flags for Protection**

The `EPROCESS` structure—used internally by the kernel to represent a process—contains special **protection bits**:

- These bits **alter standard access control behavior**.
    
- When set, they restrict user-mode access by overriding **normal discretionary access control (DAC)** permissions.
    
- Even if a token has `SeDebugPrivilege`, **most access rights are denied** to the process unless explicitly allowed.
    

---

### 📋 3. **Allowed Access Rights**

Only a **limited set of permissions** is granted to external processes (even admin processes) for protected processes:

|Allowed Access Rights|Description|
|---|---|
|`PROCESS_QUERY_LIMITED_INFORMATION`|Allows querying limited metadata (e.g., name, PID).|
|`PROCESS_SET_LIMITED_INFORMATION`|Allows modifying basic settings (e.g., affinity).|
|`PROCESS_TERMINATE`|Allows terminating the process.|
|`PROCESS_SUSPEND_RESUME`|Allows suspending or resuming the process.|

➡️ For **threads within protected processes**, access is even more restricted (details provided in _Chapter 4 – Thread Internals_).

---

### 🧰 4. **Impact on Tools**

- **Process Explorer** and similar tools rely on **user-mode APIs**, which respect these access restrictions and thus **cannot fully inspect or control** protected processes.
    
- **WinDbg (in kernel mode)** can **bypass user-mode restrictions**, since it operates directly in kernel debugging context.
    

---

## ⚠️ 5. Security Bypass and Hardening Mechanisms

### ❗ Theoretical Bypass:

- An administrator could technically load a **malicious kernel-mode driver** to:
    
    - **Modify the `EPROCESS` flags** directly.
        
    - Bypass the protected process enforcement.
        

### 🚫 Why This Is Difficult (and Detectable):

1. **Code Signing Policy (64-bit Windows)**:
    
    - Windows enforces **mandatory driver signing**.
        
    - Malicious drivers are blocked or **require manual signature revocation** by Microsoft.
        
2. **PatchGuard (Kernel Patch Protection)**:
    
    - Monitors key kernel structures (like `EPROCESS`).
        
    - Detects and halts execution on unauthorized modification.
        
3. **Peauth.sys (Protected Environment and Authentication Driver)**:
    
    - Detects and reports tampering attempts.
        
    - Enforces **Protected Media Path (PMP)** policy compliance.
        
4. **Playback Policy Enforcement**:
    
    - Even on **32-bit systems**, the **media playback policy** checks for **recognized driver certificates**.
        
    - Unauthorized modifications may cause playback to **fail silently or halt**.
        

---

## 🔄 Summary: Why Protected Processes Are Secure

| Feature                      | Protection Impact                                                |
| ---------------------------- | ---------------------------------------------------------------- |
| Kernel-mode process creation | Prevents user-mode interference at creation time                 |
| EPROCESS flags               | Modifies access control checks for security enforcement          |
| Limited API access           | Restricts user-mode tools from querying/manipulating the process |
| PatchGuard and Peauth.sys    | Actively detect and report tampering attempts                    |
| Code-signing enforcement     | Prevents unauthorized kernel drivers from executing              |
## 🧱 What Are Protected Process Light (PPL) Processes?

**PPLs** are a refined variant of traditional **Protected Processes**, introduced to balance **security needs** with **functional flexibility**. Like their predecessors, PPLs prevent most forms of user-mode tampering (e.g., code injection, memory reads), but they introduce a more **granular trust model** based on **Signer attributes**.

---

## 🔒 Core Protection Properties

PPLs:

- **Block thread injection and memory inspection** by processes lacking equivalent or higher privileges—even from admin or SYSTEM-level code.
    
- **Restrict querying internal state**, such as loaded DLLs or handle tables.
    

This preserves **integrity and confidentiality**, especially for processes involved in:

- DRM
    
- Antivirus and security enforcement
    
- Windows licensing
    
- Store protection
    

---

## 🧾 The Signer Trust Hierarchy

The major difference between **classic protected processes** and **PPLs** is the **Signer-based hierarchy**, which introduces **differentiated levels of protection**.

### ✳️ Each PPL has a `Signer` attribute:

- This defines its **trust level**.
    
- A **higher-value Signer** can access or even terminate a **lower-value Signer**.
    
- This allows the system to establish **layered trust**.
    

### 🔝 Key Signer Levels (from highest to lowest):

|Signer|Description|Examples|
|---|---|---|
|`WinSystem`|Highest privilege; kernel-level components.|`System`, `Memory Compression`|
|`WinTCB` (Trusted Computing Base)|Highest trust for user-mode; closely tied to kernel.|`LSASS`, `Winlogon`|
|`WinTrustedInstaller`|Used for Windows servicing.|`TrustedInstaller.exe`|
|`WinStore`|For Windows Store DRM.|UWP apps with Store protections|
|`Antimalware`|Security & AV vendors.|Defender, 3rd-party AV software|
|`Lsa`|Local Security Authority.|Credentials, secure auth|
|`Windows`|General Microsoft-signed apps.|Media Foundation|
|`App`|Least trusted; signed apps.|Generic signed user apps|

---

## 📏 Access Control Rules Based on Signers

Access rights are determined by **comparing Signer values** between two processes:

### 🔒 General Rule:

- **Lower-level Signer PPLs cannot access higher ones**.
    
- **Higher-level Signers can access lower ones**, depending on allowed access masks.
    

### ❗ Specific Restrictions:

- For many lower Signers, access is limited to:
    
    - `PROCESS_QUERY_LIMITED_INFORMATION`
        
    - `PROCESS_SET_LIMITED_INFORMATION`
        
    - `PROCESS_SUSPEND_RESUME`
        
- **`PROCESS_TERMINATE`** is **denied** to many PPLs, unless the caller has a **higher or equivalent Signer level**.
    

This enforces a **hierarchical security model** where **critical infrastructure processes** (like `LSASS`) are not vulnerable to lower-trust processes—even if those run with administrator rights.

---

## 🔁 Interaction with Traditional Protected Processes

- **Classic Protected Processes (PP)** are still **more secure** than any PPL.
    
- **PPLs exist to provide compatibility and scalability**—offering protections without the strict certificate requirements of PP.
    
- PP and PPL cannot be escalated to each other dynamically—**their nature is fixed at process creation**.
    

---

## ⚙️ Real-World Examples

|Process|Protection Type|Signer|
|---|---|---|
|`System`|PP|`WinSystem`|
|`LSASS`|PPL|`WinTCB`|
|`MsMpEng.exe` (Defender)|PPL|`Antimalware`|
|`audiodg.exe`|PP|`Windows`|
|`mfpmp.exe`|PP|`Windows`|
|UWP DRM app|PPL|`WinStore`|

---

## 🛡 Summary: PPL vs PP

|Feature|Protected Process (PP)|Protected Process Light (PPL)|
|---|---|---|
|Introduced|Vista/Server 2008|Windows 8.1 / Server 2012 R2|
|Requires special certificate|Yes|No (uses signer model)|
|Trust model|Binary (protected or not)|Hierarchical (signer-based)|
|Use cases|DRM core playback|AV, system protection, store|
|Flexibility for ISVs|Low|High|
## How Does Windows Prevent Forged Protected Processes?

The concern is legitimate: if **any process** could **claim to be protected**, malware authors could easily **shield malicious code from antivirus (AV) software**. To mitigate this, **Microsoft uses Code Integrity and certificate-based enforcement**, with **specific requirements** at the digital signature level.

---

## 🔑 Key Enforcement Mechanisms

### 1. **Code Integrity (CI) Policy**

Microsoft extended its **Code Integrity (CI) module** to validate a set of **Enhanced Key Usage (EKU) Object Identifiers (OIDs)** within a code-signing certificate. These EKUs **authenticate the process's signer identity**.

### 2. **EKU OIDs Required for PPL**

Two main EKUs signal the intent to run as a PPL:

|EKU OID|Purpose|
|---|---|
|`1.3.6.1.4.1.311.10.3.22`|Identifies binaries eligible for Protected Process Light|
|`1.3.6.1.4.1.311.10.3.20`|Secondary PPL eligibility tag (legacy compatibility)|

These OIDs must be **explicitly embedded** in the code-signing certificate used to sign the executable.

---

## 🪪 Signer Validation Logic

Simply having an EKU is **not enough**. The **Signer and Issuer strings** must also meet **hardcoded trust criteria** within Windows.

For example:

- To be assigned the **`PsProtectedSignerWindows`** level:
    
    - The **Issuer** must be _Microsoft Windows_.
        
    - The **EKU** `1.3.6.1.4.1.311.10.3.6` (Windows System Component Verification) must also be present.
        

This tightly couples **certificate subject, issuer, and usage purpose**—making it impossible for an attacker to generate a valid signature without access to **Microsoft's private signing infrastructure**.

---

## 🧰 Protection Summary: Why Malware Can't Abuse PPL

|Security Mechanism|Purpose|
|---|---|
|EKU OIDs|Explicitly restrict PPL eligibility to vetted certificates|
|Signer/Issuer Match|Ensures only Microsoft-signed binaries can claim high-trust signer values|
|Code Integrity|Validates the signature and policy before assigning PPL status|
|Kernel enforcement|Enforces PPL status at process creation—can't be spoofed post-launch|

These validations occur **before the process is fully initialized**, ensuring the **kernel assigns PPL attributes only to trusted, signed code**.

---

## 🔍 Real-World Implication

Antivirus engines, Windows Defender, and security software can:

- **Safely ignore PPL attributes** unless the signer is valid.
    
- **Detect malicious binaries** attempting to misuse or spoof PPL markers.
    
- Trust the **PPL designation only if validated through Code Integrity**.


## 🧬 DLL Loading Constraints for Protected Processes

A core risk with any protected or sensitive process is **DLL injection or replacement**. If a malicious DLL were loaded into such a process:

- It would execute **with the same privileges and protection level**.
    
- It could **bypass security**, **manipulate execution**, or even **disable system integrity controls**.
    

To mitigate this, Windows implements a **DLL Signature Level enforcement** mechanism tightly coupled with the **process’s protection level**.

---

## 🧾 SignatureLevel and SectionSignatureLevel

Within the kernel's `EPROCESS` structure:

|Field|Description|
|---|---|
|`SignatureLevel`|Indicates the **code-signing trust level** of the main executable.|
|`SectionSignatureLevel`|Represents the **minimum allowed signature level** for any DLL loaded into the process.|

These levels are **evaluated by the Code Integrity (CI)** system **before loading a DLL**, much like verifying the main binary.

---

## 🔐 Protection Level Impact on DLL Loading

When a process runs with a **high trust level**—for example, as a **PPL with `WinTcb` signer**—Windows will:

- Restrict DLL loading to only those **signed at the same or higher level** (e.g., `Windows`, `WinTcb`, `WinSystem`).
    
- Prevent the use of third-party or unsigned libraries—even those from admins.
    

This prevents:

- **Logic bugs** from being exploited.
    
- **Malicious file replacement (plating)** where a benign DLL is replaced with a harmful one.
    
- **Low-trust services from tampering** with system-critical components.
    

---

## 🛡 Examples of PPL-Enforced DLL Loading

On **Windows 10 and Windows Server 2016**, certain critical binaries are **PPL-signed with `WinTcb-Lite`**:

|Process|Description|
|---|---|
|`smss.exe`|Session Manager – boot session initialization.|
|`csrss.exe`|Client/Server Runtime Subsystem – interacts with Win32k.sys.|
|`services.exe`|Manages Windows services.|
|`wininit.exe`|Performs Windows startup tasks.|

These binaries are part of the **Minimum TCB List**, which means:

- **Windows enforces their protection level at runtime**, regardless of how they are launched.
    
- **CreateProcess calls** targeting these binaries must specify the **correct protection level**, or the process **won’t be allowed to launch**.
    

---

## 🧷 Additional Protected Services and Configurations

### ✔️ Services with PPL or PP:

- **`lsass.exe`** (Local Security Authority Subsystem):
    
    - PPL on ARM platforms by default.
        
    - Can be configured as PPL on x86/x64 via **registry settings or policy**.
        
- **`sppsvc.exe`** (Software Protection Platform):
    
    - Enforces licensing and DRM compliance.
        
- **`svchost.exe`**:
    
    - Hosts many services.
        
    - Examples of hosted services running protected:
        
        - **AppX Deployment Service**
            
        - **Windows Subsystem for Linux (WSL) Service**
            

These services are often targeted by attackers, so **running them as PPL or PP** greatly reduces their attack surface.

---

## 🔐 Importance of WinTcb-Lite and System Integrity

- Processes like **`csrss.exe`** are deeply integrated with **kernel-mode components** such as `win32k.sys` and can access **privileged private APIs**.
    
- Ensuring they **cannot be run without proper protection levels** stops attackers from launching impersonated versions or bypassing signature requirements.
    

---

## 🧷 Minimum TCB List Guarantee

Windows enforces a **Minimum TCB List**, ensuring:

- Certain binaries (e.g., `csrss.exe`, `smss.exe`) **must** run with a **minimum signature and protection level** if executed from system paths.
    
- The enforcement is **independent of who or what initiates the process**—including administrators.
    

This list is enforced by the **Code Integrity** system at process launch time and helps protect against **process impersonation and startup manipulation**.

---

## 🧾 Summary Table

| Mechanism               | Purpose                                                             |
| ----------------------- | ------------------------------------------------------------------- |
| `SignatureLevel`        | Defines the minimum trust of the process’s main executable          |
| `SectionSignatureLevel` | Defines the minimum signing level required for DLLs                 |
| DLL loading validation  | Ensures that only trusted DLLs are mapped into PPL/PP processes     |
| Minimum TCB list        | Forces key binaries to always launch with minimum protection levels |
![[Pasted image 20250505210039.png]]


## 🛡️ Third-Party PPL Support: Extending Security Beyond Microsoft

### 📌 Background

Originally, **Protected Processes** (and their lighter variant, **PPL**) were only available to **Microsoft-signed binaries**. However, recognizing that security vendors also need strong protection from malware tampering, **Microsoft extended PPL capabilities** to vetted **third-party anti-malware providers**.

---

## 🧩 Components of an Anti-Malware Product

A typical anti-malware solution consists of:

|Component|Role|
|---|---|
|**Kernel Driver**|Monitors I/O operations, intercepts files and network activity, implements callbacks for object/process/thread events.|
|**User-mode Service**|Manages driver policy, logs events (e.g., file infections), and handles remote communication. Often a **high-value target** for malware.|
|**User-mode GUI Process**|Displays alerts, user interaction, optional policy control.|

---

## ❗ Threat Model: Why PPL Is Needed

Without PPL protection:

- Malware (even with user-mode elevation) could:
    
    - Inject code into AM processes.
        
    - Terminate the AM service.
        
    - Alter policy or neutralize logging.
        

With PPL:

- These actions are **blocked**, **even by admin-level processes**, unless they have equal or higher protection level.
    

---

## 🏗️ How PPL Is Enabled for Third-Party AM

### 🔐 Requirement: **ELAM Driver**

- **ELAM (Early Launch Anti Malware)** is a special category of boot-time drivers.
    
- Required for PPL support because it anchors trust into the **earliest stage of Windows boot**.
    
- Must be **signed by Microsoft** with an **Anti-Malware Certificate**.
    

### 📦 ELAMCERTIFICATEINFO Resource Section

In the AM’s PE file (typically the EXE of the user-mode service), a custom **resource section** called `ELAMCERTIFICATEINFO` is included. This section:

- Specifies **up to 3 additional Signers** (public keys).
    
- Each Signer can be associated with **up to 3 EKUs** (Enhanced Key Usages), defined by **OID strings**.
    

### 🧠 Code Integrity Role

At runtime:

1. **Code Integrity** inspects the signature.
    
2. If the binary matches one of the Signers and EKUs defined in `ELAMCERTIFICATEINFO`, it is permitted to:
    
    - **Request a PPL level of `PS_PROTECTED_ANTIMALWARE_LIGHT` (0x31)**.
        

➡️ This ensures only **vetted, signed anti-malware binaries** can request this level of protection.

---

## 🧪 Real-World Example: **Windows Defender**

|Component|PPL Enabled?|Details|
|---|---|---|
|`MsMpEng.exe`|✅|Main anti-malware engine (protected from injection/termination)|
|`NisSvc.exe`|✅|Network Inspection Service (monitors traffic and enforces rules)|

Both are:

- Signed with Microsoft’s **anti-malware certificate**.
    
- Whitelisted by the **Code Integrity module** via ELAM policies.
    

---

## 🛡️ Benefits of PPL for Anti-Malware Vendors

|Protection Feature|Benefit|
|---|---|
|Code injection blocked|Prevents malware tampering|
|Termination blocked|Ensures continuous protection|
|Signature enforcement|Limits protection to approved vendors|
|Boot-time driver enforcement|Strengthens root-of-trust|

---

## ⚠️ Limitation: Kernel-Level Attacks Still Apply

- PPL cannot defend against **kernel-mode malware or rootkits**.
    
- Advanced threats may attempt to load malicious drivers or **bypass Code Integrity using stolen certificates**.
    

➡️ Complementary protections like **Secure Boot**, **VBS (Virtualization-Based Security)**, and **Kernel Patch Protection (PatchGuard)** are necessary for full resilience.



## 🧠 What Is a Pico Process?

A **Pico process** is a minimal Windows process that **does not rely on the traditional Windows user-mode environment**, such as:

- Win32 APIs
    
- TEB (Thread Environment Block)
    
- PEB (Process Environment Block)
    

Instead, it relies on a **Pico provider**, a user-mode subsystem DLL or runtime (like WSL) that acts as a translator between non-Windows code and NT kernel facilities.

---

## 🧩 Pico Provider Function Registration

When a **Pico provider** registers itself with the Windows kernel (typically during system initialization), it calls a **registration API** provided by the NT kernel. In return, it receives a **set of function pointers** (callbacks) that allow it to create and control Pico processes and threads.

### 📥 Function Pointer Set Includes:

|Function Type|Description|
|---|---|
|**Process/Thread Creation**|Functions to create Pico processes and Pico threads.|
|**Context Management**|Get/Set an arbitrary "context" pointer for each Pico process/thread.|
|**CPU Context Access**|Get/Set the `CONTEXT` structure for a thread (register state, etc.).|
|**FS/GS Segment Management**|Change segment registers, often used to point to thread-local storage.|
|**Process/Thread Termination**|Explicitly terminate Pico threads or processes.|
|**Thread Suspension/Resumption**|Suspend or resume execution of a thread.|

➡️ These callbacks allow the **Pico provider full control over thread lifecycle, state, and execution context**—without relying on the Win32 subsystem.

---

## 🧠 Technical Underpinnings

### 🔹 Kernel Structures Used:

- `EPROCESS` (process kernel object)
    
- `ETHREAD` (thread kernel object)
    

Each of these has a field called **`PicoContext`**, which:

- Stores a pointer (or handle) to provider-defined structures.
    
- Allows the kernel to maintain **provider-specific state** alongside traditional kernel data.
    

This architecture supports clean and modular integration of **foreign runtime models** within the NT process/thread model.

---

## 📌 Practical Use Case: WSL

- **WSL’s Pico provider** translates **Linux system calls** into NT kernel calls.
    
- Uses Pico threads and processes to run ELF binaries **without creating full Win32 processes**.
    
- The FS/GS override function is used to simulate Linux-style **thread-local storage**.
    

---

## 🔐 Security & Isolation Benefits

- Pico processes can be **highly restricted**.
    
- Minimal attack surface—no Win32 libraries loaded.
    
- Useful for sandboxing, containers, and secure VM environments.
    

---

## ✅ Summary Table

| Functionality            | Purpose                                 | Structure Affected    |
| ------------------------ | --------------------------------------- | --------------------- |
| Create Process/Thread    | Establish new Pico entities             | N/A                   |
| Set/Get Context          | Track provider-specific metadata        | `EPROCESS`, `ETHREAD` |
| Set/Get CPU Context      | Control execution (registers, IP, etc.) | `CONTEXT`             |
| Modify FS/GS             | Simulate TLS (e.g., Linux `pthread`)    | Segment registers     |
| Terminate/Suspend/Resume | Manage thread lifecycle                 | N/A                   |
