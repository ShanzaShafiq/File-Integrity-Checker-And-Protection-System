# File-Integrity-Checker-And-Protection-System
C++ based File Integrity Monitoring System using SHA-256 hashing

**📌 Project Information**

**Project Title**:File Integrity Checker and Protection System 
**Student Name** :Shanza Shafiq 
**Roll No** : BITF24M008 
**Subject** : Information Security 
**Submitted To** : Sir Huzaifa Nazir 
**University** : Punjab University College of Information Technology 
**Campus** :Allama Iqbal Campus 

**📖 About This Project**

This project is a **C++ based File Integrity Monitoring System** that detects unauthorized modifications to files using **SHA-256 cryptographic hashing**.

The system computes a unique hash (fingerprint) of a file and stores it as a baseline. Whenever verification is needed, the hash is recomputed and compared with the stored value. If the hashes differ, the system raises an alert — meaning the file has been **tampered or modified**.

**❓ Problem Statement**

In modern computer systems, important files such as reports, documents, and system files can be modified **without the user's knowledge**. Unauthorized modification may lead to:
- Data corruption
- Loss of important information
- Security breaches
Most users have no simple mechanism to verify whether their files have been altered. This project solves that problem.

 **✅ Features**

 🔑 **Password Login** :Password-protected access with hidden input 
🔒 **Account Lockout** :System locks after 3 wrong password attempts |
➕ **Add File** : Compute and store SHA-256 baseline hash of any file 
🔍 **Check Integrity** :Recompute hash and compare — shows SAFE or TAMPERED  👁️ **View All Files** :List all monitored files with their stored hashes 
📋 **Activity Log** :Every action saved to `log.txt` with date and time 
🗑️ **Remove File** :Remove any file from monitoring 

 **🔐 Security Concepts Demonstrated**

1. **Data Integrity** — SHA-256 detects any file modification, even a single character change
2. **Access Control** — Password login ensures only authorized users can access the system
3. **Account Lockout** — Prevents brute force attacks by locking after 3 failed attempts
4. **Audit Logging** — Every action recorded with timestamp (audit trail)
5. **Tamper Detection** — Alert raised immediately when hash mismatch is found
6. **Avalanche Effect** — 1 byte change produces a completely different 64-character hash
7. **One-Way Hashing** — Cannot reverse a hash to get the original file
8. **Binary File Reading** — Works on all file types: `.txt`, `.pdf`, `.docx`, images, etc.

** ⚙️ How It Works**

```
BASELINE PHASE                    VERIFICATION PHASE
──────────────                    ──────────────────
Select File          →            Select Same File
      ↓                                  ↓
Read in Binary Mode  →            Read in Binary Mode
      ↓                                  ↓
Compute SHA-256      →            Recompute SHA-256
      ↓                                  ↓
Store Hash + Time    →            Compare with Stored Hash
                                         ↓
                                MATCH  →  FILE IS SAFE
                                NO MATCH →  FILE TAMPERED!


 **📚 Libraries Used**

`<iostream>:` cin`, `cout` — basic input/output 
<fstream>:` Read and write files 
<string>:` String data type 
<ctime>:` Get current date and time 
<conio.h>:Hidden password input (`_getch()`) 

 **🧮 SHA-256 — Manual Implementation**

SHA-256 (**Secure Hash Algorithm 256-bit**) is implemented completely from scratch without any library.

**How it works:**
1. Set 8 fixed initial hash values (from square roots of prime numbers)
2. Pad the message to make size a multiple of 512 bits
3. Break data into 64-byte blocks
4. Process each block through **64 rounds** of bitwise operations (AND, OR, XOR, rotate)
5. Produce final 256-bit result → convert to 64 hex characters

**Key property — Avalanche Effect:**
File contains: "Hello"   →  Hash: 185f8db32921bd...
File contains: "Hello!"  →  Hash: 334d016068f6d5... (completely different!)

## 🗃️ Database Format

All hashes are stored in `hash.txt` in this format:

**Example:**
C:\Users\Shanza\Documents\report.pdf|a3f2c1d8e9b7...64chars|2025-04-19 14:30:00
C:\Users\Shanza\Desktop\notes.txt|7b8d2e4f1a9c...64chars|2025-04-19 15:10:22

## 📋 Log File Format

All activity is recorded in `log.txt`:
```
[2025-04-19 14:30:00] : Login Successful
[2025-04-19 14:31:10] : File Added: C:\report.pdf
[2025-04-19 14:32:05] : SAFE: C:\report.pdf
[2025-04-19 14:35:22] : MODIFIED: C:\report.pdf
```


 🚀 How to Run

### Requirements
- Windows OS
- Visual Studio (any version)

### Steps
1. Clone or download this repository
2. Open **Visual Studio**
3. Create a new **Empty C++ Project**
4. Add `FileIntegrityChecker.cpp` to Source Files
5. Press **Ctrl + F5** to build and run

### Default Password
Shanza@00
You can change it in the code:
```cpp
const string PASSWORD = "shanza@00";


## 📁 Project Structure

File-Integrity-Checker_And_protection_System
├── FileIntegrityChecker.cpp       ← Main project code (C++)
├── FileIntegrityPresentation.pptx ← Presentation slides
├── ProjectProposal.pdf            ← Project proposal document
├── Documentation.pdf              ← Project documentation
└── README.md                     

## 📸 Program Output
FILE INTEGRITY CHECKER AND PROTECTION SYSTEM             
   Enter Password: *********

   Welcome!

   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice: 1
   File path: C:\Users\User\Downloads\Arooj Fatima.docx  
 File Added!
  Hash: 98f67e5d597dcfedc120ede7d660709079a3d8f4fe90ab29e9f41b68ae7876af
   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice: 2
   File path: C:\Users\User\Downloads\Arooj Fatima.docx

  Old Hash : 98f67e5d597dcfedc120ede7d660709079a3d8f4fe90ab29e9f41b68ae7876af
  New Hash : 98f67e5d597dcfedc120ede7d660709079a3d8f4fe90ab29e9f41b68ae7876af

  |  STATUS: FILE IS SAFE ..........
  |  Hashes match. No changes found....   |
   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice: 1
   File path: C:\Users\User\Downloads\Arooj Fatima.docx
  File already monitored!
   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice: 2
   File path: C:\Users\User\Downloads\Arooj Fatima.docx

  Old Hash : 98f67e5d597dcfedc120ede7d660709079a3d8f4fe90ab29e9f41b68ae7876af
  New Hash : f51bd69df75bfadb964c389303903b2b274bffe28a29f61cef1a3876170d43c3

 ALERT: FILE HAS BEEN MODIFIED!     
   Hashes do NOT match!               
   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice: 3

 MONITORED FILES 

  [1] C:\Users\User\Downloads\Project_Proposal_information_security (1).pdf
      Hash: bb936a6b8d78fcf6cde6c01499861d5f6b85fdd4bf85cc17478415168fa0219c

  [2] C:\Users\User\Downloads\Project_Proposal_information_security (1).pdf 
      Hash: bb936a6b8d78fcf6cde6c01499861d5f6b85fdd4bf85cc17478415168fa0219c

  [3] C:\Users\User\Downloads\Arooj Fatima.docx
      Hash: 98f67e5d597dcfedc120ede7d660709079a3d8f4fe90ab29e9f41b68ae7876af

  Total: 3 file(s)
   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice: 4

  ACTIVITY LOG 

  [Sun Apr 19 18:35:08 2026] : Login Successful
  [Sun Apr 19 18:43:24 2026] : Login Successful
  [Sun Apr 19 18:44:43 2026] : File Added: C:\Users\User\Downloads\Project_Proposal_information_security (1).pdf
  [Sun Apr 19 18:44:59 2026] : SAFE: C:\Users\User\Downloads\Project_Proposal_information_security (1).pdf
  [Sun Apr 19 19:54:44 2026] : Login Successful
  [Sun Apr 19 19:55:40 2026] : File Added: C:\Users\User\Downloads\Project_Proposal_information_security (1).pdf 
  [Sun Apr 19 19:56:06 2026] : SAFE: C:\Users\User\Downloads\Project_Proposal_information_security (1).pdf 
  [Sun Apr 19 19:57:07 2026] : User logged out
  [Mon Apr 20 02:34:39 2026] : Login Successful
  [Mon Apr 20 02:36:04 2026] : Login Successful
  [Mon Apr 20 02:37:23 2026] : Login Successful
  [Mon Apr 20 02:41:01 2026] : Login Successful
  [Mon Apr 20 02:52:10 2026] : Failed login attempt 1
  [Mon Apr 20 02:52:19 2026] : Failed login attempt 2
  [Mon Apr 20 02:52:28 2026] : Login Successful
  [Mon Apr 20 03:00:14 2026] : Login Successful
  [Mon Apr 20 03:00:27 2026] : File Added: C:\Users\User\Downloads\Arooj Fatima.docx
  [Mon Apr 20 03:00:41 2026] : SAFE: C:\Users\User\Downloads\Arooj Fatima.docx
  [Mon Apr 20 03:01:46 2026] : MODIFIED: C:\Users\User\Downloads\Arooj Fatima.docx
   1. Add File
   2. Check File
   3. View All Files
   4. View Log
   5. Exit
   Choice:4
    Goodbye! Stay secure

