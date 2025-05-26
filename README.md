# Cassandra — Reverse Shell Generator

**Cassandra** is a flexible, lightweight command-line tool built for **penetration testers** and **red teamers** to dynamically generate reverse shell one-liners across multiple platforms and scripting environments.

Instead of managing static reverse shells, Cassandra generates tailored reverse shell commands in real-time—customized with your listener IP and port—offering optional Base64 and URL encoding for compatibility across diverse contexts.

---

## ✨ Features

- 🗣️ **Multi-language support**: Bash, Python, PHP, Perl, PowerShell, Ruby, Node.js, Netcat, Go, Lua, Zsh, and more  
- 🔢 **Over 25+ different reverse shell variants** across supported languages (e.g., `bash`, `bash_tcp`, `python3`, `php_system`, etc.)  
- ♻️ **Multiple variants** per language  
- 🎯 **Targeted generation**: Output a single payload or generate all supported payloads at once  
- 🔐 **Encoding options**: Base64 or URL-encode the output for flexible payload delivery and bypassing filters  
- ⚙️ **Zero dependencies**: Pure Python 3; no external libraries required  

---

## ⚙️ Installation

Clone the repository using Git:

    git clone https://github.com/v3dSec/cassandra.git
    cd cassandra

Run the script with Python 3 (no additional dependencies required).

---

## 💡 Why Use Cassandra?

- 🧰 Eliminates the need for managing static payload libraries  
- 🌐 Encoding support ensures payloads work in diverse injection scenarios  
- 🧼 Clean, minimal CLI interface for quick usage  
- 🧪 Perfect for CTFs, penetration testing, and red teaming engagements  

---

## 🧰 Usage

### Required Flags

- `--lhost` → Listener IP address (your attacking machine)  
- `--lport` → Listener port  
- `--language` → Generate a shell for a specific language  
  *or*  
- `--all` → Generate shells for all supported languages  

### Optional Flags

- `--base64` → Base64-encode the reverse shell output  
- `--url` → URL-encode the reverse shell output  

> ⚠️ Only one encoding flag (`--base64` or `--url`) can be used at a time.

---

## 🧪 Examples

### ▶️ Basic Usage (No Encoding)

**Bash reverse shell:**

    python3 cassandra.py --lhost 192.168.56.1 --lport 4444 --language bash

**Python 3 reverse shell:**

    python3 cassandra.py --lhost 10.10.14.5 --lport 9001 --language python

**Generate all available reverse shells (25+ variants):**

    python3 cassandra.py --lhost 10.10.14.5 --lport 9001 --all

---

### 🔐 Encoded Output

**Base64-encoded reverse shell (PHP):**

    python3 cassandra.py --lhost 192.168.0.20 --lport 1234 --language php --base64

Base64 encoding is useful when embedding payloads in scripts or bypassing input filters.

**URL-encoded reverse shell (PowerShell):**

    python3 cassandra.py --lhost 192.168.0.20 --lport 1234 --language powershell --url

URL encoding helps when injecting payloads into HTTP parameters or web requests.

---

## ⚠️ Legal Disclaimer

This tool is intended strictly for **authorized penetration testing** and **educational purposes**.  
Use Cassandra **only** on systems for which you have **explicit written permission**.  
Unauthorized or malicious use may violate laws and ethical guidelines.

---
