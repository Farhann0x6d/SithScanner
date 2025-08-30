# 🛡️ SithScanner

SithScanner is a lightweight **browser extension** that detects and blocks emerging web exploits such as **ClickFix** and **FileFix**.  
It analyzes scripts and HTML in real time, looking for signs of:

- 📋 Clipboard abuse (`navigator.clipboard.writeText`, silent copy attacks, etc.)
- ⚙️ LOLBins (Living Off the Land Binaries like `powershell.exe`, `cmd.exe`, `curl.exe`, etc.)
- 🔑 Dangerous command-line switches (`-enc`, `-ec`, `base64 -d`, etc.)
- 🌀 Heavy obfuscation techniques (`fromCharCode`, long hex variable names)
- 🖼️ Malicious iframe payloads

When a threat is detected, the extension halts page execution and shows a warning:

> **⚠️ Security Alert**  
> "ClickFix detected! Please report this site to your Security Operations Center (SOC)."

---
