# 🛡️ SithScanner

“An elegant defense for a more civilized age.”

SithScanner is a lightweight **browser extension** that detects and blocks emerging web exploits such as **ClickFix** and **FileFix**. This will likely progress into a browser EDR as the project develops.
  
It analyzes scripts and HTML in real time, looking for signs of:

- 📋 Clipboard abuse (`navigator.clipboard.writeText`, silent copy attacks, etc.)
- LOLBins (Living Off the Land Binaries like `powershell.exe`, `cmd.exe`, `curl.exe`, etc.)
- Command-line switches (`-enc`, `-ec`, `base64 -d`, etc.)
- 🌀 Heavy obfuscation techniques

When a threat is detected, the extension halts page execution and shows a warning:

> **⚠️ Security Alert**  
> "ClickFix detected! Please report this site to your Security Operations Center (SOC)."

---
