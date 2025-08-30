# 🛡️ SithScanner

“An elegant defense for a more civilized age.”

SithScanner is a lightweight browser-based EDR that goes beyond static URL blacklists. Instead of relying on reputation feeds, it actively analyzes in-browser behavior — detecting clipboard abuse, LOLBins, and obfuscated payloads (like those used in ClickFix campaigns) — and blocks them before they can execute.
  
It analyzes scripts and HTML in real time, looking for signs of:

- 📋 Clipboard abuse through JS methods like (`navigator.clipboard.writeText`, etc.)
- LOLBins that are copied to user clipboards (Living Off the Land Binaries like `powershell.exe`, `cmd.exe`, `curl.exe`, etc.)
- Command-line switches (`-enc`, `-ec`, `base64 -d`, etc.)
- 🌀 Heavy obfuscation techniques

When a threat is detected, the extension halts page execution and shows a warning:

<img width="2546" height="1228" alt="Screenshot 2025-08-30 174351" src="https://github.com/user-attachments/assets/fdb42b07-4ad7-4af9-831d-ec950d57a55e" />

---
