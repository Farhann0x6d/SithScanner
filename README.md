# 🛡️ SithScanner

“An elegant defense for a more civilized age.”

SithScanner is a lightweight **browser extension** that detects and blocks techniques such as **ClickFix** and **FileFix**. This will likely progress into a browser EDR as the project develops.
  
It analyzes scripts and HTML in real time, looking for signs of:

- 📋 Clipboard abuse (`navigator.clipboard.writeText`, silent copy attacks, etc.)
- LOLBins (Living Off the Land Binaries like `powershell.exe`, `cmd.exe`, `curl.exe`, etc.)
- Command-line switches (`-enc`, `-ec`, `base64 -d`, etc.)
- 🌀 Heavy obfuscation techniques

When a threat is detected, the extension halts page execution and shows a warning:

<img width="2546" height="1228" alt="Screenshot 2025-08-30 174351" src="https://github.com/user-attachments/assets/fdb42b07-4ad7-4af9-831d-ec950d57a55e" />

---
