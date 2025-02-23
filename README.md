# Phish_Byte
Phish_Byte is a Python-based tool designed to analyze emails for phishing and spoofing attempts by extracting and verifying key security indicators. This tool helps identify fraudulent emails by checking multiple security aspects.

🔍 Features & Checks:
✅ Domain Consistency Check: Verifies if the "From," "Reply-To," and "Return-Path" headers originate from the same domain. Inconsistent domains may indicate spoofing. <br>
✅ Embedded URLs Analysis: Extracts URLs from the email body, counts secured (HTTPS) and unsecured (HTTP) links, and detects mismatched anchor texts leading to misleading sites. <br>
✅ SPF Validation (Upcoming): Checks if the email's originating IP is authorized by the sender’s domain SPF record. <br>

🛠 How It Works:
1️⃣ Copy and paste the original email (including headers). <br>
2️⃣ DarkMail scans and validates key indicators. <br>
3️⃣ A report is generated, flagging potential threats. <br>

Ideal for cybersecurity professionals and enthusiasts, Phish_Byte helps detect phishing attempts with ease! 🚀
