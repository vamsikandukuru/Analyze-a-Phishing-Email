# Cyber Security Internship – Task 2

##  Task: Phishing Email Analysis

### Objective:
Analyze a suspicious phishing email to identify potential threats, including embedded malware, spoofed headers, suspicious links, and phishing techniques.

---

##  Tools Used

 Tool                                  Purpose 

   MXToolbox                    Analyze email headers and sender IP reputation 
   VirusTotal                   Scan payloads and links for known malware 
   SETToolkit                   Simulate phishing email delivery 
   PHP + base64                 Create and embed trojan payload 
   HTML Email Template          Craft email with clickable trojan link 
   Online Header Analyzer       Identify spoofing or suspicious sender behavior 

---

##  Methodology

1. Email Sample Creation  
   - A phishing email was crafted using a fake Microsoft update notification.
   - Payload was created using a **PHP-based base64 encoded trojan**.

2. Trojan Embedding
   - The payload was embedded in an HTML email using an `<a>` tag that disguised the trojan as a legitimate link (e.g., "Update Now").

3. Phishing Delivery
   - Used **SETToolkit** to deliver the phishing email through a local SMTP server.
   - Email was sent with high-priority flags to increase user trust.

4. Header Analysis
   - Raw email data was copied into **MXToolbox**.
   - MXToolbox revealed:
     - Sender IP address
     - SPF/DKIM/DMARC failures
     - RBL (Real-time Blackhole List) status
     - Spoofed `From:` address pretending to be Microsoft

5. VirusTotal Analysis
   - Payload URL and the PHP file were scanned.
   - Detected as malicious by multiple AV engines.

   Behavioral Analysis
   - Upon clicking, the link triggers PHP-based script execution.
   - Observed system-level commands (attempted backdoor connection).
   - Suspicious use of obfuscation techniques.

---

##  Results

- The email was flagged by MXToolbox as suspicious.
- RBL Check showed blacklisted sender IP.
- SPF/DKIM validation failed.
- VirusTotal scan detected malware in the attached PHP payload.
- Email behavior mimicked legitimate communication from Microsoft.
- User click leads to trojan download and remote execution attempt.

---

## ✅ Remediation & Recommendations

- **Do not trust emails with urgent or forced actions (e.g., "Update Now").**
- **Verify sender domains using MXToolbox or mail header analysis.**
- **Never download or run unknown attachments or links.**
- Keep antivirus and endpoint protection updated.
- Report suspected phishing emails to the security team.
- Educate users on recognizing phishing signs (grammar errors, suspicious links, fake logos).
- Implement email filtering and block known phishing domains/IPs.
- Use DMARC, SPF, and DKIM properly to prevent spoofing.

---
