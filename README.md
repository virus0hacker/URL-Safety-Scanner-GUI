# 🔥 URL Safety Scanner — GUI | Advanced Cybersecurity Tool

**URL Safety Scanner** is a professional desktop GUI tool for analyzing suspicious or shortened links without opening them — designed for cybersecurity awareness and legal OSINT.

The program scans any link and reveals:
- Whether the link is shortened
- The final real URL after redirects
- Whether the link contains nested malicious redirect parameters
- Server information (Server header, X-Powered-By)
- IP details (Country, City, ISP, ASN)
- Cloudflare / Akamai / Fastly / Imperva detection (if the website is using a CDN / Proxy)
- HTTPS status
- Phishing blacklist database result
- Risk classification ⚠️ (High / Medium / Low)

> ⚠️ Internal safety:  
> The tool **does NOT open the link**, only analyzes metadata — 100% safe to use.

---

## 🖥 Features
| Feature | Status |
|--------|--------|
| GUI interface (Tkinter) | ✔️ |
| Show original + resolved URL | ✔️ |
| Detect shortened links | ✔️ |
| Detect nested redirect links in URL parameters | ✔️ |
| Extract IP + server headers | ✔️ |
| Fetch IP information (Country, City, ISP, ASN) | ✔️ |
| Identify CDN providers | ✔️ |
| Risk classification system | ✔️ |
| Sound alert on High Risk | ✔️ |
| Paste button (Clipboard → URL field) | ✔️ |
| Premium “Credits” window with logo + signature | ✔️ |

---


---

## 📦 Installation

### 1️⃣ Install Python dependencies
```bash
pip install requests pillow colorama

```
Run the tool:
```
python url_safety_scanner_gui.py
```

📌 Usage

Paste any URL (even shortened links like bit.ly / tinyurl / t.co)

Click Scan

Review:

Risk Level

Server/Network data

Redirect or nested redirect information

Phishing detection result

⚠️ If the link is flagged → A sound alert will play.



🛡️ Legal Notice

This tool is intended only for:

Educational cybersecurity

Awareness against phishing and social engineering

Self-protection and OSINT in legal boundaries

It must NOT be used for:
🔻 Hacking
🔻 Doxxing
🔻 Privacy violations
🔻 Any illegal activity

🔻 You are responsible for your own usage 🔻



🧑‍💻 Developer:
```

|     Field   |       Info        |
| ----------- |     ----------    |
| Developer   | **ViRuS-HaCkEr**  |
| Snapchat    |    **ml-ftt**     |
| Twitter / X |    **h3fq1**      |
```

⭐ Support

If you like the project:

Leave a Star ⭐
---

Share the repository to support the community ⚡

🚀 Future plans (optional roadmap)

Export reports as PDF / JSON / CSV
