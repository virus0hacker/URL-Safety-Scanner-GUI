#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URL Safety Scanner
Author: virus-hacker
Snapchat: ml-ftt
Twitter: h3fq1
"""

import threading
import platform
import socket
from urllib.parse import urlparse, parse_qs

import requests
from requests.exceptions import RequestException

import tkinter as tk
from tkinter import ttk, messagebox

from colorama import init as colorama_init
from PIL import Image, ImageTk

colorama_init(autoreset=True)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0"})

def play_alert():
    try:
        if platform.system() == "Windows":
            import winsound
            winsound.Beep(1000, 400)
            winsound.Beep(800, 400)
        else:
            print("\a")
    except:
        pass

def safe_head_or_get(url):
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=8)
        if r.status_code >= 400:
            r = SESSION.get(url, allow_redirects=True, timeout=8)
        return r.url, r
    except RequestException:
        return url, None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def extract_nested_links(url):
    nested = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for key in params:
        for v in params[key]:
            if v.startswith("http://") or v.startswith("https://"):
                nested.append(v)
    return nested

def fetch_ip_info(ip):
    if not ip:
        return None
    try:
        resp = SESSION.get(f"http://ip-api.com/json/{ip}", timeout=8)
        data = resp.json()
        if data.get("status") == "success":
            return data
    except:
        return None
    return None

def check_blacklist(domain):
    try:
        r = SESSION.get(f"https://phish.sinking.yachts/v2/check/{domain}", timeout=7)
        return r.text.strip() == "true"
    except:
        return False

def classify(https, flagged, nested, tld):
    score = 0
    if flagged: score += 4
    if not https: score += 2
    if nested: score += 1
    bad_tlds = {".ru", ".cn", ".xyz", ".top", ".ml", ".tk", ".ga", ".cf"}
    if tld in bad_tlds: score += 1
    if score >= 4:
        return ("HIGH RISK ⚠️", "#b30000")
    elif score >= 2:
        return ("MEDIUM RISK ⚠️", "#b38f00")
    else:
        return ("LOW RISK ✅", "#006b3c")

def detect_cdn(info):
    if not info:
        return None
    text = (str(info.get("isp","")) + " " + str(info.get("org","")) + " " + str(info.get("as",""))).lower()
    if "cloudflare" in text: return "Cloudflare"
    if "akamai" in text: return "Akamai"
    if "fastly" in text: return "Fastly"
    if "imperva" in text or "incapsula" in text: return "Imperva / Incapsula"
    return None


class URLScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("URL Safety Scanner — By ViRuS-HaCkEr (Snap: ml-ftt)")
        self.root.geometry("900x670")

        self._build_ui()

    def _build_ui(self):
        banner = tk.Label(
            self.root,
            text="URL SAFETY SCANNER\nSnap: ml-ftt — By ViRuS-HaCkEr",
            bg="#004225", fg="white",
            font=("Segoe UI", 14, "bold"), pady=11
        )
        banner.pack(fill=tk.X)

        container = ttk.Frame(self.root, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(container)
        top.pack(fill=tk.X, pady=(0,10))

        ttk.Label(top, text="URL:").pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=65)
        self.url_entry.pack(side=tk.LEFT, padx=5)
        self.url_entry.bind("<Return>", lambda e: self.start_scan())

        paste_btn = ttk.Button(top, text="Paste", command=self.paste_url)
        paste_btn.pack(side=tk.LEFT, padx=5)

        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        # ----- Credits button -----
        credits_btn = ttk.Button(top, text="Credits", command=self.show_credits)
        credits_btn.pack(side=tk.LEFT, padx=5)

        self.risk_lbl = tk.Label(
            container, text="No Scan", bg="#444", fg="white",
            font=("Segoe UI", 12, "bold"), padx=10, pady=6
        )
        self.risk_lbl.pack(fill=tk.X, pady=(0,8))

        info = ttk.LabelFrame(container, text="Basic Info")
        info.pack(fill=tk.X)
        self.lbl_original = ttk.Label(info, text="Original: -")
        self.lbl_resolved = ttk.Label(info, text="Resolved: -")
        self.lbl_domain = ttk.Label(info, text="Domain: -")
        self.lbl_ip = ttk.Label(info, text="IP: -")
        self.lbl_https = ttk.Label(info, text="HTTPS: -")
        for lbl in (self.lbl_original, self.lbl_resolved, self.lbl_domain, self.lbl_ip, self.lbl_https):
            lbl.pack(anchor="w")

        net = ttk.LabelFrame(container, text="Server / Network Info")
        net.pack(fill=tk.X, pady=5)
        self.lbl_server = ttk.Label(net, text="Server: -")
        self.lbl_powered = ttk.Label(net, text="X-Powered-By: -")
        self.lbl_country = ttk.Label(net, text="Country/City: -")
        self.lbl_isp = ttk.Label(net, text="ISP/Org: -")
        self.lbl_asn = ttk.Label(net, text="ASN: -")
        self.lbl_cdn = ttk.Label(net, text="CDN: -")
        for lbl in (self.lbl_server, self.lbl_powered, self.lbl_country,
                    self.lbl_isp, self.lbl_asn, self.lbl_cdn):
            lbl.pack(anchor="w")

        nested_frame = ttk.LabelFrame(container, text="Nested URLs inside parameters")
        nested_frame.pack(fill=tk.X)
        self.nested_box = tk.Text(nested_frame, height=5)
        self.nested_box.pack(fill=tk.X)

        log_frame = ttk.LabelFrame(container, text="Raw Response Headers")
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_box = tk.Text(log_frame)
        self.log_box.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w")
        status.pack(fill=tk.X, side=tk.BOTTOM)

    def paste_url(self):
        try:
            text = self.root.clipboard_get()
            self.url_var.set(text)
        except:
            messagebox.showwarning("Clipboard", "Clipboard is empty.")

    def set_status(self, txt):
        self.status_var.set(txt)
        self.root.update_idletasks()

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Please paste or type a URL first.")
            return
        if not urlparse(url).scheme:
            url = "http://" + url
            self.url_var.set(url)
        self.clear()
        self.scan_btn.config(state=tk.DISABLED)
        self.set_status("Scanning...")

        t = threading.Thread(target=self._scan_worker, args=(url,), daemon=True)
        t.start()

    def _scan_worker(self, url):
        try:
            report = self.do_scan(url)
            self.root.after(0, lambda: self.apply_report(report))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: (self.scan_btn.config(state=tk.NORMAL), self.set_status("Ready.")))

    def do_scan(self, original):
        resolved, resp = safe_head_or_get(original)
        parsed = urlparse(resolved)
        domain = parsed.netloc
        https = parsed.scheme == "https"

        nested = extract_nested_links(resolved)
        ip = resolve_ip(domain)

        server = resp.headers.get("Server") if resp else "-"
        powered = resp.headers.get("X-Powered-By") if resp else "-"
        headers_raw = dict(resp.headers) if resp else {}

        ipinfo = fetch_ip_info(ip)
        flagged = check_blacklist(domain)

        tld = "." + domain.split(".")[-1].lower() if "." in domain else ""
        risk, color = classify(https, flagged, nested, tld)

        if "HIGH" in risk.upper():
            play_alert()

        return {
            "original": original,
            "resolved": resolved,
            "domain": domain,
            "ip": ip,
            "https": https,
            "nested": nested,
            "flagged": flagged,
            "risk": risk,
            "risk_color": color,
            "server": server,
            "powered": powered,
            "headers": headers_raw,
            "ipinfo": ipinfo,
            "cdn": detect_cdn(ipinfo),
        }

    def clear(self):
        self.risk_lbl.config(text="Scanning...", bg="#444")
        for lbl in [
            self.lbl_original, self.lbl_resolved, self.lbl_domain,
            self.lbl_ip, self.lbl_https, self.lbl_server, self.lbl_powered,
            self.lbl_country, self.lbl_isp, self.lbl_asn, self.lbl_cdn
        ]:
            lbl.config(text="-")
        self.nested_box.delete("1.0", tk.END)
        self.log_box.delete("1.0", tk.END)

    def apply_report(self, r):
        self.risk_lbl.config(text=r["risk"], bg=r["risk_color"], fg="white")
        self.lbl_original.config(text=f"Original: {r['original']}")
        self.lbl_resolved.config(text=f"Resolved: {r['resolved']}")
        self.lbl_domain.config(text=f"Domain: {r['domain']}")
        self.lbl_ip.config(text=f"IP: {r['ip'] or '-'}")
        self.lbl_https.config(text=f"HTTPS: {'Yes' if r['https'] else 'No'}")
        self.lbl_server.config(text=f"Server: {r['server']}")
        self.lbl_powered.config(text=f"X-Powered-By: {r['powered']}")

        if r["ipinfo"]:
            info = r["ipinfo"]
            self.lbl_country.config(text=f"Country/City: {info.get('country')} - {info.get('city')}")
            self.lbl_isp.config(text=f"ISP/Org: {info.get('isp')} / {info.get('org')}")
            self.lbl_asn.config(text=f"ASN: {info.get('as')}")
        else:
            self.lbl_country.config(text="Country/City: -")
            self.lbl_isp.config(text="ISP/Org: -")
            self.lbl_asn.config(text="ASN: -")

        self.lbl_cdn.config(text=f"CDN: {r['cdn'] or '-'}")

        self.nested_box.delete("1.0", tk.END)
        self.nested_box.insert(tk.END, "\n".join(r["nested"]) if r["nested"] else "No nested links detected.")

        self.log_box.delete("1.0", tk.END)
        for k, v in r["headers"].items():
            self.log_box.insert(tk.END, f"{k}: {v}\n")
        if r["flagged"]:
            self.log_box.insert(tk.END, "\n[!] Domain is listed in phishing database\n")

        self.set_status("Scan complete.")

    # ⚡ Window of credits with logo + signature
    def show_credits(self):
        win = tk.Toplevel(self.root)
        win.title("Credits")
        win.geometry("460x430")
        win.resizable(False, False)
        bg = "#00331f"
        frame = tk.Frame(win, bg=bg)
        frame.pack(fill=tk.BOTH, expand=True)

        

        tk.Label(frame, text="⚡ URL SAFETY SCANNER ⚡", bg=bg, fg="#00ff7f",
                 font=("Segoe UI", 15, "bold")).pack()

        tk.Label(frame, text="👨‍💻 Developer: ViRuS-HaCkEr", bg=bg, fg="#00ffaa", font=("Segoe UI", 12)).pack(pady=(10, 2))
        tk.Label(frame, text="👻 Snapchat: ml-ftt", bg=bg, fg="#00ffaa", font=("Segoe UI", 11)).pack()
        tk.Label(frame, text="🐦 Twitter / X: h3fq1", bg=bg, fg="#00ffaa", font=("Segoe UI", 11)).pack()

        tk.Label(frame, text='Ahmed / ml-ftt — "Cyber Security with Respect"',
                 bg=bg, fg="white", font=("Segoe UI", 9, "italic")).pack(pady=(16, 0))

        tk.Label(
            frame,
            text="© All Rights Reserved\nUnauthorized resale prohibited",
            bg=bg, fg="#888888", font=("Segoe UI", 8, "italic")
        ).pack(pady=(20, 0))


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except:
        pass
    URLScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
