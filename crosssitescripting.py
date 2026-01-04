import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
import tkinter as tk
from tkinter import scrolledtext, messagebox
import uuid
import html
import traceback

TEXT_LIKE_TYPES = {
    "text", "search", "email", "url", "tel", "password", "number"
}

def normalize_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        return "http://" + url
    return url

def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

def get_all_forms(session, url):
    resp = session.get(url, timeout=15)
    resp.raise_for_status()
    soup = bs(resp.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    details["action"] = form.attrs.get("action", "").strip()
    details["method"] = form.attrs.get("method", "get").strip().lower() or "get"

    inputs = []
    for input_tag in form.find_all("input"):
        itype = input_tag.attrs.get("type", "text").lower()
        name = input_tag.attrs.get("name")
        value = input_tag.attrs.get("value", "")
        inputs.append({"tag": "input", "type": itype, "name": name, "value": value})

    for ta in form.find_all("textarea"):
        name = ta.attrs.get("name")
        value = ta.text or ""
        inputs.append({"tag": "textarea", "type": "textarea", "name": name, "value": value})

    return details | {"inputs": inputs}

def build_submission_data(form_details, injection_value: str):
    data = {}
    for field in form_details["inputs"]:
        name = field.get("name")
        if not name:
            continue

        ftype = field.get("type", "text").lower()
        tag = field.get("tag", "input")

        if tag == "textarea" or ftype in TEXT_LIKE_TYPES:
            data[name] = injection_value
        else:
            data[name] = field.get("value", "")
    return data

def reflected_in_response(response_text: str, marker: str):
    raw = marker in response_text
    escaped = html.escape(marker) in response_text
    return {"raw": raw, "escaped": escaped, "any": raw or escaped}

def submit_form(session, base_url, form_details, data):
    target_url = urljoin(base_url, form_details["action"] or base_url)
    method = form_details["method"]
    if method == "post":
        resp = session.post(target_url, data=data, timeout=20)
    else:
        resp = session.get(target_url, params=data, timeout=20)
    return target_url, resp

class XSSScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XSS Vulnerability Scanner — Enhanced Report")

        tk.Label(root, text="Enter URL:").pack()
        self.url_entry = tk.Entry(root, width=60)
        self.url_entry.pack()
        self.scan_btn = tk.Button(root, text="Scan for XSS", command=self.start_scan)
        self.scan_btn.pack()

        self.output = scrolledtext.ScrolledText(root, width=100, height=25)
        self.output.pack()

    def log(self, msg):
        self.output.insert(tk.END, msg + "\n")
        self.output.see(tk.END)
        self.root.update_idletasks()

    def set_busy(self, busy=True):
        self.scan_btn.config(state=("disabled" if busy else "normal"))
        self.root.update_idletasks()

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Please enter a target URL")
            return
        url = normalize_url(url)
        self.output.delete("1.0", tk.END)
        self.set_busy(True)
        try:
            self.scan(url)
        except Exception as e:
            self.log(f"[!] Error: {e}")
            self.log(traceback.format_exc())
        finally:
            self.set_busy(False)

    def scan(self, url):
        self.log(f"[*] Scanning: {url}")
        session = requests.Session()
        session.headers.update({"User-Agent": "XSS-Scanner/2.0"})

        try:
            forms = get_all_forms(session, url)
        except requests.RequestException as e:
            self.log(f"[!] Could not fetch page: {e}")
            return

        self.log(f"[+] Found {len(forms)} forms")
        if not forms:
            return

        marker = "__XSS_TEST__" + uuid.uuid4().hex[:6]
        self.log(f"[*] Injection marker: {marker}")

        for idx, form in enumerate(forms, start=1):
            self.log("-" * 70)
            self.log(f"[Form #{idx}] Action: {form.attrs.get('action', '')} | Method: {form.attrs.get('method', 'get').upper()}")
            details = get_form_details(form)
            if not same_origin(url, urljoin(url, details["action"])):
                self.log("[!] Skipped — Cross-origin form")
                continue

            data = build_submission_data(details, marker)
            try:
                target_url, resp = submit_form(session, url, details, data)
            except requests.RequestException as e:
                self.log(f"[!] Error submitting form: {e}")
                continue

            result = reflected_in_response(resp.text, marker)
            if result["any"]:
                self.report_vulnerability(details, target_url, result)
            else:
                self.log("[-] No reflection detected")

    def report_vulnerability(self, form_details, target_url, result):
        self.log(f"[!!!] Vulnerability Detected: Potential Reflected Cross-Site Scripting (XSS)")
        self.log(f"      Description: User-supplied input is reflected in the response without proper encoding.")
        self.log(f"      Impact: An attacker could inject malicious scripts, leading to session theft, defacement, or phishing.")
        self.log(f"      Threat Level: HIGH")
        self.log(f"      Location: {target_url}")
        self.log(f"      Reflection Type: {'Raw HTML' if result['raw'] else 'HTML-escaped'}")
        self.log(f"      Recommendation: Sanitize and HTML-encode all user inputs before rendering in the browser.")
        self.log("-" * 70)

if __name__ == "__main__":
    root = tk.Tk()
    app = XSSScannerGUI(root)
    root.mainloop()
