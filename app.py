from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

app = Flask(__name__)

# --------------- XSS SCANNING LOGIC ----------------
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] in ["text", "search"]:
            input["value"] = value
        if input.get("name") and input.get("value"):
            data[input["name"]] = input["value"]
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_xss(url):
    forms = get_all_forms(url)
    results = []
    js_script = "<script>alert('XSS')</script>"
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode(errors="ignore")
        if js_script in content:
            results.append({
                "url": url,
                "form": form_details,
                "threat": "Reflected Cross-Site Scripting (XSS)",
                "impact": "Attackers can inject malicious JavaScript into the webpage.",
                "recommendation": "Sanitize and validate all user inputs before rendering."
            })
    return results

# --------------- FLASK ROUTES ----------------
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target_url = request.form.get("url")
    findings = scan_xss(target_url)
    return render_template("result.html", results=findings, target=target_url)

if __name__ == "__main__":
    app.run(debug=True)
