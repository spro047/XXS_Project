# XSS Vulnerability Scanner (XXS_Project)

A dual-interface Python security tool designed to detect potential Reflected Cross-Site Scripting (XSS) vulnerabilities in web applications. It automatically crawls a given URL for HTML forms, injects test payloads, and evaluates the HTTP responses for unescaped reflections.

## Description

The `XXS_Project` provides automated security auditing capabilities using Python's `requests` and `BeautifulSoup` libraries. It identifies all forms on a target webpage, parses their action URLs and input fields, and programmatically submits test payloads (e.g., `<script>alert('XSS')</script>` or unique UUID markers). If the payload is reflected back in the HTML response without proper sanitization, the tool flags it as a Reflected XSS vulnerability.

The project offers two distinct user interfaces:
1. **Web Interface (`app.py`)**: A Flask-based web application where users can input a target URL and view scan results formatted in a clean HTML dashboard.
2. **Desktop GUI (`crosssitescripting.py`)**: A standalone desktop application built with `tkinter`, providing real-time scrolled text logging of the scanning process, form discovery, and threat reporting.

## How to Use and Run

### Prerequisites

- Python 3.7+
- Recommended to use a virtual environment

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/spro047/XXS_Project.git
   cd XXS_Project
   ```

2. **Install dependencies**:
   Ensure you have the required libraries installed.
   ```bash
   pip install flask requests beautifulsoup4
   ```

### Running the Flask Web App
```bash
python app.py
```
Then navigate to `http://127.0.0.1:5000` in your browser. Enter a target URL in the form to begin scanning.

### Running the Tkinter Desktop GUI
```bash
python crosssitescripting.py
```
A desktop window titled "XSS Vulnerability Scanner" will open. Enter the URL and click "Scan for XSS" to view the live logs.

## Challenges Faced

Developing an automated XSS vulnerability scanner posed several intricate challenges:

1. **Dynamic Form Parsing**: Beautiful Soup is excellent for static HTML, but handling dynamically generated forms (like those built by React or Angular) or forms with relative `action` paths required careful logic. The `urljoin` method was strictly necessary to ensure payloads were posted to the correct absolute URL, regardless of how the target site structured its form actions.
2. **Mitigating False Positives**: Not every reflection of user input guarantees an XSS vulnerability. Distinguishing between raw reflection (dangerous) and HTML-escaped reflection (safe) was a core challenge. The Tkinter script actively identifies whether the injected marker was returned "escaped" (using `html.escape`) or "raw", providing a more accurate threat assessment.
3. **Cross-Origin Restrictions**: Submitting forms blindly can lead to scanning third-party endpoints or search engines unintentionally. Enforcing a `same_origin` check during the scanning loop ensures the tool behaves responsibly and only tests endpoints belonging to the target domain.
4. **GUI Responsiveness**: Within the Tkinter app, running synchronous network requests (`requests.get`/`post`) inside a loop can lock up the main UI thread. Utilizing `root.update_idletasks()` was required to force the GUI log window to refresh and display real-time feedback to the user while waiting for network I/O.
