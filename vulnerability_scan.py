#!/usr/bin/env python3

import requests
import json
from fpdf import FPDF

# Define patterns for detecting vulnerabilities
ERROR_PATTERNS = {
    "SQL Injection": ["syntax error", "unclosed quotation", "SQLSTATE"],
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "CSRF": ["unexpected state", "token mismatch"],
    "SSRF": ["internal IP", "169.254.169.254"],
    "RCE": ["uid=", "gid=", "root"]
}

# Function to analyze the server response
def analyze_response(response, payload_category, payload):
    for error in ERROR_PATTERNS.get(payload_category, []):
        if error.lower() in response.text.lower():
            print(f"[{payload_category}] Confirmed issue with payload: {payload}")
            return f"[{payload_category}] Confirmed issue with payload: {payload}"
    return None

# Function to send HTTP requests
def send_request(url, payload, method="GET"):
    try:
        if method == "GET":
            response = requests.get(url, params=payload, timeout=10)
        elif method == "POST":
            response = requests.post(url, data=payload, timeout=10)
        else:
            raise ValueError("Unsupported HTTP method")
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

# Function to run the scan
def run_scan(target_url, payloads):
    results = []
    for category, payload_list in payloads.items():
        print(f"Scanning for {category} vulnerabilities...")
        for payload in payload_list:
            # For GET request
            response = send_request(target_url, {"input": payload}, method="GET")
            if response:
                result = analyze_response(response, category, payload)
                if result:
                    results.append(result)
            # For POST request
            response = send_request(target_url, {"input": payload}, method="POST")
            if response:
                result = analyze_response(response, category, payload)
                if result:
                    results.append(result)
    return results

# Function to generate a PDF report
def generate_report(results, target_url):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Vulnerability Scan Report", ln=True, align="C")
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Target URL: {target_url}", ln=True, align="L")
    pdf.ln(10)

    if results:
        pdf.cell(200, 10, txt="Vulnerabilities Found:", ln=True, align="L")
        pdf.ln(5)
        for result in results:
            pdf.multi_cell(0, 10, txt=result)
    else:
        pdf.cell(200, 10, txt="No vulnerabilities found.", ln=True, align="L")

    pdf.output("scan_report.pdf")
    print("Scan report generated: scan_report.pdf")

# Main function
def main():
    print("Welcome to the Vulnerability Scanner")
    target_url = input("Enter target URL (e.g., http://example.com): ").strip()
    def scan_url(url):
    # Ensure the URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        print(f"Scanning {url}...")

    # Scanning logic here


    # Load payloads from file
    try:
        with open("payloads.json", "r") as file:
            payloads = json.load(file)
    except FileNotFoundError:
        print("Error: payloads.json file not found!")
        return

    print("Starting scan...")
    results = run_scan(target_url, payloads)
    print("Scan complete.")

    if results:
        print("Vulnerabilities found:")
        for result in results:
            print(result)
    else:
        print("No vulnerabilities found.")

    # Generate report
    generate_report(results, target_url)

if __name__ == "__main__":
    main()

