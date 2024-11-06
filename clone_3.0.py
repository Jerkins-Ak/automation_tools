#!/usr/bin/env python3

import asyncio  # For asynchronous programming
import aiohttp  # For making asynchronous HTTP requests
import json  # For working with JSON data
import os  # For file and directory operations
from bs4 import BeautifulSoup  # For parsing HTML, if needed
from selenium import webdriver  # For controlling the web browser to take screenshots
from selenium.webdriver.chrome.options import Options  # For configuring Chrome browser options

# Configuration settings
username = "babydoom"  # Replace with your actual username for identification
USER_AGENT = f"Intigriti-{username}-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
# Custom headers for the HTTP requests
HEADERS = {
    "User-Agent": USER_AGENT,  # Identifies the request as coming from this specific user-agent
    "X-Bug-Bounty": f"Intigriti-{username}"  # A custom header for bug bounty tracking
}
MAX_REQUESTS_PER_SECOND = 10  # Limit the number of requests per second to prevent overwhelming the target
SCREENSHOTS_PATH = "./screenshots"  # Path where screenshots will be saved
os.makedirs(SCREENSHOTS_PATH, exist_ok=True)  # Create the screenshots directory if it doesn't already exist

# Payloads for different vulnerability types, including CSRF tokens
payloads = {
    "SQL Injection": ["' OR 1=1 --", "' UNION SELECT NULL,NULL --"],  # Common SQL injection payloads
    "NoSQL Injection": ["{$ne:null}", "{$gt: ''}"],  # Common NoSQL injection payloads
    "SSRF": ["http://localhost:80", "http://169.254.169.254"],  # SSRF payloads targeting internal IPs
    "CSRF": ["<input type='hidden' name='csrf_token' value='invalid_token'>"]  # Example CSRF payload
}

# Asynchronous vulnerability scanning function
async def scan_vulnerabilities(domain, payloads):
    findings = []  # List to store any vulnerabilities found

    # Create an asynchronous HTTP session
    async with aiohttp.ClientSession() as session:
        # Loop through each vulnerability type and its payloads
        for vuln_type, vuln_payloads in payloads.items():
            for payload in vuln_payloads:
                url = f"http://{domain}"  # Target domain URL

                # Rate limiting to control request frequency
                await asyncio.sleep(1 / MAX_REQUESTS_PER_SECOND)

                try:
                    # Send GET request with payload and headers
                    async with session.get(url, params={'q': payload}, headers=HEADERS) as response:
                        response_text = await response.text()  # Get response content as text

                        # Initialize variables to track if vulnerability is found and screenshot file path
                        vulnerability_found = False
                        screenshot_file = ""

                        # Check for SQL Injection vulnerability
                        if vuln_type == "SQL Injection" and check_sql_injection(response_text):
                            vulnerability_found = True  # Mark vulnerability as found
                            findings.append({
                                "type": "SQL Injection",  # Type of vulnerability
                                "url": str(response.url),  # The URL accessed
                                "payload": payload,  # The payload used
                                "http_request": str(response.request_info),  # HTTP request information
                                "http_response": response_text[:200]  # First 200 chars of the response
                            })

                        # Check for NoSQL Injection vulnerability
                        elif vuln_type == "NoSQL Injection" and check_nosql_injection(response_text):
                            vulnerability_found = True
                            findings.append({
                                "type": "NoSQL Injection",
                                "url": str(response.url),
                                "payload": payload,
                                "http_request": str(response.request_info),
                                "http_response": response_text[:200]
                            })

                        # Check for SSRF vulnerability
                        elif vuln_type == "SSRF" and check_ssrf(response_text):
                            vulnerability_found = True
                            findings.append({
                                "type": "SSRF",
                                "url": str(response.url),
                                "payload": payload,
                                "http_request": str(response.request_info),
                                "http_response": response_text[:200]
                            })

                        # Check for CSRF vulnerability
                        elif vuln_type == "CSRF" and check_csrf(response_text):
                            vulnerability_found = True
                            findings.append({
                                "type": "CSRF",
                                "url": str(response.url),
                                "payload": payload,
                                "http_request": str(response.request_info),
                                "http_response": response_text[:200]
                            })

                        # If a vulnerability is found, take a screenshot of the page
                        if vulnerability_found:
                            screenshot_file = os.path.join(SCREENSHOTS_PATH, f"{vuln_type}_{payload}.png")
                            take_screenshot(url, screenshot_file)  # Capture screenshot
                            findings[-1]["screenshot"] = screenshot_file  # Store screenshot path in findings

                # Exception handling for any errors that may occur
                except Exception as e:
                    print(f"Error: {e}")

    # Generate a report of all findings once scanning is complete
    generate_report(domain, findings)

# Placeholder functions for checking vulnerabilities and handling results

def check_sql_injection(response_text):
    # Detects SQL Injection by looking for SQL-specific error messages in the response
    return "syntax error" in response_text or "mysql" in response_text.lower()

def check_nosql_injection(response_text):
    # Detects NoSQL Injection by looking for NoSQL error messages in the response
    return "NoSQL" in response_text or "unexpected token" in response_text

def check_ssrf(response_text):
    # Detects SSRF vulnerability by checking for responses from internal IPs or localhost
    return "169.254" in response_text or "localhost" in response_text

def check_csrf(response_text):
    # Detects CSRF vulnerability by looking for invalid CSRF token messages
    return "CSRF token invalid" in response_text or "403 Forbidden" in response_text

def take_screenshot(url, screenshot_file):
    # Initializes the Chrome browser in headless mode and captures a screenshot
    options = Options()
    options.headless = True  # Run Chrome in headless mode (no GUI)
    options.add_argument(f"user-agent={USER_AGENT}")  # Use custom user-agent

    # Launch Chrome browser and open the URL
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    driver.save_screenshot(screenshot_file)  # Save the screenshot
    driver.quit()  # Close the browser

def generate_report(domain, findings):
    # Saves findings as a JSON report file in the screenshots directory
    report_path = os.path.join(SCREENSHOTS_PATH, f"{domain}_report.json")
    with open(report_path, 'w') as report_file:
        json.dump(findings, report_file, indent=4)  # Save findings to JSON with indentation
    print(f"Report saved at {report_path}")  # Output report location

# Example usage of the scan function
if __name__ == "__main__":
    # Prompt the user to input the target domain for the scan
    domain = input("Enter the target domain (e.g., example.com): ").strip()  # Removes leading and trailing whitespace
    asyncio.run(scan_vulnerabilities(domain, payloads))  # Run the scan

