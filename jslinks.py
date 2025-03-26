#!/usr/bin/env python3

import requests
import re
import argparse
import time
from urllib.parse import urljoin, urlparse

# Argument parsing
parser = argparse.ArgumentParser(description="Extract unique API endpoints from JavaScript files recursively.")
parser.add_argument("-d", "--domain", help="Single target domain (e.g., example.com)")
parser.add_argument("-l", "--list", help="File containing multiple domains (one per line)")
parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive extraction")
parser.add_argument("-o", "--output", default="endpoints.txt", help="Output file (default: endpoints.txt)")
parser.add_argument("-H", "--header", action="append", help="Custom headers (format: 'Header-Name: value')")
args = parser.parse_args()

# Read domains from file or use a single domain
domains = []
if args.list:
    with open(args.list, "r") as file:
        domains = [line.strip() for line in file if line.strip()]
elif args.domain:
    domains = [args.domain]
else:
    print("❌ Please provide either -d <domain> or -l <domain_list.txt>")
    exit(1)

output_file = args.output  # Output filename
visited_js = set()
visited_urls = set()
queue = []
found_endpoints = set()

# Default headers to mimic a browser
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

# If user provides custom headers, override defaults
if args.header:
    for h in args.header:
        try:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
        except ValueError:
            print(f"❌ Invalid header format: {h} (should be 'Header-Name: value')")
            exit(1)

# Regex patterns
js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)

def get_js_files(url):
    """Fetch HTML and extract JavaScript file URLs using regex."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"❌ Failed to fetch {url}")
            return []
        html_content = response.text
        js_files = js_pattern.findall(html_content)
        return [urljoin(url, js) for js in js_files]
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
        return []

def extract_endpoints(js_url, parent_url, target_domain):
    """Fetch a JavaScript file and extract possible API endpoints."""
    try:
        response = requests.get(js_url, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"❌ Failed to fetch {js_url}")
            return []
        js_content = response.text
        endpoints = set()

        full_url_pattern = re.compile(rf'https?:\/\/(?:[a-zA-Z0-9-]+\.)*{re.escape(target_domain)}(\/[a-zA-Z0-9\-_]+){2,}')
        absolute_path_pattern = re.compile(r'\/[a-zA-Z\-_]+(?:\/[a-zA-Z0-9\-_]+)+|\/[a-zA-Z\-_]{4,}')
        relative_file_pattern = re.compile(r'(?<!\/)[a-zA-Z0-9_-]+\.(php|asp|jsp|aspx|cfm|cgi|pl|py|rb|do|action)\b', re.IGNORECASE)
        excluded_extensions = re.compile(r'\.(js|svg|woff|png|jpg|jpeg|gif|css|ico|map|ttf|otf|eot|pdf|xml|rss|txt|zip|tar|gz)$', re.IGNORECASE)

        for pattern in [full_url_pattern, absolute_path_pattern, relative_file_pattern]:
            matches = pattern.findall(js_content)
            for endpoint in matches:
                full_endpoint = urljoin(parent_url, endpoint)
                if not excluded_extensions.search(full_endpoint):
                    parsed_url = urlparse(full_endpoint)
                    if target_domain in parsed_url.netloc:
                        endpoints.add(full_endpoint)
        return endpoints
    except Exception as e:
        print(f"❌ Error fetching JS file {js_url}: {e}")
        return []

def save_results():
    """Save unique and sorted results to a file."""
    with open(output_file, "w") as f:
        for endpoint in sorted(found_endpoints):
            f.write(endpoint + "\n")
    print(f"✅ Results saved in {output_file}")

# Process each domain
for domain in domains:
    print(f"🔍 Processing domain: {domain}")
    target_url = f"https://{domain}"
    queue = [target_url]

    while queue:
        current_url = queue.pop(0)
        if current_url in visited_urls:
            continue
        print(f"🔍 Scanning: {current_url}")
        visited_urls.add(current_url)

        js_files = get_js_files(current_url)
        for js in js_files:
            if js not in visited_js:
                print(f"📌 Found JS: {js}")
                visited_js.add(js)
                endpoints = extract_endpoints(js, current_url, domain)
                for endpoint in endpoints:
                    if endpoint not in found_endpoints:
                        found_endpoints.add(endpoint)
                    if args.recursive and endpoint.startswith(target_url) and endpoint not in visited_urls:
                        queue.append(endpoint)
        time.sleep(1)  # Avoid too many requests in a short time

# Save results
save_results()
