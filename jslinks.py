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

# Regex patterns
js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)

def get_js_files(url):
    """Fetch HTML and extract JavaScript file URLs using regex."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"❌ Failed to fetch {url}")
            return []

        html_content = response.text
        js_files = js_pattern.findall(html_content)

        # Convert relative JS URLs to absolute
        js_files = [urljoin(url, js) for js in js_files]

        return js_files
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
        return []

def extract_endpoints(js_url, parent_url, target_domain):
    """Fetch a JavaScript file and extract possible API endpoints."""
    try:
        response = requests.get(js_url, timeout=10)
        if response.status_code != 200:
            print(f"❌ Failed to fetch {js_url}")
            return []

        js_content = response.text
        endpoints = set()

        # Full URLs under target domain (2+ path segments)
        full_url_pattern = re.compile(rf'https?:\/\/(?:[a-zA-Z0-9-]+\.)*{re.escape(target_domain)}(\/[a-zA-Z0-9\-_]+){2,}')

        # Absolute Paths: At least 2 segments OR meaningful single-word paths
        absolute_path_pattern = re.compile(r'\/[a-zA-Z\-_]+(?:\/[a-zA-Z0-9\-_]+)+|\/[a-zA-Z\-_]{4,}')

        # Relative Filenames: Web-related extensions without a leading slash
        relative_file_pattern = re.compile(r'(?<!\/)[a-zA-Z0-9_-]+\.(php|asp|jsp|aspx|cfm|cgi|pl|py|rb|do|action)\b', re.IGNORECASE)

        # Exclude static files
        excluded_extensions = re.compile(r'\.(js|svg|woff|png|jpg|jpeg|gif|css|ico|map|ttf|otf|eot|pdf|xml|rss|txt|zip|tar|gz)$', re.IGNORECASE)

        for pattern in [full_url_pattern, absolute_path_pattern, relative_file_pattern]:
            matches = pattern.findall(js_content)
            for endpoint in matches:
                # Convert relative paths to absolute
                full_endpoint = urljoin(parent_url, endpoint)

                # Only keep valid URLs
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

        # Extract JavaScript files from the current page
        js_files = get_js_files(current_url)

        for js in js_files:
            if js not in visited_js:
                print(f"📌 Found JS: {js}")
                visited_js.add(js)

                # Extract API endpoints from the JS file
                endpoints = extract_endpoints(js, current_url, domain)

                for endpoint in endpoints:
                    if endpoint not in found_endpoints:
                        found_endpoints.add(endpoint)

                    # Add new API paths to the queue if recursive mode is enabled
                    if args.recursive and endpoint.startswith(target_url) and endpoint not in visited_urls:
                        queue.append(endpoint)

        time.sleep(1)  # Avoid too many requests in a short time

# Save results
save_results()
