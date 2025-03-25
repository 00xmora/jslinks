import requests
import re
import argparse
import time
from urllib.parse import urljoin

# Argument parsing
parser = argparse.ArgumentParser(description="Extract unique API endpoints from JavaScript files recursively.")
parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive extraction")
args = parser.parse_args()

target_url = f"https://{args.domain}"
visited_js = set()
visited_urls = set()
queue = [target_url]
found_endpoints = set()

# Output file
output_file = "endpoints.txt"

# Regex to extract JavaScript files
js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)

# Regex patterns for API endpoint extraction
endpoint_patterns = [
    re.compile(r'https?:\/\/[a-zA-Z0-9\-_.]+\/[a-zA-Z0-9\-_/]*'),  # Full URLs
    re.compile(r'\/[a-zA-Z0-9\-_/]+'),  # Absolute URLs (e.g., /api/auth)
    re.compile(r'\.\.\/[a-zA-Z0-9\-_/]+'),  # Dotted URLs (e.g., ../api/auth)
    re.compile(r'[a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-]+\.[a-zA-Z]+'),  # Relative URLs with slashes (e.g., text/test.php)
    re.compile(r'[a-zA-Z0-9_\-]+\.[a-zA-Z]+')  # Relative URLs without slashes (e.g., test.php)
]

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

def extract_endpoints(js_url, parent_url):
    """Fetch a JavaScript file and extract possible API endpoints."""
    try:
        response = requests.get(js_url, timeout=10)
        if response.status_code != 200:
            print(f"❌ Failed to fetch {js_url}")
            return []

        js_content = response.text
        endpoints = set()

        for pattern in endpoint_patterns:
            matches = pattern.findall(js_content)
            for endpoint in matches:
                # Resolve relative paths correctly based on parent URL
                full_endpoint = urljoin(parent_url, endpoint)
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

# Recursive processing loop
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
            endpoints = extract_endpoints(js, current_url)

            for endpoint in endpoints:
                if endpoint not in found_endpoints:
                    print(f"🔗 API Found: {endpoint}")
                    found_endpoints.add(endpoint)

                # Add new API paths to the queue if recursive mode is enabled
                if args.recursive and endpoint.startswith(target_url) and endpoint not in visited_urls:
                    queue.append(endpoint)

    time.sleep(1)  # Avoid too many requests in a short time

# Save results
save_results()
