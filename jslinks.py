#!/usr/bin/env python3

import requests
import re
import time
import os
from urllib.parse import urljoin, urlparse

def fetch_js_files(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)
        return [urljoin(url, js_file) for js_file in js_pattern.findall(response.text)]
    except Exception:
        print(f"Error fetching JS files from {url}")
        return []

def extract_endpoints(js_url, headers):
    patterns = [
        re.compile(r'https?:\/\/(?:[a-zA-Z0-9.-]+)\.[a-zA-Z0-9.-]+(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?'),
        re.compile(r'\/(?:api|v\d+|graphql|gql|rest|wp-json|endpoint|service|data|public|private|internal|external)(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?'),
        re.compile(r'(?<![\/\w])(?:api|v\d+|graphql|gql|rest|wp-json|endpoint|service|data|public|private|internal|external)(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?(?![a-zA-Z0-9_-])'),
        re.compile(r'(["\'])([a-zA-Z][a-zA-Z0-9_-]{2,}\/[a-zA-Z0-9_-]{2,}(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?)(\1)'),
        re.compile(r'(?:"[^"]*"|\'[^\']*\'|)(?<![\w\/])([a-zA-Z][a-zA-Z0-9_-]{1,}\/[a-zA-Z0-9_-]{2,}(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?)(?![\w-])'),
        re.compile(r'(?<!\/)([a-zA-Z][a-zA-Z0-9_-]*\.(?:php|asp|jsp|aspx|cfm|cgi|pl|py|rb|do|action))(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?\b', re.IGNORECASE),
    ]
    try:
        response = requests.get(js_url, headers=headers, timeout=10)
        endpoints = set()
        for pattern in patterns:
            matches = pattern.findall(response.text)
            if pattern.pattern.startswith(r'(["\'])'):
                endpoints.update(match[1] for match in matches)
            else:
                endpoints.update(matches)
        return endpoints
    except Exception:
        print(f"Error extracting endpoints from {js_url}")
        return set()

def normalize_endpoint(endpoint, base_url):
    """Normalize an endpoint to a full URL using the base URL of the JS file."""
    parsed_base = urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
    
    if endpoint.startswith(('http://', 'https://')):
        return endpoint  # Already a full URL
    elif endpoint.startswith('/'):
        return urljoin(base_domain, endpoint)  # Absolute path, prepend base domain
    elif '.' in endpoint and not endpoint.startswith('/'):
        # Likely a subdomain or full domain without protocol (e.g., api.example.com/path)
        if not endpoint.startswith(('http://', 'https://')):
            return f"https://{endpoint}"
        return endpoint
    else:
        return urljoin(base_domain, endpoint)  # Relative path, resolve with base URL

def jslinks(domains=None, domain_list=None, js_file=None, output="endpoints.txt", recursive=False, headers=None):
    # Default headers if none provided
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    }
    headers = headers if headers else default_headers
    
    all_domains = []
    if domains:
        all_domains.extend(domains if isinstance(domains, list) else [domains])
    if domain_list:
        with open(domain_list) as f:
            all_domains.extend(f.read().splitlines())
    
    urls_to_crawl = []
    if all_domains:
        urls_to_crawl.extend([f"https://{d}" for d in all_domains if not d.startswith(('http://', 'https://'))] + \
                            [d for d in all_domains if d.startswith(('http://', 'https://'))])
    if js_file:
        with open(js_file) as f:
            urls_to_crawl.extend(f.read().splitlines())

    if not urls_to_crawl:
        print("❌ No URLs to crawl. Provide at least -d, -l, or -j.")
        return []

    found_endpoints = set()
    # Load existing endpoints if file exists
    if os.path.exists(output):
        with open(output, "r") as f:
            found_endpoints.update(line.strip() for line in f if line.strip())
    
    visited_js = set()
    queue = urls_to_crawl.copy()

    while queue:
        url = queue.pop(0)
        js_files = fetch_js_files(url, headers)
        for js in js_files:
            if js not in visited_js:
                visited_js.add(js)
                endpoints = extract_endpoints(js, headers)
                # Normalize endpoints with the JS file's base URL
                normalized_endpoints = {normalize_endpoint(ep, js) for ep in endpoints}
                found_endpoints.update(normalized_endpoints)
                if recursive:
                    for endpoint in normalized_endpoints:
                        if endpoint.endswith('.js') and endpoint not in visited_js and endpoint not in queue:
                            queue.append(endpoint)
        time.sleep(1)
    
    # Sort and write (append mode if file existed, otherwise overwrite)
    with open(output, "w") as f:
        f.write("\n".join(sorted(found_endpoints)))
    print(f"✅ Results saved in {output} (sorted and deduplicated)")
    
    return list(found_endpoints)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract JS endpoints")
    parser.add_argument("-d", "--domains", nargs="*", help="List of domains")
    parser.add_argument("-l", "--domain-list", help="File with domains")
    parser.add_argument("-j", "--js-file", help="File with JS URLs")
    parser.add_argument("-o", "--output", default="endpoints.txt", help="Output file (default: endpoints.txt)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive extraction")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (format: 'Header-Name: value')")
    args = parser.parse_args()
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            try:
                key, value = h.split(":", 1)
                custom_headers[key.strip()] = value.strip()
            except ValueError:
                print(f"❌ Invalid header format: {h} (should be 'Header-Name: value')")
                exit(1)
    
    endpoints = jslinks(
        domains=args.domains,
        domain_list=args.domain_list,
        js_file=args.js_file,
        output=args.output,
        recursive=args.recursive,
        headers=custom_headers
    )