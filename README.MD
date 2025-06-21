# JSLinks

JSLinks is a Python tool designed to extract API endpoints and URLs from JavaScript files by crawling domains or specific JS URLs. It supports recursive crawling and custom headers, making it ideal for web reconnaissance and security testing.

## Features

### Endpoint Extraction:
- Extracts URLs, API paths, and endpoints from JavaScript files using regex patterns.
- Supports full URLs, absolute paths, relative paths, and file extensions (e.g., `.php`).

### Flexible Input:
- Accepts domains, domain lists, or JS file URLs as input.

### Customization:
- Recursive crawling to follow JS links.
- Custom HTTP headers for requests.

### Organized Output:
- Saves sorted, deduplicated endpoints to a specified output file, appending to existing content.

## Installation

### Prerequisites
- Python 3 and `pip` installed.
- Basic Linux tools (`git`, `curl`).

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/omarsamy10/jslinks.git
   cd jslinks
   ```
2. Install dependencies:
   ```bash
   pip install requests
   ```
3. Make the script executable (optional):
   ```bash
   chmod +x jslinks.py
   ```
   Optionally, move it to `/usr/local/bin`:
   ```bash
   sudo mv jslinks.py /usr/local/bin/jslinks
   ```

## Usage
Run `jslinks.py` with the desired options:
```bash
python3 jslinks.py -d example.com -o endpoints.txt
```

### Options
- `-d, --domains`: List of domains to crawl (e.g., `example.com`).
- `-l, --domain-list`: File containing domains (one per line).
- `-j, --js-file`: File containing JS URLs to crawl.
- `-o, --output`: Output file for endpoints (default: `endpoints.txt`).
- `-r, --recursive`: Enable recursive JS crawling.
- `-H, --header`: Custom headers (e.g., `"Authorization: Bearer token"`).

## Output
Results are saved to the specified output file (e.g., `endpoints.txt`), sorted and deduplicated. If the file exists, new endpoints are appended and the file is re-sorted.

## Example
```bash
python3 jslinks.py -d example.com -j js_urls.txt -o results.txt -r -H "User-Agent: CustomAgent"
```
### Output File (`results.txt`)
```
https://api/v1/users
https://api.example.com/account/profile
https://example.com/data
```

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.


## Acknowledgments
Inspired by web reconnaissance tools and workflows.

## Contact
For questions, feedback, or support:
- Twitter: [@omarsamy10](https://twitter.com/00xmora)
- Linkedin: [omarsamy](https://www.linkedin.com/in/00xmora)


Enjoy using JSLinks! 🚀
