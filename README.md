# Url-Grabber-Scanner

#### Author: **@amitlt2 (Amit Kumar Biswas)**

**X:** **https://x.com/amitlt2**

#### Description: 
A fancy and powerful URL gathering tool for bug bounty hunters. This tool extracts URLs, JavaScript files, and parameters from various online sources and archives. It also supports subdomain enumeration and filtering with colors for better readability.

#### Features
* Gather URLs from multiple sources:
- Common Crawl
- AlienVault OTX
- URLScan.io
- SecurityTrails
- Wayback Machine & GAU
* Enumerate subdomains using subfinder and extract URLs
* Filter JavaScript files (-x js)
* Extract URLs containing parameters (--param)
* Save results in a text file (-o output.txt)

### Installation Guide
#### Prerequisites
Ensure you have the following installed:
* Python 3
* Golang (for external tools)

#### Install Required Python Packages
```
pip install -r requirements.txt
```

#### Install External Tools
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```
```
go install github.com/lc/gau/v2/cmd/gau@latest
```
```
go install github.com/tomnomnom/waybackurls@latest
```

#### Usage
```
python url_grabber.py -u example.com         # Gather URLs for a single domain
```

```
python url_grabber.py -d example.com         # Enumerate subdomains and extract URLs
```

```
python url_grabber.py -x js -u example.com   # Extract JavaScript files
```

```
python url_grabber.py --param -u example.com # Extract URLs with parameters
```

```
python url_grabber.py -o results.txt -u example.com # Save output to a text file
```

#### Contribution

Feel free to fork and contribute! PRs are welcome. 🚀

#### License

This project is licensed under the MIT License.

Happy Bug Hunting! 🐞

