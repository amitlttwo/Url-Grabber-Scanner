import argparse
import subprocess
import requests
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

# Function to fetch URLs from Common Crawl
def fetch_common_crawl(domain):
    url = f"https://index.commoncrawl.org/collinfo.json"
    response = requests.get(url)
    if response.status_code == 200:
        return [f"https://index.commoncrawl.org/{entry['id']}-index" for entry in response.json()]
    return []

# Function to fetch URLs from AlienVault OTX
def fetch_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    response = requests.get(url)
    if response.status_code == 200:
        return [entry['url'] for entry in response.json().get('data', [])]
    return []

# Function to fetch URLs from URLScan.io
def fetch_urlscan(domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    response = requests.get(url)
    if response.status_code == 200:
        return [result['task']['url'] for result in response.json().get('results', [])]
    return []

# Function to fetch URLs from SecurityTrails
def fetch_securitytrails(domain):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": "YOUR_SECURITYTRAILS_API_KEY"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('subdomains', [])
    return []

# Function to fetch URLs using gau & waybackurls
def fetch_wayback_gau(domain):
    gau_urls = subprocess.run(["gau", domain], capture_output=True, text=True).stdout.split("\n")
    wayback_urls = subprocess.run(["waybackurls", domain], capture_output=True, text=True).stdout.split("\n")
    return list(set(gau_urls + wayback_urls))

# Function to extract JavaScript files
def extract_js_files(urls):
    return [url for url in urls if url.endswith(".js")]

# Function to extract parameters from URLs
def extract_parameters(urls):
    return [url for url in urls if "?" in url]

# Function to enumerate subdomains using subfinder
def enumerate_subdomains(domain):
    subdomains = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True).stdout.split("\n")
    return [sub for sub in subdomains if sub]

# Function to save results to a file
def save_to_file(urls, output_file):
    with open(output_file, "w") as f:
        for url in urls:
            f.write(url + "\n")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Urls Grabber Tool")
    parser.add_argument("-u", metavar="URL", type=str, help="Single domain URL gathering")
    parser.add_argument("-d", metavar="DOMAIN", type=str, help="Enumerate subdomains and fetch URLs")
    parser.add_argument("-x", metavar="FILTER", type=str, help="Filter (e.g., js for JavaScript files)")
    parser.add_argument("--param", action="store_true", help="Grab only URLs with parameters")
    parser.add_argument("-o", metavar="OUTPUT", type=str, help="Output results to a text file")
    args = parser.parse_args()
    
    urls = []
    
    with Progress() as progress:
        if args.u:
            task = progress.add_task("[cyan]Fetching URLs for single domain...", total=5)
            urls += fetch_common_crawl(args.u)
            progress.update(task, advance=1)
            urls += fetch_alienvault(args.u)
            progress.update(task, advance=1)
            urls += fetch_urlscan(args.u)
            progress.update(task, advance=1)
            urls += fetch_wayback_gau(args.u)
            progress.update(task, advance=2)
        
        if args.d:
            subdomains = enumerate_subdomains(args.d)
            task = progress.add_task(f"[green]Checking {len(subdomains)} subdomains...", total=len(subdomains))
            for subdomain in subdomains:
                urls += fetch_wayback_gau(subdomain)
                progress.update(task, advance=1)
        
        if args.x == "js":
            urls = extract_js_files(urls)
        
        if args.param:
            urls = extract_parameters(urls)
    
    if args.o:
        save_to_file(urls, args.o)
        console.print(f"[bold yellow]Results saved to {args.o}")
    
    # Fancy Table Output
    table = Table(title="Urls Grabber Results", show_header=True, header_style="bold magenta")
    table.add_column("ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("URL", style="green")
    for i, url in enumerate(set(urls), start=1):
        table.add_row(str(i), url)
    console.print(table)

if __name__ == "__main__":
    main()
