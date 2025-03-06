from flask import Flask, render_template, request, jsonify
import requests
import time
import json
import re
import os
import csv
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import minimal required ML components
import numpy as np
import pickle
import importlib.util

# Suppress matplotlib warnings and plots
os.environ['MPLBACKEND'] = 'Agg'  # Force non-interactive backend

# Define the folder where scan results will be stored
RESULTS_FOLDER = os.path.join(os.getcwd(), "scan_results")

# Ensure the folder exists
if not os.path.exists(RESULTS_FOLDER):
    os.makedirs(RESULTS_FOLDER)

# List of SSRF payloads to test against candidate endpoints
ssrf_payloads = [
    'http://127.0.0.1',
    'http://localhost',
    'http://[::1]',
    'http://169.254.169.254',   # AWS metadata endpoint
    'http://127.0.0.1:25',      # SMTP port
    'file:///etc/passwd',       # Local file inclusion
    'gopher://127.0.0.1:25/_HELO%20localhost'  # Protocol abuse
]

# Attack types mapping from ML model
attack_type_mapping = {
    0: "Blind SSRF",
    1: "Cloud-Based SSRF",
    2: "DNS Rebinding SSRF",
    3: "External SSRF",
    4: "Internal SSRF",
    5: "Protocol Abuse SSRF"
}

# Enhanced CWE and mitigation mapping directly from ml_ssrf_remediation.py
cwe_name_mapping = {
    918: "Server-Side Request Forgery (SSRF)",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    352: "Cross-Site Request Forgery (CSRF)",
    400: "Uncontrolled Resource Consumption",
    601: "URL Redirection to Untrusted Site ('Open Redirect')",
    829: "Inclusion of Functionality from Untrusted Control Sphere",
    94: "Code Injection",
    287: "Improper Authentication",
    610: "Externally Controlled Reference to a Resource in Another Sphere",
    441: "Unintended Proxy or Intermediary ('Confused Deputy')",
    77: "Command Injection",
    116: "Improper Encoding or Escaping of Output",
    185: "Incorrect Authorization",
    611: "Improper Restriction of XML External Entity Reference (XXE)",
    113: "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
    115: "Improper Neutralization of Input During Writing of Files",
    125: "Out-of-bounds Read",
    1286: "Improper Access Control",
    20: "Improper Input Validation",
    201: "Information Exposure Through Sent Data",
    22: "Path Traversal",
    264: "Permissions, Privileges, and Access Control",
    269: "Improper Privilege Management",
    288: "Authentication Bypass Issues",
    330: "Use of Insufficiently Random Values",
    367: "Time-of-check Time-of-use (TOCTOU) Race Condition",
    425: "Direct Request ('Forced Browsing')",
    434: "Unrestricted File Upload",
    502: "Deserialization of Untrusted Data",
    691: "Insufficient Control Flow Management",
    704: "Incorrect Type Conversion or Cast",
    74: "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    79: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    807: "Reliance on Untrusted Inputs in a Security Decision",
    835: "Loop with Unreachable Exit Condition ('Infinite Loop')",
    862: "Missing Authorization",
    91: "XML Injection (aka Blind XPath Injection)"
}

# Comprehensive mitigation mapping for SSRF vulnerabilities
# Combining CWE-specific mitigations for SSRF attack types
mitigation_mapping = {
    # Blind SSRF
    0: {
        918: "Implement outbound connection restrictions, URL allowlists, and blind SSRF detection mechanisms",
        200: "Prevent information disclosure via blind SSRF by implementing strict filtering and monitoring of outbound requests",
        352: "Prevent CSRF and blind SSRF attacks with proper tokens and URL validation",
        20: "Implement strict input validation specifically targeting blind SSRF payloads",
        'default': "Disable dangerous protocols and implement strict URL validation for blind SSRF prevention"
    },
    # Cloud-Based SSRF
    1: {
        918: "Block access to cloud metadata endpoints, implement instance profile limitations, and use network-level controls",
        200: "Prevent cloud metadata exposure by blocking well-known cloud metadata IP addresses and paths",
        829: "Implement network segregation, metadata service blocks, and strict URL validation",
        264: "Apply least privilege for cloud resources, block metadata access, and implement strong IAM policies",
        'default': "Block access to cloud metadata endpoints and use network-level controls"
    },
    # DNS Rebinding SSRF
    2: {
        918: "Implement DNS pinning, hostname validation, and strict domain checks to prevent DNS rebinding attacks",
        352: "Use proper hostname validation and implement DNS rebinding protections in addition to CSRF controls",
        807: "Validate hostnames both at request time and resolution time to prevent DNS rebinding attacks",
        'default': "Implement DNS pinning and proper host validation"
    },
    # External SSRF
    3: {
        918: "Use allowlists for external domains, implement outbound firewall rules, and validate all external URLs",
        610: "Restrict which external domains can be accessed and implement strict URL validation",
        601: "Implement URL validation and filtering for open redirects that could lead to SSRF exploitation",
        'default': "Use allowlists and validate all external URLs"
    },
    # Internal SSRF
    4: {
        918: "Disable access to internal networks, implement URL filtering to block private IP ranges, use network segmentation",
        441: "Prevent confused deputy attacks with proper authentication and restrictions on internal network access",
        610: "Implement strict controls on requests to internal resources and sensitive endpoints",
        'default': "Disable access to internal networks and implement strict validation"
    },
    # Protocol Abuse SSRF
    5: {
        918: "Disable dangerous URL schemes (file://, gopher://, etc.), whitelist allowed protocols, and implement protocol filtering",
        611: "Disable XML external entity processing to prevent XXE-based SSRF attacks",
        94: "Implement strict protocol filtering to prevent code injection via protocol abuse",
        'default': "Disable dangerous URL schemes and implement protocol filtering"
    },
    # General SSRF (for predictions without specific attack type)
    20: {
        918: "Restrict internal network access, validate user input, use allowlists for URLs, implement proper authentication",
        'default': "Implement comprehensive SSRF defenses including URL validation, network controls, and proper access restrictions"
    }
}

def get_specific_mitigation(attack_type_code, cwe_id):
    """
    Get specific mitigation based on attack type and CWE ID
    """
    # Convert string CWE-ID to integer if needed
    if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
        try:
            cwe_id = int(cwe_id.replace("CWE-", ""))
        except ValueError:
            cwe_id = 918  # Default to SSRF CWE if conversion fails
    
    # Default to CWE-918 if not specified or invalid
    if not isinstance(cwe_id, int):
        cwe_id = 918
    
    # Get mitigation based on attack type and CWE
    attack_mitigations = mitigation_mapping.get(attack_type_code, mitigation_mapping[20])
    mitigation = attack_mitigations.get(cwe_id, attack_mitigations.get('default', mitigation_mapping[20]['default']))
    
    return mitigation

def load_ml_model(quiet=False):
    """
    Load the trained ML model without displaying graphs/visualizations
    """
    # First try to load directly from pickle file
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decision_tree_model.pkl")
    if os.path.exists(model_path):
        try:
            with open(model_path, "rb") as f:
                model = pickle.load(f)
            if not quiet:
                print("[+] Successfully loaded pre-trained SSRF detection model")
            return model
        except Exception as e:
            if not quiet:
                print(f"[-] Error loading model from file: {e}")
    
    # If pickle load fails, try to import from module with visualization suppression
    try:
        # Import matplotlib and completely disable plotting functionality
        import matplotlib
        matplotlib.use('Agg')  # Non-interactive backend
        import matplotlib.pyplot as plt
        old_show = plt.show
        plt.show = lambda *args, **kwargs: None  # No-op function
        
        # Now try to import the module
        spec = importlib.util.spec_from_file_location(
            "ml_ssrf_remediation", 
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_ssrf_remediation.py")
        )
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Restore plt.show
            plt.show = old_show
            
            if hasattr(module, 'loaded_model'):
                if not quiet:
                    print("[+] Using trained model from ml_ssrf_remediation.py")
                return module.loaded_model
            elif hasattr(module, 'dt_model'):
                if not quiet:
                    print("[+] Using decision tree model from ml_ssrf_remediation.py")
                return module.dt_model
    
    except Exception as e:
        if not quiet:
            print(f"[-] Error importing ml_ssrf_remediation module: {e}")
    
    # Return None if no model found
    if not quiet:
        print("[!] No SSRF detection model available - will use heuristic detection only")
    return None

def init_driver():
    """Initialize a headless Chrome WebDriver."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--log-level=3")  # Suppress WebDriver logs
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def is_valid_url(url):
    """Check if the URL has a scheme and network location."""
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

def selenium_crawl(driver, url, visited, base_domain, max_depth=3, depth=0):
    """
    Recursively crawl pages using Selenium to capture dynamic content.
    """
    if depth > max_depth or url in visited:
        return []
    visited.add(url)
    print(f"Crawling: {url} (Depth: {depth})")
    try:
        driver.get(url)
        # Wait briefly for dynamic content to load
        time.sleep(2)
    except Exception as e:
        print(f"Error loading {url}: {e}")
        return []
    
    html = driver.page_source
    soup = BeautifulSoup(html, 'html.parser')
    found_urls = []
    
    # Find links from anchor tags
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        full_url = urljoin(url, href)
        parsed_full = urlparse(full_url)
        if is_valid_url(full_url) and parsed_full.netloc == base_domain and full_url not in visited:
            found_urls.append(full_url)
            found_urls.extend(selenium_crawl(driver, full_url, visited, base_domain, max_depth, depth + 1))
    
    # Find form actions
    for form in soup.find_all('form', action=True):
        action = form.get('action')
        form_url = urljoin(url, action)
        if is_valid_url(form_url) and urlparse(form_url).netloc == base_domain and form_url not in visited:
            found_urls.append(form_url)
    
    return list(set(found_urls))

def find_ssrf_candidates(urls):
    """
    Identify URLs with query parameters commonly used in SSRF vulnerabilities
    """
    candidates = []
    pattern = re.compile(r'(url|uri|target|path|file|redirect|src|dest|location|href|site|go|image|proxy|content)', re.IGNORECASE)
    for url in urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param in qs:
            if pattern.search(param):
                candidates.append(url)
                break
    return list(set(candidates))

def determine_cwe_id(url, payload, response_data):
    """
    Determine the most likely CWE ID based on the response and payload
    """
    # Default to CWE-918 (SSRF)
    cwe_id = 918
    
    # Check response patterns for other CWE possibilities
    if 'file://' in payload and response_data.get('status_code', 0) == 200:
        # File inclusion suggests CWE-22 (Path Traversal)
        cwe_id = 22
    elif '169.254.169.254' in payload and response_data.get('content_different', False):
        # Cloud metadata access suggests CWE-200 (Information Exposure)
        cwe_id = 200
    elif 'gopher://' in payload and response_data.get('status_code', 0) < 400:
        # Protocol abuse can be CWE-74 (Injection) or CWE-94 (Code Injection)
        cwe_id = 94
    elif payload.endswith(':25') and response_data.get('timing_diff', 0) > 1.0:
        # SMTP access suggests CWE-441 (Confused Deputy)
        cwe_id = 441
    
    # Additional heuristics for other CWEs could be added here
    
    return cwe_id

def extract_features_for_ml(url, payload, response_data):
    """
    Extract relevant features for ML model prediction
    """
    # Determine attack type based on payload pattern
    attack_type_code = 3  # Default to External SSRF
    
    if '127.0.0.1' in payload or 'localhost' in payload or '[::1]' in payload:
        attack_type_code = 4  # Internal SSRF
    elif '169.254.169.254' in payload:
        attack_type_code = 1  # Cloud-Based SSRF
    elif 'file://' in payload:
        attack_type_code = 5  # Protocol Abuse SSRF
    elif 'gopher://' in payload:
        attack_type_code = 5  # Protocol Abuse SSRF
    
    # Determine CWE ID based on response and payload
    cwe_id = determine_cwe_id(url, payload, response_data)
    
    # Extract additional features that could be used by an advanced ML model
    features = {
        'cwe_id': cwe_id,
        'attack_type': attack_type_code,
        'status_code': response_data.get('status_code', 0),
        'content_length': response_data.get('content_length', 0),
        'content_diff': response_data.get('content_different', False),
        'response_time': response_data.get('response_time', 0),
        'timing_diff': response_data.get('timing_diff', 0)
    }
    
    return features

def predict_ssrf_vulnerability(model, url, response_data, payload):
    """
    Use ML to predict SSRF vulnerabilities and determine confidence score
    """
    # Extract features for ML model
    features = extract_features_for_ml(url, payload, response_data)
    attack_type_code = features['attack_type']
    cwe_id = features['cwe_id']
    
    # Initialize base confidence using response characteristics
    confidence = 0.5
    
    # Adjust confidence based on response indicators
    if features['content_diff']:
        confidence += 0.2  # Content differences are strong indicators
    
    # Status code impact on confidence
    status_code = features['status_code']
    if status_code >= 200 and status_code < 300:
        confidence += 0.1  # Successful responses
    elif status_code >= 300 and status_code < 400:
        confidence += 0.05  # Redirects
    elif status_code >= 500:
        confidence += 0.1  # Server errors might indicate successful SSRF
    
    # Analyze timing differences
    if features['timing_diff'] > 1.0:
        confidence += 0.1  # Significant timing differences
    
    # Use ML model if available for more accurate prediction
    predicted_mitigation = None
    if model and hasattr(model, 'predict'):
        try:
            # Create input features for ML model - use only numeric features
            # to avoid the "no valid feature names" warning
            ml_features = np.array([[features['cwe_id'], features['attack_type']]])
            prediction = model.predict(ml_features)[0]
            predicted_mitigation = prediction
            
            # Calculate ML-based confidence boost
            if attack_type_code in [1, 4, 5]:  # Cloud, Internal, Protocol Abuse
                confidence += 0.15
            else:
                confidence += 0.10
                
            # Use prediction probability if available for more accurate confidence
            if hasattr(model, 'predict_proba'):
                try:
                    probs = model.predict_proba(ml_features)[0]
                    max_prob = max(probs)
                    # Blend ML probability with heuristic confidence
                    confidence = 0.4 * confidence + 0.6 * max_prob
                except Exception:
                    pass
        except Exception as e:
            pass
    
    # Get specific mitigation based on attack type and CWE ID
    mitigation = get_specific_mitigation(attack_type_code, cwe_id)
    
    # If we have a CWE name, include it in the response
    cwe_name = cwe_name_mapping.get(cwe_id, f"CWE-{cwe_id}")
    
    return {
        "attack_type": attack_type_mapping.get(attack_type_code, "External SSRF"),
        "confidence": min(confidence, 0.95),  # Cap at 0.95
        "payload": payload,
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "mitigation": mitigation
    }

def test_ssrf(url, ml_model=None):
    """Test URL for SSRF vulnerabilities with payloads"""
    results = {}
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    pattern = re.compile(r'(url|uri|target|path|file|redirect|src|dest|location|href|site|go|image|proxy|content)', re.IGNORECASE)
    
    # Get original response for comparison
    original_response = None
    try:
        start_time = time.time()
        resp = requests.get(url, timeout=5)
        end_time = time.time()
        original_response = {
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "content_hash": hash(resp.text[:500]),
            "headers": dict(resp.headers),
            "response_time": end_time - start_time
        }
    except Exception as e:
        print(f"[-] Error fetching original URL {url}: {e}")
        original_response = None
    
    for param in qs:
        if pattern.search(param):
            param_results = {}
            
            for payload in ssrf_payloads:
                qs_modified = qs.copy()
                qs_modified[param] = [payload]
                new_query = urlencode(qs_modified, doseq=True)
                modified_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                          parsed.params, new_query, parsed.fragment))
                try:
                    # Adding custom headers to potentially bypass restrictions
                    custom_headers = {
                        'X-Forwarded-For': '127.0.0.1',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    
                    start_time = time.time()
                    resp = requests.get(modified_url, timeout=5, allow_redirects=False, headers=custom_headers)
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    response_data = {
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "payload": payload,
                        "headers": dict(resp.headers),
                        "response_time": response_time
                    }
                    
                    # Detect content changes more thoroughly
                    if original_response:
                        # Check content hash
                        content_hash = hash(resp.text[:500])
                        content_different = (content_hash != original_response["content_hash"])
                        
                        # Check headers for SSRF indicators
                        if not content_different:
                            # Check for specific header changes that might indicate SSRF
                            header_diff = False
                            for key in ['server', 'x-powered-by', 'content-type']:
                                if (key in resp.headers) != (key in original_response["headers"]):
                                    header_diff = True
                                    break
                            if header_diff:
                                content_different = True
                                
                        # Check for timing differences
                        timing_diff = abs(response_time - original_response["response_time"])
                        response_data["timing_diff"] = timing_diff
                        
                        response_data["content_different"] = content_different
                    
                    # Get ML prediction
                    prediction = predict_ssrf_vulnerability(ml_model, modified_url, response_data, payload)
                    response_data["prediction"] = prediction
                    
                    param_results[modified_url] = response_data
                except Exception as e:
                    param_results[modified_url] = {"error": str(e), "payload": payload}
            
            results[param] = param_results
    
    return results

def analyze_ssrf_results(ssrf_results):
    """Analyze test results to identify actual SSRF vulnerabilities"""
    vulnerability_report = {
        "vulnerable_endpoints": [],
        "potential_endpoints": []
    }
    
    for candidate_url, results in ssrf_results.items():
        if isinstance(results, dict) and "error" in results:
            continue
            
        high_confidence_predictions = []
        medium_confidence_predictions = []
        
        for param, param_results in results.items():
            # Initialize payload_success_count for each parameter
            payload_success_count = 0
            
            for test_url, response_data in param_results.items():
                if "error" in response_data:
                    continue
                
                # Count successful payload tests
                if response_data.get("status_code", 0) >= 200 and response_data.get("status_code", 0) < 400:
                    payload_success_count += 1
                    
                if "prediction" in response_data:
                    prediction = response_data["prediction"]
                    payload = response_data.get("payload", "unknown")
                    
                    if prediction["confidence"] >= 0.75:
                        high_confidence_predictions.append({
                            "test_url": test_url,
                            "attack_type": prediction["attack_type"],
                            "confidence": prediction["confidence"],
                            "cwe_id": prediction.get("cwe_id", 918),
                            "cwe_name": prediction.get("cwe_name", "Server-Side Request Forgery (SSRF)"),
                            "mitigation": prediction["mitigation"],
                            "payload": payload
                        })
                    elif prediction["confidence"] >= 0.6:
                        medium_confidence_predictions.append({
                            "test_url": test_url,
                            "attack_type": prediction["attack_type"],
                            "confidence": prediction["confidence"],
                            "cwe_id": prediction.get("cwe_id", 918),
                            "cwe_name": prediction.get("cwe_name", "Server-Side Request Forgery (SSRF)"),
                            "mitigation": prediction["mitigation"],
                            "payload": payload
                        })
        
            # Additional heuristic: If multiple payloads worked, it's likely vulnerable
            if payload_success_count >= 4:
                # This is a strong indicator of SSRF vulnerability
                if not high_confidence_predictions and medium_confidence_predictions:
                    # Promote the highest confidence medium prediction to high confidence
                    if medium_confidence_predictions:
                        best_prediction = max(medium_confidence_predictions, key=lambda x: x["confidence"])
                        best_prediction["confidence"] = 0.85  # Boost to high confidence
                        high_confidence_predictions.append(best_prediction)
                        medium_confidence_predictions.remove(best_prediction)
        
        # Add to vulnerability report
        if high_confidence_predictions:
            vulnerability_report["vulnerable_endpoints"].append({
                "url": candidate_url,
                "predictions": high_confidence_predictions
            })
        elif medium_confidence_predictions:
            vulnerability_report["potential_endpoints"].append({
                "url": candidate_url,
                "predictions": medium_confidence_predictions
            })
    
    return vulnerability_report

def save_results_to_csv(vulnerability_report, filename="ssrf_results.csv"):
    """Save vulnerability results to CSV file"""
    file_path = os.path.join(RESULTS_FOLDER, filename)
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['url', 'attack_type', 'confidence', 'payload', 'cwe_id', 'cwe_name', 'mitigation']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Add confirmed vulnerabilities
        for endpoint in vulnerability_report["vulnerable_endpoints"]:
            url = endpoint["url"]
            for pred in endpoint["predictions"]:
                writer.writerow({
                    'url': url,
                    'attack_type': pred["attack_type"],
                    'confidence': f"{pred['confidence']:.2f}",
                    'payload': pred["payload"],
                    'cwe_id': pred.get("cwe_id", 918),
                    'cwe_name': pred.get("cwe_name", "Server-Side Request Forgery (SSRF)"),
                    'mitigation': pred["mitigation"]
                })
        
        # Add potential vulnerabilities
        for endpoint in vulnerability_report["potential_endpoints"]:
            url = endpoint["url"]
            for pred in endpoint["predictions"]:
                writer.writerow({
                    'url': url,
                    'attack_type': pred["attack_type"],
                    'confidence': f"{pred['confidence']:.2f}",
                    'payload': pred["payload"],
                    'cwe_id': pred.get("cwe_id", 918),
                    'cwe_name': pred.get("cwe_name", "Server-Side Request Forgery (SSRF)"),
                    'mitigation': pred["mitigation"]
                })

    print(f"[+] Results saved to {file_path}")

app = Flask(__name__)

@app.route("/")
def index():
    """ Serves the SSRF Visualization Page """
    return render_template("index.html")

@app.route("/crawl", methods=["POST"])
def crawl():
    """Runs SSRF crawler and returns discovered URLs."""
    target_url = request.json.get("url")
    target_domain = urlparse(target_url).netloc
    
    if not target_url:
        return jsonify({"error": "Missing target URL"}), 400
    
    print("\n===== SSRF Vulnerability Scanner =====")
    print(f"Target: {target_url}")
    print(f"Domain: {target_domain}")

    # Load ML model for SSRF classification
    ml_model = load_ml_model()

    driver = init_driver()

    print("\n[*] Starting dynamic crawl...")
    base_domain = urlparse(target_url).netloc
    visited = set()
    all_urls = selenium_crawl(driver, target_url, visited, base_domain, max_depth=3)
    print(f"[+] Found {len(all_urls)} internal URLs")

    candidates = find_ssrf_candidates(all_urls)
    print(f"[*] Testing {len(candidates)} potential SSRF endpoints")

    # Look for additional candidates based on common SSRF patterns
    for url in all_urls:
        # Check for common SSRF vulnerability patterns in URL paths
        if any(pattern in url.lower() for pattern in ['redirect', 'url', 'link', 'go', 'return', 'continue']):
            if url not in candidates:
                candidates.append(url)
                print(f"[+] Added potential SSRF endpoint: {url}")
    
    ssrf_results = {}
    # Use ThreadPoolExecutor to speed up SSRF testing concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_candidate = {executor.submit(test_ssrf, candidate, ml_model): candidate for candidate in candidates}
        for future in as_completed(future_to_candidate):
            candidate = future_to_candidate[future]
            try:
                test_results = future.result()
                ssrf_results[candidate] = test_results
            except Exception as e:
                print(f"[-] Error testing {candidate}: {str(e)}")
                ssrf_results[candidate] = {"error": str(e)}
    
    # Analyze results to find vulnerabilities
    vulnerability_report = analyze_ssrf_results(ssrf_results)

    # Add vulnerability report to results
    ssrf_results["vulnerability_report"] = vulnerability_report

    # Save detailed results to JSON
    file_path = os.path.join(RESULTS_FOLDER, "ssrf_results.json")
    with open(file_path, "w") as f:
        json.dump(ssrf_results, f, indent=2)

    print(f"[+] Results saved to {file_path}")

    # Also save to CSV for spreadsheet analysis
    save_results_to_csv(vulnerability_report)

    # Print summary
    print("\n===== SSRF Scan Results =====")
    print(f"Total URLs scanned: {len(all_urls)}")
    print(f"Potential SSRF endpoints tested: {len(candidates)}")
    print(f"Confirmed vulnerable endpoints: {len(vulnerability_report['vulnerable_endpoints'])}")
    print(f"Potential vulnerable endpoints: {len(vulnerability_report['potential_endpoints'])}")

    # Count attack types
    attack_type_counts = {}

    # Print discovered vulnerabilities
    if vulnerability_report["vulnerable_endpoints"]:
        print("\n[!] SSRF VULNERABILITIES FOUND:")
        for endpoint in vulnerability_report["vulnerable_endpoints"]:
            print(f"\n[!] Vulnerable URL: {endpoint['url']}")
            for pred in endpoint["predictions"]:
                attack_type = pred["attack_type"]
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
                print(f"    - Attack Type: {pred['attack_type']}")
                print(f"    - CWE: {pred.get('cwe_id', 918)} ({pred.get('cwe_name', 'Server-Side Request Forgery')})")
                print(f"    - Confidence: {pred['confidence']:.2f}")
                print(f"    - Payload: {pred['payload']}")
                print(f"    - Mitigation: {pred['mitigation']}")

    if vulnerability_report["potential_endpoints"]:
        print("\n[?] Potential SSRF vulnerabilities (needs verification):")
        for endpoint in vulnerability_report["potential_endpoints"]:
            print(f"    * {endpoint['url']}")
            # Show top prediction for context
            if endpoint["predictions"]:
                top_pred = endpoint["predictions"][0]
                print(f"      - Most likely: {top_pred['attack_type']} (CWE-{top_pred.get('cwe_id', 918)})")
                print(f"      - Confidence: {top_pred['confidence']:.2f}")
                print(f"      - Try payload: {top_pred['payload']}")
                print(f"      - Mitigation: {top_pred['mitigation']}")
    
    if not vulnerability_report["vulnerable_endpoints"] and not vulnerability_report["potential_endpoints"]:
        print("\n[+] No SSRF vulnerabilities detected")
    
    print(f"\n[+] Scan completed. Results saved to ssrf_results.json and ssrf_results.csv")
    driver.quit()
    
    # return jsonify({
    #     "message": "Crawling complete",
    #     "target_url": target_url,
    #     "domain": target_domain,
    #     "total_urls_scanned": len(all_urls),
    #     "ssrf_results": ssrf_results,
    # })

    return jsonify({
        "message": "Crawling complete",
        "ssrf_results": ssrf_results,
        "scan_summary": {
            "target_url": target_url,
            "domain": target_domain,
            "total_urls_scanned": len(all_urls),
            "dataset_saved": "ssrf_cve_dataset.csv",
            "confirmed_ssrf_vulnerabilities": len(vulnerability_report['vulnerable_endpoints']),
            "potential_ssrf_endpoints": len(vulnerability_report['potential_endpoints']),
            "attack_type_distribution": attack_type_counts
        }
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
