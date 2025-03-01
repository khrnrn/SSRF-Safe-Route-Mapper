from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

CWE_SSRF_URL = "https://cwe.mitre.org/data/definitions/918.json"

@app.route("/")
def index():
    """ Serves the SSRF Visualization Page """
    return render_template("index.html")

scanned_urls = []

@app.route("/scan", methods=["POST"])
def scan():
    """ Handles SSRF Scanning Requests """
    target_url = request.json.get("url")
    if not target_url:
        return jsonify({"error": "Missing target URL"}), 400

    try:
        response = requests.get(target_url, timeout=5)
        scanned_urls.append(target_url)  # Store scanned URL

        return jsonify({
            "url": target_url,
            "status": response.status_code,
            "content": response.text[:200]  # Limit content for security
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
                       
@app.route("/get_scanned_urls")
def get_scanned_urls():
    """ Returns all scanned URLs """
    return jsonify(scanned_urls)

@app.route("/ssrf_data")
def ssrf_data():
    """ Fetches SSRF vulnerability details from CWE or provides static data """
    try:
        response = requests.get(CWE_SSRF_URL, timeout=5)
        if response.status_code == 200 and "json" in response.headers.get("Content-Type", ""):
            return jsonify(response.json())

        return jsonify({
            "id": "CWE-918",
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "SSRF vulnerabilities occur when an attacker forces a server to make unintended requests.",
            "mitigation": [
                "Validate and sanitize all user inputs.",
                "Use allowlists instead of denylists for internal resources.",
                "Restrict metadata service access from web applications."
            ]
        })
    except Exception as e:
        return jsonify({"error": f"Failed to fetch data: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
