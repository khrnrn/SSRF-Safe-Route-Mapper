# SSRF Safe Route Mapper
SSRF Safe Route Mapper is an advanced security tool designed to detect, visualize, and mitigate Server-Side Request Forgery (SSRF) vulnerabilities in web applications. SSRF is a critical security issue that can expose sensitive internal resources and lead to unauthorized access.

## Setup
You'll need to install:
1. Python 3
   - Ensure Python 3.x is installed.

2. Python Libraries (Install via pip)

   Run:

   ```
   pip install flask requests beautifulsoup4 selenium numpy pickle pandas matplotlib seaborn scikit-learn xgboost
   ```
   - flask
   - requests
   - beautifulsoup4
   - selenium
   - numpy
   - pickle
   - pandas
   - matplotlib & seaborn
   - scikit-learn
   - xgboost

3. Chromedriver (For Selenium)

   Install it via:

   ### Linux

   ```
   sudo apt install chromium-chromedriver
   ```

   ### macOS

   ```
   brew install chromedriver
   ```


   Or manually download from: https://sites.google.com/chromium.org/driver/downloads


## How to Use
Download ssrf-safe-route-mapper folder.

```
python app.py
```
