import requests
import joblib
from flask import Flask, request, jsonify
from huggingface_hub import hf_hub_download
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import tldextract
import idna
import re
import Levenshtein
import cv2
import numpy as np
import os
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from googleapiclient.discovery import build

# Initialize Flask app
app = Flask(__name__)

# ===== AI MODEL LOADING =====
# Load AI model & vectorizer from Hugging Face
MODEL_REPO = "abhishek2k6/phishing-detection-ai"

# Download & Load Model
model_path = hf_hub_download(MODEL_REPO, "phishing_model.pkl")
vectorizer_path = hf_hub_download(MODEL_REPO, "vectorizer.pkl")

model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

# ===== PHISHING DETECTION FUNCTIONS =====

def ai_predict(url):
    """Use AI model to predict if a URL is phishing or legitimate."""
    transformed_url = vectorizer.transform([url])
    prediction = model.predict(transformed_url)[0]
    return "Phishing" if prediction == 1 else "Legitimate"

def get_domain_age(url):
    """Fetch domain registration date using WHOIS API."""
    try:
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        api_url = f"https://api.api-ninjas.com/v1/whois?domain={domain}"
        headers = {"X-Api-Key": "qIXsnvklGZWkVYULAHl8yw==ZuieULnWpTomuWUe"}  # Get a free key from API Ninjas

        response = requests.get(api_url, headers=headers).json()
        print("WHOIS API Response:", response)  # Debugging line

        if "created" in response:
            creation_date = datetime.strptime(response["created"], "%Y-%m-%d")
            age_days = (datetime.now() - creation_date).days
            return age_days
        return "Unknown"
    except Exception as e:
        print("WHOIS Error:", str(e))  # Debugging line
        return "Error fetching WHOIS data"

def check_google_safe_browsing(url):
    """Check if the URL is blacklisted by Google Safe Browsing."""
    GOOGLE_API_KEY = "AIzaSyDWXcksbv6kWyUEs5VYez3FU3OTasEcJjQ"
    safe_browsing_service = build("safebrowsing", "v4", developerKey=GOOGLE_API_KEY)
    
    request_body = {
        "client": {"clientId": "fakebuster", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    response = safe_browsing_service.threatMatches().find(body=request_body).execute()
    print("Google Safe Browsing API Response:", response)  # Debugging line
    return bool(response.get("matches"))  # Returns True if blacklisted, False if safe

# ===== WEB SCRAPING FUNCTIONS =====

def fetch_website(url):
    """Fetches the HTML content of a given URL."""
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass
    return None

def extract_website_details(url, html):
    """Extracts title, description, and links from the webpage."""
    soup = BeautifulSoup(html, "html.parser")
    
    title = soup.title.string if soup.title else "No Title Found"
    
    description_tag = soup.find("meta", attrs={"name": "description"})
    description = description_tag["content"] if description_tag else "No Description Found"
    
    links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
    
    return {
        "Title": title,
        "Description": description,
        "Links": links[:10]  # Limiting to 10 for simplicity
    }

def detect_login_forms(html):
    """Detects if the webpage contains a login form."""
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    
    for form in forms:
        if form.find("input", {"type": "password"}):
            return "Login Form Detected"
    
    return "No Login Form Found"

def analyze_phishing_keywords(html):
    """Checks for common phishing keywords in the webpage text."""
    phishing_keywords = ["account verification", "confirm your identity", "update billing", "login immediately", "password reset"]
    
    text_content = " ".join([p.get_text() for p in BeautifulSoup(html, "html.parser").find_all("p")])
    
    detected_keywords = [word for word in phishing_keywords if word.lower() in text_content.lower()]
    
    return detected_keywords if detected_keywords else "No Suspicious Keywords Found"

def check_external_scripts(html, base_url):
    """Lists all external JavaScript files linked on the page."""
    soup = BeautifulSoup(html, "html.parser")
    scripts = [urljoin(base_url, script["src"]) for script in soup.find_all("script", src=True)]
    
    return scripts if scripts else "No External Scripts Found"

def analyze_images(html, base_url):
    """Finds images on the webpage and extracts their URLs."""
    soup = BeautifulSoup(html, "html.parser")
    images = [urljoin(base_url, img["src"]) for img in soup.find_all("img", src=True)]
    
    return images[:5] if images else "No Images Found"

def extract_domain_info(url):
    """Extracts the main domain name from a URL."""
    domain_info = tldextract.extract(url)
    return f"{domain_info.domain}.{domain_info.suffix}"

def web_scraper(url):
    """Runs the full web scraping process for phishing detection."""
    html = fetch_website(url)
    if not html:
        return "Error: Could not retrieve website data."

    details = extract_website_details(url, html)
    login_detection = detect_login_forms(html)
    phishing_analysis = analyze_phishing_keywords(html)
    scripts = check_external_scripts(html, url)
    images = analyze_images(html, url)
    domain = extract_domain_info(url)
    
    return {
        "Domain": domain,
        "Website Details": details,
        "Login Form": login_detection,
        "Phishing Keywords": phishing_analysis,
        "External Scripts": scripts,
        "Images": images
    }

# ===== URL ANALYSIS FUNCTIONS =====

def detect_typosquatting(domain):
    """Checks for typosquatting using Levenshtein distance."""
    trusted_domains = ["google.com", "facebook.com", "paypal.com", "amazon.com", "bankofamerica.com"]
    for trusted in trusted_domains:
        distance = Levenshtein.distance(domain, trusted)
        if distance == 1:  # Only flag domains with slight differences
            return f"Possible Typosquatting: {domain} (Similar to {trusted})"
    return "No Typosquatting Detected"

def detect_homoglyphs(domain):
    """Checks for homoglyph attacks (e.g., rn vs m, l vs 1)."""
    homoglyphs = {"0": "o", "1": "l", "rn": "m", "vv": "w", "vvv": "w"}
    for key, value in homoglyphs.items():
        if key in domain or value in domain:
            return f"Potential Homoglyph Attack: {domain}"
    return "No Homoglyph Attack Detected"

def detect_suspicious_subdomains(subdomain, domain):
    """Flags phishing subdomains pretending to be real sites."""
    phishing_keywords = ["secure", "login", "verify", "bank", "account", "update"]
    for keyword in phishing_keywords:
        if keyword in subdomain:
            return f"Suspicious Subdomain: {subdomain}.{domain}"
    return "No Suspicious Subdomains Found"

def detect_special_characters(domain):
    """Checks for non-ASCII characters in domain names."""
    try:
        ascii_domain = idna.encode(domain).decode("utf-8")
        if ascii_domain != domain:
            return f"Unicode/IDN Domain Detected: {domain} -> {ascii_domain}"
    except Exception:
        return f"Malformed Domain: {domain}"
    return "No Special Characters Found"

def analyze_url(url):
    """Runs all URL analysis checks."""
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    subdomain = domain_info.subdomain
    
    return {
        "Domain": domain,
        "Subdomain": subdomain if subdomain else "None",
        "Typosquatting": detect_typosquatting(domain),
        "Homoglyph Attack": detect_homoglyphs(domain),
        "Suspicious Subdomains": detect_suspicious_subdomains(subdomain, domain),
        "Special Characters": detect_special_characters(domain),
    }

# ===== JAVASCRIPT ANALYSIS FUNCTIONS =====

def detect_hidden_redirects(html_content):
    """Detects hidden JavaScript-based redirects."""
    if not html_content:
        return "Could not retrieve content"

    redirect_patterns = [
        r"window\.location\s*=\s*[\"'](.*?)['\"]",
        r"window\.location\.href\s*=\s*[\"'](.*?)['\"]",
        r"window\.location\.replace\s*\(\s*[\"'](.*?)['\"]\s*\)",
        r"window\.location\.assign\s*\(\s*[\"'](.*?)['\"]\s*\)"
    ]

    found_redirects = []
    for pattern in redirect_patterns:
        matches = re.findall(pattern, html_content)
        found_redirects.extend(matches)

    return f"⚠️ Hidden Redirects Found: {', '.join(found_redirects)}" if found_redirects else "No Suspicious Redirects Found"
def analyze_javascript_redirects(url):
    """Runs all JavaScript & Redirection Analysis checks."""
    html_content = fetch_website(url)

    return {
        "Hidden Redirects": detect_hidden_redirects(html_content),
        "External Scripts": check_external_scripts(html_content, url)
    }

# ===== LOGO ANALYSIS FUNCTIONS =====

def fetch_website_logo(url):
    """Extracts the first logo image from the website."""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Find logo image (common in <img> tags with "logo" in class or alt)
        img_tag = soup.find("img", {"class": lambda x: x and "logo" in x.lower()})
        if not img_tag:
            img_tag = soup.find("img", {"alt": lambda x: x and "logo" in x.lower()})

        if img_tag and img_tag.get("src"):
            logo_url = requests.compat.urljoin(url, img_tag["src"])
            return logo_url
    except Exception:
        pass

    return None

def download_image(image_url):
    """Downloads an image from a URL."""
    try:
        response = requests.get(image_url, stream=True)
        if response.status_code == 200:
            image_array = np.asarray(bytearray(response.content), dtype=np.uint8)
            return cv2.imdecode(image_array, cv2.IMREAD_COLOR)
    except Exception:
        pass

    return None

def compare_logo_with_trusted(logo_image):
    """Compares the extracted logo with trusted logos using SSIM."""
    if not logo_image:
        return "⚠️ No logo found on website"

    LOGO_DIRECTORY = "trusted_logos"
    # Make sure directory exists
    if not os.path.exists(LOGO_DIRECTORY):
        os.makedirs(LOGO_DIRECTORY)
        return "⚠️ Trusted logos directory is empty"

    trusted_logos = [os.path.join(LOGO_DIRECTORY, f) for f in os.listdir(LOGO_DIRECTORY) if f.endswith(".png")]

    for trusted_logo_path in trusted_logos:
        trusted_logo = cv2.imread(trusted_logo_path)

        if trusted_logo is None or logo_image is None:
            continue

        # Resize images to the same dimensions
        trusted_logo = cv2.resize(trusted_logo, (100, 100))
        logo_image = cv2.resize(logo_image, (100, 100))

        # Convert to grayscale for comparison
        trusted_logo_gray = cv2.cvtColor(trusted_logo, cv2.COLOR_BGR2GRAY)
        logo_gray = cv2.cvtColor(logo_image, cv2.COLOR_BGR2GRAY)

        # Compute difference
        diff = cv2.absdiff(trusted_logo_gray, logo_gray)
        score = np.mean(diff)

        # If images are very similar (low difference score), it's legit
        if score < 10:
            return "✅ Logo matches trusted brand"
    
    return "⚠️ Logo does not match known brands (Possible phishing)"

def analyze_website_logo(url):
    """Runs the logo analysis pipeline."""
    logo_url = fetch_website_logo(url)
    if not logo_url:
        return {"Logo URL": "No logo found", "Analysis": "⚠️ No logo detected on site"}

    logo_image = download_image(logo_url)
    logo_analysis = compare_logo_with_trusted(logo_image)

    return {
        "Logo URL": logo_url,
        "Analysis": logo_analysis
    }

# ===== CONTENT DETECTION FUNCTIONS =====

def detect_phishing_text(content):
    """Scans for phishing keywords and urgency tactics."""
    phishing_keywords = [
        "verify your account", "update your payment", "urgent action required", 
        "suspicious activity detected", "confirm your identity", "your account will be locked"
    ]
    
    if not content:
        return "Could not retrieve content"

    soup = BeautifulSoup(content, "html.parser")
    text = soup.get_text().lower()

    found_keywords = [kw for kw in phishing_keywords if kw in text]
    
    return f"⚠️ Phishing Phrases Detected: {', '.join(found_keywords)}" if found_keywords else "No Suspicious Text Found"

def detect_fake_login_forms(content):
    """Checks for suspicious login forms (hidden/malicious)."""
    if not content:
        return "Could not retrieve content"

    soup = BeautifulSoup(content, "html.parser")
    forms = soup.find_all("form")

    suspicious_forms = []
    for form in forms:
        inputs = form.find_all("input")
        has_password_field = any(i.get("type") == "password" for i in inputs)
        has_hidden_fields = any(i.get("type") == "hidden" for i in inputs)

        if has_password_field and has_hidden_fields:
            suspicious_forms.append(str(form))

    return "⚠️ Fake Login Form Detected" if suspicious_forms else "No Suspicious Forms Found"

def analyze_content(url):
    """Runs all content-based detection checks."""
    content = fetch_website(url)
    
    return {
        "Phishing Keywords": detect_phishing_text(content),
        "Fake Login Forms": detect_fake_login_forms(content)
    }

# ===== SSL CERTIFICATE FUNCTIONS =====

def get_ssl_info(domain):
    """Checks SSL certificate details for a given domain."""
    try:
        # Connect to the website on port 443 (HTTPS)
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
        
        # Load the certificate
        cert = x509.load_der_x509_certificate(cert, default_backend())

        # Extract details
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        valid_from = cert.not_valid_before
        valid_to = cert.not_valid_after

        return {
            "Issuer": issuer,
            "Subject": subject,
            "Valid From": valid_from.strftime("%Y-%m-%d"),
            "Valid To": valid_to.strftime("%Y-%m-%d"),
            "Is Expired": valid_to < cert.not_valid_before
        }
    except Exception as e:
        return {"Error": f"Could not verify SSL: {str(e)}"}

# ===== MAIN API ENDPOINT =====

@app.route('/analyze', methods=['POST'])
def analyze_url_endpoint():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # ✅ AI Prediction
    ai_result = ai_predict(url)
    risk_score = 10 if ai_result == "Phishing" else 0

    # ✅ Google Safe Browsing Check
    is_blacklisted = check_google_safe_browsing(url)
    if is_blacklisted:
        risk_score += 10  # Increase risk score if blacklisted

    # ✅ WHOIS Domain Age Check
    domain_age = get_domain_age(url)
    if isinstance(domain_age, int) and domain_age < 30:
        risk_score += 5  # Increase risk for newly registered domains
    
    # Run additional analyses
    domain = extract_domain_info(url)
    url_analysis_results = analyze_url(url)
    web_scraping_results = web_scraper(url)
    js_analysis_results = analyze_javascript_redirects(url)
    content_analysis_results = analyze_content(url)
    logo_analysis_results = analyze_website_logo(url)
    
    try:
        ssl_results = get_ssl_info(domain)
        # Add risk for SSL issues
        if "Error" in ssl_results:
            risk_score += 5
    except Exception:
        ssl_results = {"Error": "Could not analyze SSL"}
    
    # Increase risk score based on additional analyses
    if "Possible Typosquatting" in url_analysis_results.get("Typosquatting", ""):
        risk_score += 5
    
    if "Potential Homoglyph Attack" in url_analysis_results.get("Homoglyph Attack", ""):
        risk_score += 5
        
    if "Suspicious Subdomain" in url_analysis_results.get("Suspicious Subdomains", ""):
        risk_score += 3
        
    if "Hidden Redirects Found" in js_analysis_results.get("Hidden Redirects", ""):
        risk_score += 7
        
    if "Phishing Phrases Detected" in content_analysis_results.get("Phishing Keywords", ""):
        risk_score += 8
        
    if "Fake Login Form Detected" in content_analysis_results.get("Fake Login Forms", ""):
        risk_score += 10
        
    if "Logo does not match" in logo_analysis_results.get("Analysis", ""):
        risk_score += 3

    # Compile comprehensive results
    return jsonify({
        "url": url,
        "ai_prediction": ai_result,
        "google_blacklisted": is_blacklisted,
        "domain_age": domain_age,
        "risk_score": min(risk_score, 100),  # Cap risk score at 100
        "url_analysis": url_analysis_results,
        "web_content": web_scraping_results,
        "javascript_analysis": js_analysis_results,
        "content_analysis": content_analysis_results,
        "logo_analysis": logo_analysis_results,
        "ssl_certificate": ssl_results
    })

# ===== RUN THE APPLICATION =====
if __name__ == "__main__":
    app.run(debug=True)

