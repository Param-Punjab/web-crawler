from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import tldextract
import ssl
import socket
from datetime import datetime
import whois
import requests
import re
import dns.resolver
import threading
import uuid
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import jellyfish
lev_distance = jellyfish.levenshtein_distance

app = Flask(__name__)
app.secret_key = 'secretkey' 

analysis_results = {}

class AdvancedDomainChecker:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.target_parts = tldextract.extract(self.target_domain)
        
    def is_legitimate_domain(self, domain):
        """Check the domain legitimacy using multiple verification methods"""
        check_score = 0
        reasons = []
        
        parts = tldextract.extract(domain)

        if parts.registered_domain != self.target_parts.registered_domain:
            check_score += 1
            reasons.append("Different registered domain")
        
        ssl_valid, ssl_reason = self.has_valid_ssl_certificate(domain)
        if not ssl_valid:
            check_score += 1
            reasons.append(f"SSL Issue: {ssl_reason}")
        
        auth_valid, auth_reason = self.has_domain_authentication(parts.registered_domain)
        if not auth_valid:
            check_score += 1
            reasons.append(f"Domain auth issue: {auth_reason}")

        registration_valid, reg_reason = self.has_legitimate_registration(domain)
        if not registration_valid:
            check_score += 1
            reasons.append(f"Registration issue: {reg_reason}")
        
        if check_score == 0:
            return True, "Domain appears legitimate"
        else:
            return False, "; ".join(reasons)
            
    def has_valid_ssl_certificate(self, domain, port=443):
        """Check if the domain has valid SSL certificate from trusted CA"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                if not cert:
                    return False, "No SSL certificate found"
                
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if datetime.now() > not_after:
                    return False, "SSL certificate expired"

                org_name = None
                if 'subject' in cert:
                    for field in cert['subject']:
                        if field[0][0] == 'organizationName':
                            org_name = field[0][1]
                            break

                if org_name and ("education" in org_name.lower() or "college" in org_name.lower() 
                                or "university" in org_name.lower() or "gndec" in org_name.lower()):
                    return True, f"Valid educational certificate: {org_name}"
                
                return True, "Valid SSL certificate"
        except Exception as e:
            return False, f"SSL connection failed: {str(e)}"
    
    def has_domain_authentication(self, domain):
        """Check for domain authentication records that legitimate organizations typically implement"""
        try:
            dmarc_record = f"_dmarc.{domain}"
            try:
                answers = dns.resolver.resolve(dmarc_record, 'TXT')
                for rdata in answers:
                    if 'v=DMARC1' in str(rdata):
                        return True, "DMARC record found"
            except:
                pass

            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    if 'v=spf1' in str(rdata):
                        return True, "SPF record found"
            except:
                pass

            return False, "No domain authentication records found"
        except Exception as e:
            return False, f"DNS checks failed: {str(e)}"
    
    def has_legitimate_registration(self, domain):
        """Check WHOIS information for legitimate registration details"""
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date

                if isinstance(creation_date, str):
                    try:
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            creation_date = datetime.strptime(creation_date, '%d-%b-%Y')
                        except:
                            return True, "Could not parse creation date"

                domain_age = (datetime.now() - creation_date).days
                if domain_age < 30:
                    return False, f"Domain is very new ({domain_age} days)"

            if domain.endswith('.edu') or domain.endswith('.ac.in'):
                return True, "Educational domain detected"

            return True, "Domain registration appears legitimate"
        except Exception as e:
            return False, f"WHOIS check failed: {str(e)}"

class PhishingDetector:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.checker = AdvancedDomainChecker(target_domain)
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        
    def generate_domain_variations(self):
        """Generate potential phishing domains using various techniques"""
        variations = set()
        domain_parts = tldextract.extract(self.target_domain)
        base_domain = f"{domain_parts.domain}.{domain_parts.suffix}"
        
        prefixes = ['login', 'signin', 'verify', 'secure', 'account', 'auth']
        suffixes = ['login', 'signin', 'verify', 'secure', 'account', 'auth']
        
        for prefix in prefixes:
            variations.add(f"{prefix}-{base_domain}")
            variations.add(f"{prefix}.{base_domain}")
            variations.add(f"{prefix}{base_domain}")
            
        for suffix in suffixes:
            variations.add(f"{base_domain}-{suffix}")
            variations.add(f"{base_domain}.{suffix}")
            variations.add(f"{base_domain}{suffix}")
            
        if domain_parts.suffix == 'com':
            for tld in ['net', 'org', 'info', 'biz']:
                variations.add(f"{domain_parts.domain}.{tld}")
                
        return variations
        
    def get_suspicious_domains(self):
        """Get all suspicious domains from various sources"""
        print("Searching for suspicious domains...")
        
        generated_domains = self.generate_domain_variations()
        print(f"Generated {len(generated_domains)} domain variations")
        
        valid_domains = []
        for domain in generated_domains:
            if self.validate_domain_exists(domain):
                valid_domains.append(domain)
                
        print(f"Found {len(valid_domains)} valid domains to check")
        return valid_domains
        
    def validate_domain_exists(self, domain):
        """Check if a domain actually exists by resolving DNS"""
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except:
            return False
            
    def analyze_domain(self, domain):
        """Analyze a single domain for phishing indicators"""
        risk_factors = []
        final_url = domain
        title = ""
        
        is_legitimate, reason = self.checker.is_legitimate_domain(domain)
        if not is_legitimate:
            risk_factors.append(f"Legitimacy check failed: {reason}")
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10, allow_redirects=True)
            final_url = response.url
            content = response.text
            
            soup = BeautifulSoup(content, 'html.parser')
            
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text().strip()
                
            login_forms = soup.find_all('form')
            for form in login_forms:
                inputs = form.find_all('input')
                has_password = any(input.get('type') == 'password' for input in inputs)
                has_username = any(input.get('type') in ['text', 'email'] for input in inputs)
                
                if has_password and has_username:
                    risk_factors.append("Contains login form with username and password fields")
                    break
            
            suspicious_keywords = ['login', 'signin', 'verify', 'account', 'security']
            content_lower = content.lower()
            
            if title:
                title_lower = title.lower()
                if any(keyword in title_lower for keyword in suspicious_keywords):
                    risk_factors.append("Uses suspicious keywords in title")
            
            keyword_count = 0
            for keyword in suspicious_keywords:
                if keyword in content_lower:
                    keyword_count += 1
            
            if keyword_count > 3:
                risk_factors.append(f"Uses multiple ({keyword_count}) suspicious keywords in content")
                
            target_clean = self.target_domain.replace('www.', '').replace('.com', '')
            domain_clean = domain.replace('www.', '').replace('.com', '')
            
            similarity = lev_distance(target_clean, domain_clean)
            if similarity <= 2:
                risk_factors.append(f"Very similar to target domain (distance: {similarity})")
                
        except Exception as e:
            risk_factors.append(f"Cannot access website: {str(e)}")
        
        risk_level = self.determine_risk_level(risk_factors)
        
        return risk_factors, final_url, title, risk_level
        
    def determine_risk_level(self, risk_factors):
        """Determine risk level based on factors found"""
        if not risk_factors:
            return "Low"
        
        high_risk_indicators = [
            "SSL certificate is invalid or expired",
            "Contains login form with username and password fields",
            "Legitimacy check failed:"
        ]
        
        medium_risk_indicators = [
            "Uses HTTP instead of HTTPS",
            "Uses multiple (",
            "Recently registered domain (",
            "Very similar to target domain"
        ]
        
        high_count = sum(1 for factor in risk_factors if any(indicator in factor for indicator in high_risk_indicators))
        medium_count = sum(1 for factor in risk_factors if any(indicator in factor for indicator in medium_risk_indicators))
        
        if high_count > 0:
            return "High"
        elif medium_count > 1 or (medium_count > 0 and len(risk_factors) > 2):
            return "Medium"
        else:
            return "Low"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    target_domain = request.form.get('domain')
    if not target_domain:
        return jsonify({'success': False, 'error': 'Please enter a domain name'})
    
    if not target_domain.startswith(('http://', 'https://')):
        target_domain = 'https://' + target_domain
    
    parsed_domain = urlparse(target_domain)
    netloc = parsed_domain.netloc or parsed_domain.path
    
    analysis_id = str(uuid.uuid4())
    
    analysis_results[analysis_id] = {
        'target_domain': netloc,
        'status': 'processing',
        'progress': 0,
        'results': [],
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'end_time': None,
        'total_domains': 0,
        'processed_domains': 0
    }
    
    thread = threading.Thread(target=run_analysis, args=(netloc, analysis_id))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'analysis_id': analysis_id,
        'redirect_url': f'/results/{analysis_id}'
    })

def run_analysis(target_domain, analysis_id):
    """Run the analysis and store results with progress updates"""
    detector = PhishingDetector(target_domain)
    
    analysis_results[analysis_id]['status'] = 'searching_domains'
    analysis_results[analysis_id]['progress'] = 20
    
    suspicious_domains = detector.get_suspicious_domains()
    
    if not suspicious_domains:
        analysis_results[analysis_id]['status'] = 'completed'
        analysis_results[analysis_id]['progress'] = 100
        analysis_results[analysis_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return
    
    analysis_results[analysis_id]['status'] = 'analyzing_domains'
    analysis_results[analysis_id]['progress'] = 40
    analysis_results[analysis_id]['total_domains'] = len(suspicious_domains)
    analysis_results[analysis_id]['processed_domains'] = 0
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(detector.analyze_domain, domain): domain for domain in suspicious_domains}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_domain)):
            domain = future_to_domain[future]
            try:
                risk_factors, final_url, title, risk_level = future.result()
                
                if risk_factors:
                    results.append({
                        "domain": domain,
                        "url": final_url,
                        "title": title,
                        "risk_factors": risk_factors,
                        "risk_level": risk_level
                    })
                
                analysis_results[analysis_id]['processed_domains'] = i + 1
                analysis_results[analysis_id]['progress'] = 40 + (i / len(suspicious_domains)) * 60
                analysis_results[analysis_id]['results'] = results
                
            except Exception as e:
                print(f"Error analyzing {domain}: {e}")
    
    analysis_results[analysis_id]['status'] = 'completed'
    analysis_results[analysis_id]['progress'] = 100
    analysis_results[analysis_id]['results'] = results
    analysis_results[analysis_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

@app.route('/results/<analysis_id>')
def results(analysis_id):
    if analysis_id not in analysis_results:
        return redirect(url_for('index'))
    
    return render_template('results.html', analysis_id=analysis_id)

@app.route('/api/analysis/<analysis_id>')
def get_analysis(analysis_id):
    if analysis_id not in analysis_results:
        return jsonify({'error': 'Analysis not found'}), 404
    
    return jsonify(analysis_results[analysis_id])

@app.route('/check-domain', methods=['POST'])
def check_domain():
    """Check a single domain for legitimacy"""
    data = request.get_json()
    domain = data.get('domain')
    target_domain = data.get('target_domain')
    
    if not domain or not target_domain:
        return jsonify({'error': 'Domain and target domain are required'}), 400
    
    checker = AdvancedDomainChecker(target_domain)
    is_legitimate, reason = checker.is_legitimate_domain(domain)
    
    return jsonify({
        'domain': domain,
        'is_legitimate': is_legitimate,
        'reason': reason
    })

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
