import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import ssl
import socket
import time
import json
import dns.resolver
from datetime import datetime

class SimplePhishingDetector:
    def __init__(self, target_domain="google.com"):
        self.target_domain = target_domain
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.suspicious_domains = set()
    
    def check_ct_logs(self):
        """Check Certificate Transparency logs for suspicious domains"""
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    domain = item['name_value']
                    if '\n' in domain:
                        for subdomain in domain.split('\n'):
                            if self.target_domain in subdomain and subdomain != self.target_domain:
                                self.suspicious_domains.add(subdomain)
                    else:
                        if self.target_domain in domain and domain != self.target_domain:
                            self.suspicious_domains.add(domain)
        except Exception as e:
            print(f"Error checking CT logs: {e}")
    
    def check_dns_records(self):
        """Check DNS records for suspicious subdomains"""
        try:
            # Check common subdomains
            common_subdomains = ['login', 'signin', 'account', 'verify', 'security', 'admin', 'auth']
            for sub in common_subdomains:
                try:
                    test_domain = f"{sub}.{self.target_domain}"
                    dns.resolver.resolve(test_domain, 'A')
                    self.suspicious_domains.add(test_domain)
                except:
                    pass
        except:
            pass
    
    def validate_domain_exists(self, domain):
        """Check if a domain actually exists by resolving DNS"""
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except:
            return False
    
    def get_suspicious_domains(self):
        """Get all suspicious domains from various sources and validate they exist"""
        print("Searching for suspicious domains...")
        
        self.check_ct_logs()
        print(f"Found {len(self.suspicious_domains)} domains from CT logs")
        
        self.check_dns_records()
        print(f"Found {len(self.suspicious_domains)} domains from DNS records")
        
        # Filter out domains that don't exist
        valid_domains = []
        for domain in list(self.suspicious_domains):
            if self.validate_domain_exists(domain):
                valid_domains.append(domain)
            else:
                self.suspicious_domains.remove(domain)
        
        print(f"Total {len(self.suspicious_domains)} valid domains to check")
        
        return list(self.suspicious_domains)
    
    def analyze_domain(self, domain):
        """Analyze a single domain for phishing indicators"""
        risk_factors = []
        final_url = domain
        
        try:
            # Try HTTPS first
            response = self.session.get(f"https://{domain}", timeout=10, allow_redirects=True)
            final_url = response.url
        except:
            try:
                # Fall back to HTTP
                response = self.session.get(f"http://{domain}", timeout=10, allow_redirects=True)
                final_url = response.url
                risk_factors.append("Uses HTTP instead of HTTPS")
            except Exception as e:
                risk_factors.append(f"Cannot access website: {str(e)}")
                return risk_factors, final_url
        
        # Check if redirected to a different domain
        parsed_final = urlparse(final_url)
        if parsed_final.netloc != domain:
            risk_factors.append(f"Redirects to different domain: {parsed_final.netloc}")
        
        # Parse page content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for login forms
        login_forms = soup.find_all('form')
        for form in login_forms:
            inputs = form.find_all('input')
            has_password = any(input.get('type') == 'password' for input in inputs)
            if has_password:
                risk_factors.append("Contains login form")
                break
        
        # Check for suspicious keywords in title and content
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'security', 'authenticate', 'password']
        title = soup.find('title')
        if title:
            title_text = title.get_text().lower()
            if any(keyword in title_text for keyword in suspicious_keywords):
                risk_factors.append("Uses suspicious keywords in title")
        
        # Check for domain age (if possible)
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                if (datetime.now() - creation_date).days < 30:
                    risk_factors.append("Recently registered domain (less than 30 days)")
        except:
            pass  # WHOIS lookup might fail
        
        return risk_factors, final_url
    
    def determine_risk_level(self, risk_factors):
        """Determine risk level based on factors found"""
        if not risk_factors:
            return "Low"
        elif len(risk_factors) <= 2:
            return "Medium"
        else:
            return "High"
    
    def detect_phishing_domains(self):
        """Main method to detect phishing domains"""
        results = []
        
        suspicious_domains = self.get_suspicious_domains()
        
        if not suspicious_domains:
            print("No suspicious domains found to analyze.")
            return []
        
        print(f"Found {len(suspicious_domains)} potential phishing domains to analyze")
        
        for domain in suspicious_domains:
            print(f"Analyzing {domain}...")
            risk_factors, final_url = self.analyze_domain(domain)
            
            # Determine risk level
            risk_level = self.determine_risk_level(risk_factors)
            
            # Add to results
            results.append({
                "domain": domain,
                "url": final_url,
                "risk_factors": risk_factors,
                "risk_level": risk_level
            })
            
            time.sleep(1)  # Be respectful to the websites
            
        return results

# Simple version with predefined target
def simple_version():
    print("=== Simple Phishing Domain Detection System ===")
    target_domain = "google.com"  # Predefined target
    print(f"Analyzing domains similar to {target_domain}...")
    
    detector = SimplePhishingDetector(target_domain)
    results = detector.detect_phishing_domains()
    
    print("\n=== Phishing Detection Results ===")
    
    if results:
        print(json.dumps(results, indent=2))
        
        # Save results to a file
        filename = f"phishing_results_{target_domain.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Results saved to {filename}")
    else:
        print("No results to display.")

if __name__ == "__main__":
    simple_version()
