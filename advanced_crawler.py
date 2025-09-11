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
import concurrent.futures
import tldextract
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

class AdvancedPhishingDetector:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.extracted_target = tldextract.extract(target_domain)
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.suspicious_domains = set()
        self.legitimate_content = None
        self.vectorizer = TfidfVectorizer(stop_words='english')
        
    def fetch_legitimate_content(self):
        """Fetch content from the legitimate website for comparison"""
        try:
            response = self.session.get(f"https://{self.target_domain}", timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Remove scripts and styles
                for script in soup(["script", "style"]):
                    script.decompose()
                self.legitimate_content = soup.get_text()
        except Exception as e:
            print(f"Error fetching legitimate content: {e}")
    
    def check_ct_logs(self):
        """Check Certificate Transparency logs for suspicious domains"""
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    domain = item['name_value'].strip()
                    if '\n' in domain:
                        for subdomain in domain.split('\n'):
                            subdomain = subdomain.strip()
                            if self.target_domain in subdomain and subdomain != self.target_domain:
                                extracted = tldextract.extract(subdomain)
                                if extracted.domain != self.extracted_target.domain:
                                    self.suspicious_domains.add(subdomain)
                    else:
                        if self.target_domain in domain and domain != self.target_domain:
                            extracted = tldextract.extract(domain)
                            if extracted.domain != self.extracted_target.domain:
                                self.suspicious_domains.add(domain)
        except Exception as e:
            print(f"Error checking CT logs: {e}")
    
    def check_dns_records(self):
        """Check DNS records for suspicious subdomains"""
        try:
            # Check common subdomains
            common_subdomains = ['login', 'signin', 'account', 'verify', 'security', 'admin', 'auth', 
                                'secure', 'my', 'service', 'portal', 'access', 'online', 'web']
            for sub in common_subdomains:
                try:
                    test_domain = f"{sub}.{self.target_domain}"
                    dns.resolver.resolve(test_domain, 'A')
                    self.suspicious_domains.add(test_domain)
                except:
                    pass
        except Exception as e:
            print(f"Error checking DNS records: {e}")
    
    def generate_typosquatting_domains(self):
        """Generate potential typosquatting domains"""
        domain_parts = self.target_domain.split('.')
        main_domain = domain_parts[0]
        tld = '.'.join(domain_parts[1:]) if len(domain_parts) > 1 else 'com'
        
        # Common typosquatting techniques
        variations = set()
        
        # Character omission
        for i in range(len(main_domain)):
            variations.add(main_domain[:i] + main_domain[i+1:] + '.' + tld)
        
        # Character replacement
        for i in range(len(main_domain)):
            if main_domain[i] == 'o':
                variations.add(main_domain[:i] + '0' + main_domain[i+1:] + '.' + tld)
            if main_domain[i] == 'i':
                variations.add(main_domain[:i] + '1' + main_domain[i+1:] + '.' + tld)
            if main_domain[i] == 'l':
                variations.add(main_domain[:i] + '1' + main_domain[i+1:] + '.' + tld)
            if main_domain[i] == 'e':
                variations.add(main_domain[:i] + '3' + main_domain[i+1:] + '.' + tld)
        
        # Additional techniques
        variations.add(main_domain + '-login.' + tld)
        variations.add('login-' + main_domain + '.' + tld)
        variations.add(main_domain + '-secure.' + tld)
        variations.add('secure-' + main_domain + '.' + tld)
        variations.add(main_domain + '-account.' + tld)
        variations.add('account-' + main_domain + '.' + tld)
        
        # Check if these domains exist
        for domain in variations:
            try:
                dns.resolver.resolve(domain, 'A')
                self.suspicious_domains.add(domain)
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
        
        self.generate_typosquatting_domains()
        print(f"Found {len(self.suspicious_domains)} domains from typosquatting generation")
        
        # Filter out domains that don't exist
        valid_domains = []
        for domain in list(self.suspicious_domains):
            if self.validate_domain_exists(domain):
                valid_domains.append(domain)
            else:
                self.suspicious_domains.remove(domain)
        
        print(f"Total {len(self.suspicious_domains)} valid domains to check")
        
        return list(self.suspicious_domains)
    
    def check_ssl_certificate(self, domain):
        """Check SSL certificate for a domain"""
        risk_factors = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if exp_date < datetime.now():
                        risk_factors.append("Expired SSL certificate")
                    
                    # Check if certificate is self-signed
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    if issuer == subject:
                        risk_factors.append("Self-signed SSL certificate")
        except Exception as e:
            risk_factors.append(f"SSL error: {str(e)}")
        
        return risk_factors
    
    def check_content_similarity(self, content):
        """Check if content is similar to legitimate website"""
        if not self.legitimate_content:
            return 0, []
        
        risk_factors = []
        
        try:
            # Create TF-IDF vectors
            tfidf_matrix = self.vectorizer.fit_transform([self.legitimate_content, content])
            
            # Calculate cosine similarity
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
            
            if similarity > 0.7:
                risk_factors.append(f"High content similarity with legitimate site ({similarity:.2f})")
            
            return similarity, risk_factors
        except Exception as e:
            print(f"Error in content similarity check: {e}")
            return 0, []
    
    def analyze_domain(self, domain):
        """Analyze a single domain for phishing indicators"""
        risk_factors = []
        final_url = domain
        content_similarity = 0
        
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
                return risk_factors, final_url, content_similarity
        
        # Check SSL certificate
        ssl_risks = self.check_ssl_certificate(domain)
        risk_factors.extend(ssl_risks)
        
        # Check if redirected to a different domain
        parsed_final = urlparse(final_url)
        if parsed_final.netloc != domain:
            risk_factors.append(f"Redirects to different domain: {parsed_final.netloc}")
        
        # Parse page content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract text content for similarity check
        for script in soup(["script", "style"]):
            script.decompose()
        page_content = soup.get_text()
        
        # Check content similarity
        content_similarity, similarity_risks = self.check_content_similarity(page_content)
        risk_factors.extend(similarity_risks)
        
        # Check for login forms
        login_forms = soup.find_all('form')
        for form in login_forms:
            inputs = form.find_all('input')
            has_password = any(input.get('type') == 'password' for input in inputs)
            if has_password:
                risk_factors.append("Contains login form")
                break
        
        # Check for suspicious keywords in title and content
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'security', 'authenticate', 'password', 
                              'banking', 'financial', 'credential', 'sign in', 'log in']
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
        
        return risk_factors, final_url, content_similarity
    
    def determine_risk_level(self, risk_factors, content_similarity):
        """Determine risk level based on factors found"""
        risk_score = len(risk_factors)
        
        # Add to risk score based on content similarity
        if content_similarity > 0.7:
            risk_score += 3
        elif content_similarity > 0.5:
            risk_score += 2
        elif content_similarity > 0.3:
            risk_score += 1
        
        if risk_score == 0:
            return "Low"
        elif risk_score <= 3:
            return "Medium"
        else:
            return "High"
    
    def analyze_domains_parallel(self, domains):
        """Analyze multiple domains in parallel"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_domain = {executor.submit(self.analyze_domain, domain): domain for domain in domains}
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    risk_factors, final_url, content_similarity = future.result()
                    
                    # Determine risk level
                    risk_level = self.determine_risk_level(risk_factors, content_similarity)
                    
                    # Add to results
                    results.append({
                        "domain": domain,
                        "url": final_url,
                        "risk_factors": risk_factors,
                        "content_similarity": content_similarity,
                        "risk_level": risk_level
                    })
                    
                    print(f"Completed analysis for {domain}: {risk_level} risk")
                    
                except Exception as e:
                    print(f"Error analyzing {domain}: {e}")
                    results.append({
                        "domain": domain,
                        "url": domain,
                        "risk_factors": [f"Analysis error: {str(e)}"],
                        "content_similarity": 0,
                        "risk_level": "Unknown"
                    })
                
                time.sleep(1)  # Be respectful to the websites
        
        return results
    
    def detect_phishing_domains(self):
        """Main method to detect phishing domains"""
        # First, fetch legitimate content for comparison
        print("Fetching legitimate website content for comparison...")
        self.fetch_legitimate_content()
        
        # Get suspicious domains
        suspicious_domains = self.get_suspicious_domains()
        
        if not suspicious_domains:
            print("No suspicious domains found to analyze.")
            return []
        
        print(f"Found {len(suspicious_domains)} potential phishing domains to analyze")
        
        # Analyze domains in parallel
        results = self.analyze_domains_parallel(suspicious_domains)
        
        # Sort results by risk level (High to Low)
        risk_order = {"High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
        results.sort(key=lambda x: risk_order[x["risk_level"]], reverse=True)
        
        return results

# Interactive version
def interactive_version():
    print("=== Advanced Phishing Domain Detection System ===")
    target_domain = input("Enter the target domain (e.g., google.com): ").strip()
    
    if not target_domain:
        print("No domain entered. Using 'google.com' as default.")
        target_domain = "google.com"
    
    print(f"\nStarting analysis for {target_domain}...")
    
    detector = AdvancedPhishingDetector(target_domain)
    results = detector.detect_phishing_domains()
    
    print("\n=== Phishing Detection Results ===")
    
    if results:
        print(json.dumps(results, indent=2))
        
        # Count results by risk level
        risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for result in results:
            risk_counts[result["risk_level"]] += 1
        
        print(f"\nSummary: {risk_counts['High']} High risk, {risk_counts['Medium']} Medium risk, {risk_counts['Low']} Low risk")
        
        # Save results to a file
        filename = f"phishing_results_{target_domain.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Results saved to {filename}")
    else:
        print("No results to display.")

if __name__ == "__main__":
    interactive_version()
