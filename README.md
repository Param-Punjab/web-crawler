# Web Crawler

## Overview

This is Web Crawler that identifies and analyzes potential phishing websites targeting a specified domain. The system uses multiple techniques including Certificate Transparency logs, DNS analysis, content similarity checks, and machine learning to detect suspicious domains.

## Features

- **Multiple Detection Methods**: Uses CT logs, DNS records, and typosquatting generation
- **Content Analysis**: Compares website content with the legitimate site using TF-IDF and cosine similarity
- **SSL Certificate Verification**: Checks for valid SSL certificates and expiration dates
- **Risk Assessment**: Provides detailed risk factors and overall risk levels
- **Parallel Processing**: Analyzes multiple domains simultaneously for faster results
- **Interactive & Simple Modes**: Both interactive (user input) and predefined target versions available

## Installation
### Linux/macOS
```bash
curl -sSL https://raw.githubusercontent.com/param-punjab/web-crawler/main/install.sh | bash
```
---

### Windows

1. Clone the repository:
```bash
git clone https://github.com/param-punjab/web-crawler
cd web-crawler 
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Requirements

The project requires the following Python packages:

```text
requests>=2.28.0
beautifulsoup4>=4.11.0
python-whois>=0.8.0
tldextract>=3.4.0
scikit-learn>=1.0.0
dnspython>=2.2.0
```

## Usage

### Interactive Version

Run the interactive version to analyze any domain:

```bash
python advanced_crawler.py
```

You'll be prompted to enter the target domain (e.g., google.com, paypal.com, etc.)

### Simple Version

Run the simple version with a predefined target (default: google.com):

```bash
python simple-crawler.py
```

## Output

The system generates a detailed JSON report with the following information for each suspicious domain:
- Domain name
- Final URL (after redirects)
- Risk factors identified
- Content similarity score (advanced version)
- Overall risk level (Low, Medium, High)

Results are saved to `phishing_results_<domain>.json`

## How It Works

1. **Domain Discovery**:
   - Checks Certificate Transparency logs for domains related to the target
   - Examines DNS records for suspicious subdomains
   - Generates common typosquatting variations

2. **Domain Validation**:
   - Verifies domains exist before analysis
   - Filters out non-existent domains

3. **Content Analysis**:
   - Compares website content with the legitimate site
   - Uses TF-IDF vectorization and cosine similarity

4. **Risk Assessment**:
   - Checks for SSL certificate issues
   - Identifies login forms and suspicious keywords
   - Evaluates domain age and registration details
   - Calculates overall risk level

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and security research purposes only. Always ensure you have permission to scan domains and comply with all applicable laws and regulations.

## Support

If you encounter any issues or have questions, please open an issue in the GitHub repository.
