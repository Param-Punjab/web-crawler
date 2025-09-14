# 🕵️‍♂️ Advanced Phishing Domain Detector (Web Crawler)

A powerful Flask-based web application that detects and analyzes potential phishing domains by performing comprehensive security checks, SSL validation, domain authentication, and content analysis.

## 🌟 Features

- **Domain Legitimacy Verification**: Multi-layered domain validation
- **SSL Certificate Analysis**: Checks for valid/expired SSL certificates from trusted CAs
- **Domain Authentication**: Validates DMARC, SPF, and other security records
- **WHOIS Analysis**: Examines domain registration details and age
- **Content Scanning**: Analyzes web content for phishing indicators
- **Similarity Detection**: Uses Levenshtein distance to identify domain spoofing
- **Real-time Analysis**: Multi-threaded scanning for efficient detection
- **Risk Assessment**: Classifies domains as High, Medium, or Low risk

## 🚀 Quick Installation (Linux/macOS)

Run this single command to install and launch the application:

```bash
curl -sSL https://raw.githubusercontent.com/param-punjab/web-crawler/main/install.sh | sh
```

The application will be available at: `http://127.0.0.1:5000`

## 📋 Prerequisites

- Python 3.6+
- pip (Python package manager)
- Git
- Internet connection

## 🔧 Manual Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/param-punjab/web-crawler
   cd web-crawler
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   flask run
   ```

## 📊 Requirements

```txt
Flask==2.3.3
tldextract==3.4.4
beautifulsoup4==4.12.2
requests==2.31.0
python-whois==0.8.0
dnspython==2.4.2
python-Levenshtein==0.21.1
```

## 🎯 Usage

1. Open your browser and go to `http://127.0.0.1:5000`
2. Enter a target domain to analyze (e.g., `google.com`)
3. Click "Analyze" to start the detection process
4. View detailed results showing potential phishing domains and risk factors

## 🔍 Detection Methods

The tool uses multiple techniques to identify phishing domains:

1. **Domain Variation Generation**: Creates potential phishing domains using common patterns
2. **SSL Certificate Validation**: Checks certificate validity and organization details
3. **DNS Record Analysis**: Validates security records (DMARC, SPF)
4. **WHOIS Verification**: Examines domain registration information
5. **Content Analysis**: Scans for login forms and suspicious keywords
6. **Similarity Comparison**: Measures textual similarity to legitimate domains

## 📁 Project Structure

```
web-crawler/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── install.sh            # Installation script
└── templates/            # HTML templates
    ├── index.html        # Main interface
    └── results.html      # Results display
```


## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is open source and available under the MIT License.

## ⚡ Troubleshooting

**Common issues:**
- Ensure Python 3.6+ is installed
- Check internet connection for DNS resolution
- Verify all dependencies are installed correctly

**For support:**
Create an issue on GitHub with details about your problem.

---