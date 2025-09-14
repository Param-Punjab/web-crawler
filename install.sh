#!/bin/bash

# Web Crawler Installer Script
set -e  # Exit on any error

echo "🚀 Installing Web Crawler..."
echo "Cloning repository..."
git clone https://github.com/param-punjab/web-crawler

cd web-crawler

echo "Creating virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt

echo "✅ Installation complete!"
echo "Starting Flask server..."
echo "The app will be available at: http://127.0.0.1:5000"
echo "Press Ctrl+C to stop the server"
echo ""

flask run
