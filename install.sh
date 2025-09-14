#!/bin/bash
set -e

echo "🚀 Installing Web Crawler..."
echo "Cloning repository..."
git clone https://github.com/param-punjab/web-crawler

cd web-crawler

echo "Creating virtual environment..."
python3 -m venv venv 2>/dev/null || python -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt

echo "✅ Installation complete!"
echo "Starting Flask server..."
echo "The app will be available at: http://127.0.0.1:5000"
echo "Press Ctrl+C to stop the server"
echo ""

flask run 2>/dev/null || python -m flask run 2>/dev/null || python3 -m flask run
