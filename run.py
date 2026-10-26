"""
Entry point for the Web Application Vulnerability Scanner.
Run with: python run.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app import app
from config import Config

if __name__ == "__main__":
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=5000)
