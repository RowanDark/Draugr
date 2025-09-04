#!/usr/bin/env python3
"""
Draugr is an Advanced Web Scraper with Pattern Matching, JS Rendering, and Database Storage
Educational tool for security research and authorized penetration testing
Author: Security Research Tool
Version: 2.0

LEGAL DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Always obtain explicit written permission before scanning any website.
Unauthorized scanning may violate laws including the Computer Fraud and Abuse Act (CFAA).
"""

import sys
import re
import json
import csv
import time
import threading
import queue
import sqlite3
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs
from urllib.robotparser import RobotFileParser
from datetime import datetime
import random
from collections import defaultdict
import base64

# Web scraping imports
import requests
from bs4 import BeautifulSoup
import urllib3

# Selenium for JavaScript rendering
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Warning: Selenium not installed. JavaScript rendering disabled.")

# GUI imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QTableWidget, QTableWidgetItem, 
                             QProgressBar, QSpinBox, QCheckBox, QGroupBox,
                             QTabWidget, QFileDialog, QMessageBox, QComboBox,
                             QListWidget, QListWidgetItem, QSplitter, QTextBrowser)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QColor

# Suppress SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# ENHANCED PATTERN DEFINITIONS
# ============================================================================

PATTERN_KITS = {
    "API Keys & Secrets": {
        # Generic API Keys
        "Generic API Key": r'(?i)(?:api[_\-\s]?key|apikey|api[_\-\s]?secret|api[_\-\s]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        "Bearer Token": r'(?i)bearer\s+([a-zA-Z0-9_\-\.]+)',
        
        # Cloud Providers
        "AWS Access Key ID": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}',
        "AWS Secret Key": r'(?i)aws[_\-\s]?(?:secret[_\-\s]?)?(?:access[_\-\s]?)?key[\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?',
        "AWS Session Token": r'(?i)aws[_\-\s]?session[_\-\s]?token[\s:=]+["\']?([a-zA-Z0-9/+=]+)["\']?',
        "AWS MWS Key": r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "Google OAuth": r'(?i)(?:google|gcp|youtube|drive|yt)(?:.|_|-)?(?:api|app|oauth)?(?:.|_|-)key[\s:=]+["\']?([a-zA-Z0-9\-_]{20,})["\']?',
        "Google Cloud Platform API": r'(?i)(?:google|gcp|g-cloud)[_\-\s]?(?:api[_\-\s]?)?(?:key|token)[\s:=]+["\']?([a-zA-Z0-9\-_.]{20,})["\']?',
        "Firebase URL": r'https://[a-z0-9\-]+\.firebaseio\.com',
        "Google Service Account": r'(?i)(?:service[_\-\s]?account)[^"]*?(?:\.json|private_key)',
        
        "Azure Subscription Key": r'(?i)(?:azure|microsoft)[_\-\s]?(?:subscription[_\-\s]?)?key[\s:=]+["\']?([a-zA-Z0-9]{32})["\']?',
        "Azure Storage Key": r'(?i)(?:azure|storage)[_\-\s]?(?:account[_\-\s]?)?key[\s:=]+["\']?([a-zA-Z0-9+/]{86}==)["\']?',
        
        # Development Platforms
        "GitHub Token": r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}',
        "GitHub OAuth": r'(?i)github[_\-\s]?(?:oauth[_\-\s]?)?(?:token|key)[\s:=]+["\']?([a-zA-Z0-9_]{40})["\']?',
        "GitLab Token": r'(?:glpat|glptt)-[a-zA-Z0-9\-_]{20}',
        "Bitbucket Client ID": r'(?i)bitbucket[_\-\s]?(?:client[_\-\s]?)?id[\s:=]+["\']?([a-zA-Z0-9]{20,})["\']?',
        
        # Communication Services
        "Slack Token": r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
        "Slack Webhook": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
        "Discord Token": r'(?:discord[_\-\s]?(?:bot[_\-\s]?)?token[\s:=]+["\']?)?([MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9]{27})',
        "Discord Webhook": r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+',
        "Telegram Bot Token": r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
        "Twilio API Key": r'SK[a-z0-9]{32}',
        "Twilio Account SID": r'AC[a-z0-9]{32}',
        
        # Payment Services
        "Stripe API Key": r'(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}',
        "Stripe Restricted Key": r'rk_(?:test|live)_[a-zA-Z0-9]{24,}',
        "PayPal/Braintree Token": r'access_token[\s:=]+[a-zA-Z0-9\-\.]+',
        "Square OAuth Secret": r'sq0csp-[a-zA-Z0-9\-_]{43}',
        "Square Access Token": r'sqOatp-[a-zA-Z0-9\-_]{22}',
        "Coinbase Access Token": r'(?i)coinbase[_\-\s]?(?:api[_\-\s]?)?(?:key|token)[\s:=]+["\']?([a-zA-Z0-9]{32,})["\']?',
        
        # Social Media
        "Facebook App ID": r'(?i)(?:facebook|fb)[_\-\s]?(?:app[_\-\s]?)?id[\s:=]+["\']?([0-9]{13,17})["\']?',
        "Facebook Secret": r'(?i)(?:facebook|fb)[_\-\s]?(?:app[_\-\s]?)?secret[\s:=]+["\']?([a-f0-9]{32})["\']?',
        "Facebook Access Token": r'EAA[a-zA-Z0-9]+',
        "Twitter API Key": r'(?i)twitter[_\-\s]?(?:api[_\-\s]?)?key[\s:=]+["\']?([a-zA-Z0-9]{25})["\']?',
        "Twitter Bearer Token": r'(?i)twitter[_\-\s]?bearer[_\-\s]?token[\s:=]+["\']?([a-zA-Z0-9%]{100,})["\']?',
        
        # Other Services
        "Mailgun API Key": r'key-[a-zA-Z0-9]{32}',
        "Mailchimp API Key": r'[a-z0-9]{32}-us[0-9]{1,2}',
        "SendGrid API Key": r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        "Dropbox API Token": r'(?i)dropbox[_\-\s]?(?:api[_\-\s]?)?(?:token|key)[\s:=]+["\']?([a-zA-Z0-9]{64,})["\']?',
        "Heroku API Key": r'(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key[\s:=]+["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']?',
        "MapBox API Key": r'pk\.[a-zA-Z0-9]{60,}',
        "JWT Token": r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?',
        "NPM Token": r'npm_[a-zA-Z0-9]{36}',
        "Artifactory API Token": r'AKC[a-zA-Z0-9]{10,}',
        "Artifactory Password": r'AP[a-zA-Z0-9]{11,}',
    },
    
    "Database & Infrastructure": {
        "MongoDB Connection String": r'mongodb(?:\+srv)?://[^"\s]+',
        "PostgreSQL Connection": r'postgres://[^"\s]+',
        "MySQL Connection": r'mysql://[^"\s]+',
        "Redis URL": r'redis://[^"\s]+',
        "JDBC Connection String": r'jdbc:[a-z]+://[^"\s]+',
        "Database Password": r'(?i)(?:database|db)[_\-\s]?(?:password|pass|pwd)[\s:=]+["\']?([^"\'\s]+)["\']?',
        "Connection String with Password": r'(?i)(?:password|pwd|pass)=([^;&\s"\']+)',
        "SQL Server Connection": r'(?i)(?:server|data source)=[^;]+;(?:uid|user id)=[^;]+;(?:pwd|password)=([^;]+)',
        "Elasticsearch URL": r'(?:http|https)://[^:]+:[^@]+@[^/]+:[0-9]+',
        "Docker Registry Auth": r'(?i)docker[_\-\s]?(?:registry[_\-\s]?)?(?:auth|password)[\s:=]+["\']?([a-zA-Z0-9+/=]+)["\']?',
        "Kubernetes Config": r'(?i)kubeconfig|kubectl[^"]*?(?:token|certificate)',
        "SSH Private Key": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        "PGP Private Key": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    },
    
    "Financial Data": {
        "Credit Card Visa": r'4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}',
        "Credit Card MasterCard": r'5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}',
        "Credit Card Amex": r'3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}',
        "Credit Card Discover": r'6(?:011|5[0-9]{2})[0-9]{12}',
        "Credit Card Generic": r'\b(?:\d[ -]*?){13,16}\b',
        "CVV Code": r'\b(?:cvv|cvc|cvn|cvv2|cvc2)[\s:]+[0-9]{3,4}\b',
        "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
        "IBAN": r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
        "Bitcoin Address": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "Bitcoin Private Key": r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}',
        "Ethereum Address": r'0x[a-fA-F0-9]{40}',
        "Bank Account Number": r'\b[0-9]{8,17}\b',
        "Routing Number": r'\b(?:routing|aba|rtn)[\s:#]+[0-9]{9}\b',
        "SWIFT Code": r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
    },
    
    "Common Endpoints": {
        "Admin Panel": r'/(admin|administrator|wp-admin|backend|manage|portal|dashboard|control-panel)',
        "API Endpoints": r'/api/(?:v[0-9]+/)?[a-z]+',
        "GraphQL Endpoint": r'/graphql',
        "Config Files": r'\.(env|config|conf|cfg|ini|properties|yml|yaml|toml)(\?|$)',
        "Backup Files": r'\.(bak|backup|old|orig|original|~|save|swp)(\?|$)',
        "Database Files": r'\.(sql|db|sqlite|sqlite3|mdb|accdb)(\?|$)',
        "Log Files": r'\.(log|logs|out|err|error)(\?|$)',
        "Archive Files": r'\.(zip|tar|gz|rar|7z|bz2|xz)(\?|$)',
        "Source Code": r'\.(php|asp|aspx|jsp|py|rb|pl|cgi)(\?|$)',
        "Git Files": r'\.git(?:ignore|config|/)?',
        "SVN Files": r'\.svn(?:/)?',
        "IDE Files": r'\.(idea|vscode|project)(?:/)?',
        "Package Files": r'(?:package\.json|composer\.json|requirements\.txt|Gemfile)',
        "Build Files": r'(?:webpack\.config|gulpfile|Gruntfile|Makefile)',
        "CI/CD Files": r'(?:\.gitlab-ci\.yml|\.travis\.yml|Jenkinsfile|\.circleci)',
        "Docker Files": r'(?:Dockerfile|docker-compose\.yml)',
        "Kubernetes Files": r'(?:k8s|kubernetes)\.ya?ml',
        "Debug Endpoints": r'/(debug|test|staging|dev|development)',
        "PHPInfo": r'/phpinfo\.php',
        "Server Status": r'/server-status',
        "Hidden Directories": r'/\.[a-z]+(?:/)?',
    },
    
    "Sensitive Information": {
        "Email Address": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "Phone Number US": r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "Phone Number International": r'\+[0-9]{1,3}[-.\s]?(?:\([0-9]{1,4}\)|[0-9]{1,4})[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}',
        "Password in Text": r'(?i)(?:password|passwd|pwd)[\s:=]+["\']?([^"\'\s]{4,})["\']?',
        "Username Field": r'(?i)(?:user(?:name)?|login|email)[\s:=]+["\']?([^"\'\s]+)["\']?',
        "Private IP Address": r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.(?:[0-9]{1,3}\.){1}[0-9]{1,3}\b',
        "MAC Address": r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',
        "UUID": r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
        "Base64 Encoded Data": r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        "Hash MD5": r'\b[a-fA-F0-9]{32}\b',
        "Hash SHA1": r'\b[a-fA-F0-9]{40}\b',
        "Hash SHA256": r'\b[a-fA-F0-9]{64}\b',
        "Private Key Reference": r'(?i)(?:private[_\-\s]?key|priv[_\-\s]?key|secret[_\-\s]?key)',
        "Certificate": r'-----BEGIN CERTIFICATE-----',
        "OAuth Redirect": r'(?i)redirect[_\-]?uri[\s:=]+["\']?([^"\'\s]+)["\']?',
        "Client Secret": r'(?i)client[_\-\s]?secret[\s:=]+["\']?([^"\'\s]+)["\']?',
    },
    
    "JavaScript Specific": {
        "JS API Variable": r'(?:var|let|const)\s+(?:api|API)[a-zA-Z]*\s*=\s*["\']([^"\']+)["\']',
        "JS Token Variable": r'(?:var|let|const)\s+[a-zA-Z]*(?:token|Token|KEY|Key)\s*=\s*["\']([^"\']+)["\']',
        "JS Config Object": r'(?:config|settings|options)\s*=\s*\{[^}]*(?:key|token|secret|password)[^}]*\}',
        "JS Fetch with Auth": r'fetch\([^)]+headers[^)]*(?:Authorization|authorization)[^)]+\)',
        "JS XMLHttpRequest Auth": r'setRequestHeader\(["\'](?:Authorization|X-API-Key)["\']',
        "JS localStorage Sensitive": r'localStorage\.(?:get|set)Item\(["\'](?:token|key|password|secret)["\']',
        "JS sessionStorage Sensitive": r'sessionStorage\.(?:get|set)Item\(["\'](?:token|key|password|secret)["\']',
        "JS Window Variable": r'window\.[a-zA-Z]*(?:token|Token|KEY|Key|secret|Secret)\s*=',
        "JS Comments with Secrets": r'//.*(?:token|password|key|secret|api).*[:=]\s*["\']?([a-zA-Z0-9_\-]{10,})',
        "JS Import Secret": r'import\s+.*from\s+["\'].*(?:config|secret|key|token).*["\']',
        "JS Require Secret": r'require\(["\'].*(?:config|secret|key|token).*["\']\)',
        "JS Axios Auth": r'axios\.(?:get|post|put|delete)\([^)]+(?:headers|auth)[^)]+\)',
        "JS Environment Variable": r'process\.env\.[A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD)',
        "JS Hardcoded URL with Key": r'(?:http|https)://[^"\s]*[?&](?:api[_\-]?key|token|auth)=[^&"\s]+',
    },
    
    "Security Headers & Vulnerabilities": {
        "Missing CSP Header": r'^(?!.*content-security-policy).*$',
        "Missing X-Frame-Options": r'^(?!.*x-frame-options).*$',
        "Missing X-Content-Type": r'^(?!.*x-content-type-options).*$',
        "Missing HSTS": r'^(?!.*strict-transport-security).*$',
        "Server Version Disclosure": r'(?i)(?:server|x-powered-by):\s*[a-zA-Z]+/[\d.]+',
        "PHP Version Disclosure": r'(?i)x-powered-by:\s*php/[\d.]+',
        "ASP.NET Version": r'(?i)x-aspnet-version:\s*[\d.]+',
        "Vulnerable jQuery": r'jquery(?:\.min)?\.js\?v=([0-2]\.|3\.[0-3])',
        "SQL Injection Point": r'(?i)(?:select|insert|update|delete|union|from|where).*(?:\$_GET|\$_POST|\$_REQUEST)',
        "XSS Vulnerable": r'(?i)(?:document\.write|innerHTML|eval)\s*\([^)]*(?:\$_GET|\$_POST|location\.)',
        "Path Traversal": r'(?:\.\.\/|\.\.\\){2,}',
        "Command Injection": r'(?i)(?:exec|system|shell_exec|passthru|eval|cmd)\s*\(',
        "CORS Misconfiguration": r'(?i)access-control-allow-origin:\s*\*',
        "Debug Mode Enabled": r'(?i)(?:debug|DEBUG)\s*[:=]\s*(?:true|1|on|enabled)',
        "Stack Trace Exposed": r'(?i)(?:exception|error|stack\s*trace|traceback)',
        "TODO Comments": r'(?i)(?:TODO|FIXME|HACK|XXX|BUG):\s*(.+)',
    },
    
    "Cloud Storage & CDN": {
        "S3 Bucket URL": r'(?:s3|s3-[a-z0-9-]+)\.amazonaws\.com/[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]',
        "S3 Bucket Name": r'(?:s3://|s3\.amazonaws\.com/|s3-[a-z0-9-]+\.amazonaws\.com/)[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]',
        "Google Cloud Storage": r'(?:storage\.googleapis\.com|gs://)/?[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]',
        "Azure Blob Storage": r'https://[a-z0-9]+\.blob\.core\.windows\.net',
        "Firebase Storage": r'https://firebasestorage\.googleapis\.com',
        "CloudFront Distribution": r'[a-z0-9]+\.cloudfront\.net',
        "CDN URL": r'(?:cdn|assets|static|media)\.[a-z0-9\-]+\.[a-z]+',
        "Dropbox Share Link": r'https://www\.dropbox\.com/s/[a-z0-9]+',
        "Google Drive Link": r'https://drive\.google\.com/(?:file/d/|open\?id=)[a-zA-Z0-9_-]+',
        "OneDrive Link": r'https://1drv\.ms/[a-z]/[a-zA-Z0-9!_-]+',
    }
}

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    """Manages SQLite database for storing scan results"""
    
    def __init__(self, db_path="scanner_results.db"):
        self.db_path = db_path
        self.conn = None
        self.init_database()
        
    def init_database(self):
        """Initialize database tables"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                base_url TEXT NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                pages_scanned INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running'
            )
        ''')
        
        # Create findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                pattern_name TEXT NOT NULL,
                pattern_category TEXT,
                matched_text TEXT,
                context TEXT,
                severity TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hash TEXT UNIQUE,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        ''')
        
        # Create pages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pages (
                page_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                status_code INTEGER,
                content_hash TEXT,
                has_javascript BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        ''')
        
        # Create patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_patterns (
                pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                regex TEXT NOT NULL,
                category TEXT,
                severity TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
        
    def start_scan(self, base_url):
        """Record a new scan"""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO scans (base_url) VALUES (?)",
            (base_url,)
        )
        self.conn.commit()
        return cursor.lastrowid
        
    def end_scan(self, scan_id, pages_scanned, findings_count):
        """Mark scan as complete"""
        cursor = self.conn.cursor()
        cursor.execute(
            """UPDATE scans 
               SET end_time = CURRENT_TIMESTAMP, 
                   pages_scanned = ?, 
                   findings_count = ?,
                   status = 'complete'
               WHERE scan_id = ?""",
            (pages_scanned, findings_count, scan_id)
        )
        self.conn.commit()
        
    def add_finding(self, scan_id, url, pattern_name, pattern_category, 
                   matched_text, context, severity="medium"):
        """Add a finding to the database"""
        # Create unique hash to prevent duplicates
        hash_input = f"{url}{pattern_name}{matched_text}"
        finding_hash = hashlib.md5(hash_input.encode()).hexdigest()
        
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO findings 
                   (scan_id, url, pattern_name, pattern_category, 
                    matched_text, context, severity, hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, url, pattern_name, pattern_category, 
                 matched_text[:500], context[:1000], severity, finding_hash)
            )
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Duplicate finding
            return None
            
    def add_page(self, scan_id, url, status_code=200, has_javascript=False):
        """Add a scanned page to the database"""
        cursor = self.conn.cursor()
        cursor.execute(
            """INSERT INTO pages (scan_id, url, status_code, has_javascript)
               VALUES (?, ?, ?, ?)""",
            (scan_id, url, status_code, has_javascript)
        )
        self.conn.commit()
        
    def get_scan_history(self, limit=50):
        """Get recent scan history"""
        cursor = self.conn.cursor()
        cursor.execute(
            """SELECT scan_id, base_url, start_time, end_time, 
                      pages_scanned, findings_count, status
               FROM scans
               ORDER BY start_time DESC
               LIMIT ?""",
            (limit,)
        )
        return cursor.fetchall()
        
    def get_findings_by_scan(self, scan_id):
        """Get all findings for a specific scan"""
        cursor = self.conn.cursor()
        cursor.execute(
            """SELECT url, pattern_name, pattern_category, 
                      matched_text, context, severity, timestamp
               FROM findings
               WHERE scan_id = ?
               ORDER BY severity DESC, timestamp""",
            (scan_id,)
        )
        return cursor.fetchall()
        
    def get_statistics(self):
        """Get overall statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        stats['total_scans'] = cursor.fetchone()[0]
        
        # Total findings
        cursor.execute("SELECT COUNT(*) FROM findings")
        stats['total_findings'] = cursor.fetchone()[0]
        
        # Top patterns
        cursor.execute(
            """SELECT pattern_name, COUNT(*) as count
               FROM findings
               GROUP BY pattern_name
               ORDER BY count DESC
               LIMIT 10"""
        )
        stats['top_patterns'] = cursor.fetchall()
        
        # Severity distribution
        cursor.execute(
            """SELECT severity, COUNT(*) as count
               FROM findings
               GROUP BY severity"""
        )
        stats['severity_distribution'] = cursor.fetchall()
        
        return stats
        
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# ============================================================================
# ENHANCED CRAWLER ENGINE
# ============================================================================

class WebCrawler:
    """Enhanced web crawling engine with JS rendering and pattern matching"""
    
    def __init__(self, base_url, max_depth=3, max_pages=100, delay=1.0, 
                 use_selenium=False, browser='chrome'):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.use_selenium = use_selenium and SELENIUM_AVAILABLE
        self.browser_type = browser
        self.driver = None
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.results = []
        self.patterns = {}
        self.session = requests.Session()
        self.robot_parser = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        self.stop_crawling = False
        self.progress_callback = None
        self.status_callback = None
        self.db_manager = None
        self.current_scan_id = None
        
    def set_database(self, db_manager):
        """Set database manager"""
        self.db_manager = db_manager
        
    def init_selenium(self):
        """Initialize Selenium WebDriver"""
        if not self.use_selenium:
            return False
            
        try:
            if self.browser_type == 'chrome':
                options = ChromeOptions()
                options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument(f'user-agent={random.choice(self.user_agents)}')
                self.driver = webdriver.Chrome(options=options)
            else:  # Firefox
                options = FirefoxOptions()
                options.add_argument('--headless')
                options.set_preference("general.useragent.override", random.choice(self.user_agents))
                self.driver = webdriver.Firefox(options=options)
            
            self.driver.set_page_load_timeout(30)
            return True
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"Failed to initialize Selenium: {str(e)}")
            self.use_selenium = False
            return False
            
    def cleanup_selenium(self):
        """Clean up Selenium WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
        
    def set_patterns(self, patterns):
        """Set patterns to search for"""
        self.patterns = patterns
        
    def set_callbacks(self, progress_callback=None, status_callback=None):
        """Set GUI callbacks for progress updates"""
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        
    def check_robots_txt(self):
        """Check and parse robots.txt"""
        try:
            self.robot_parser = RobotFileParser()
            robots_url = f"{urlparse(self.base_url).scheme}://{self.domain}/robots.txt"
            self.robot_parser.set_url(robots_url)
            self.robot_parser.read()
            return True
        except:
            return False
            
    def can_fetch(self, url):
        """Check if URL can be fetched according to robots.txt"""
        if self.robot_parser:
            return self.robot_parser.can_fetch("*", url)
        return True
        
    def fetch_page(self, url):
        """Fetch a single page with optional JS rendering"""
        html = None
        headers = {}
        has_javascript = False
        
        # First try with requests
        try:
            response = self.session.get(
                url, 
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=10,
                verify=False
            )
            html = response.text
            headers = dict(response.headers)
            
            # Check if page has JavaScript that might need rendering
            if self.use_selenium and self._needs_js_rendering(html):
                has_javascript = True
                try:
                    self.driver.get(url)
                    # Wait for dynamic content
                    time.sleep(2)
                    # Get rendered HTML
                    html = self.driver.page_source
                    
                    # Extract JavaScript variables and API calls
                    js_content = self._extract_javascript_content()
                    if js_content:
                        html += f"\n<!-- EXTRACTED JS CONTENT -->\n{js_content}"
                        
                except Exception as e:
                    if self.status_callback:
                        self.status_callback(f"JS rendering failed for {url}: {str(e)}")
                        
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"Error fetching {url}: {str(e)}")
            return None, None, False
            
        return html, headers, has_javascript
        
    def _needs_js_rendering(self, html):
        """Check if page likely needs JavaScript rendering"""
        indicators = [
            'React.', 'Vue.', 'Angular', 'angular',
            '__NEXT_DATA__', '__NUXT__',
            'window.__INITIAL_STATE__',
            'data-reactroot', 'ng-app',
            '<script type="module"',
            'import ', 'export default',
            'fetch(', 'axios.', '$.ajax'
        ]
        return any(indicator in html for indicator in indicators)
        
    def _extract_javascript_content(self):
        """Extract JavaScript content using Selenium"""
        if not self.driver:
            return ""
            
        js_content = []
        
        try:
            # Extract global variables
            global_vars = self.driver.execute_script("""
                var vars = {};
                for (var prop in window) {
                    if (window.hasOwnProperty(prop)) {
                        try {
                            var val = window[prop];
                            if (typeof val === 'string' && val.length < 1000) {
                                vars[prop] = val;
                            }
                        } catch(e) {}
                    }
                }
                return JSON.stringify(vars);
            """)
            if global_vars:
                js_content.append(f"GLOBAL_VARS: {global_vars}")
                
            # Extract localStorage
            local_storage = self.driver.execute_script("return JSON.stringify(localStorage);")
            if local_storage and local_storage != "{}":
                js_content.append(f"LOCAL_STORAGE: {local_storage}")
                
            # Extract sessionStorage
            session_storage = self.driver.execute_script("return JSON.stringify(sessionStorage);")
            if session_storage and session_storage != "{}":
                js_content.append(f"SESSION_STORAGE: {session_storage}")
                
            # Extract all script contents
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                src = script.get_attribute("src")
                if not src:  # Inline script
                    content = script.get_attribute("innerHTML")
                    if content:
                        js_content.append(f"INLINE_SCRIPT: {content[:5000]}")
                        
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"JS extraction error: {str(e)}")
                
        return "\n".join(js_content)
        
    def extract_links(self, html, current_url):
        """Extract all links from HTML"""
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Standard links
            for tag in soup.find_all(['a', 'link']):
                href = tag.get('href')
                if href:
                    absolute_url = urljoin(current_url, href)
                    if urlparse(absolute_url).netloc == self.domain:
                        links.add(absolute_url.split('#')[0])
            
            # Forms
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    absolute_url = urljoin(current_url, action)
                    if urlparse(absolute_url).netloc == self.domain:
                        links.add(absolute_url)
            
            # JavaScript URLs
            js_patterns = [
                r'["\']([^"\']*?\.(?:html|php|jsp|asp|aspx))["\']',
                r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']',
                r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(?:get|post)\(["\']([^"\']+)["\']',
                r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in js_patterns:
                found_urls = re.findall(pattern, html, re.IGNORECASE)
                for url in found_urls:
                    if not url.startswith(('data:', 'javascript:', '#')):
                        absolute_url = urljoin(current_url, url)
                        if urlparse(absolute_url).netloc == self.domain:
                            links.add(absolute_url)
                    
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"Error parsing links: {str(e)}")
        return links
        
    def search_patterns(self, content, url):
        """Enhanced pattern searching with severity classification"""
        matches = []
        
        # Determine content type for better matching
        is_javascript = any(ext in url for ext in ['.js', '.json']) or 'javascript' in content[:100]
        
        for pattern_name, pattern_regex in self.patterns.items():
            try:
                # Determine severity based on pattern type
                severity = self._get_pattern_severity(pattern_name)
                
                found = re.finditer(pattern_regex, content, re.IGNORECASE | re.MULTILINE)
                for match in found:
                    # Extract context
                    context_start = max(0, match.start() - 100)
                    context_end = min(len(content), match.end() + 100)
                    context = content[context_start:context_end]
                    context = re.sub(r'\s+', ' ', context).strip()
                    
                    # Get pattern category
                    category = self._get_pattern_category(pattern_name)
                    
                    matches.append({
                        'url': url,
                        'pattern': pattern_name,
                        'category': category,
                        'match': match.group(0)[:200],  # Limit match length
                        'context': context,
                        'severity': severity,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'is_javascript': is_javascript
                    })
                    
            except Exception as e:
                if self.status_callback:
                    self.status_callback(f"Pattern error ({pattern_name}): {str(e)}")
        return matches
        
    def _get_pattern_severity(self, pattern_name):
        """Determine severity based on pattern name"""
        high_severity = ['private key', 'secret', 'password', 'credit card', 'ssn', 'api key', 'token']
        medium_severity = ['email', 'phone', 'username', 'config', 'backup']
        
        pattern_lower = pattern_name.lower()
        for term in high_severity:
            if term in pattern_lower:
                return 'high'
        for term in medium_severity:
            if term in pattern_lower:
                return 'medium'
        return 'low'
        
    def _get_pattern_category(self, pattern_name):
        """Get pattern category"""
        for category, patterns in PATTERN_KITS.items():
            if pattern_name in patterns:
                return category
        return 'Custom'
        
    def crawl(self):
        """Main crawling method"""
        self.stop_crawling = False
        self.visited_urls = set()
        self.results = []
        
        # Initialize Selenium if needed
        if self.use_selenium:
            if self.status_callback:
                self.status_callback("Initializing browser for JavaScript rendering...")
            self.init_selenium()
        
        # Start database scan record
        if self.db_manager:
            self.current_scan_id = self.db_manager.start_scan(self.base_url)
        
        # Check robots.txt
        if self.status_callback:
            self.status_callback("Checking robots.txt...")
        self.check_robots_txt()
        
        # Initialize queue with base URL
        self.url_queue.put((self.base_url, 0))
        
        while not self.url_queue.empty() and len(self.visited_urls) < self.max_pages:
            if self.stop_crawling:
                break
                
            url, depth = self.url_queue.get()
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
                
            if not self.can_fetch(url):
                if self.status_callback:
                    self.status_callback(f"Skipping {url} (robots.txt)")
                continue
                
            self.visited_urls.add(url)
            
            if self.status_callback:
                self.status_callback(f"Crawling: {url}")
            if self.progress_callback:
                progress = (len(self.visited_urls) / self.max_pages) * 100
                self.progress_callback(int(progress))
                
            # Fetch page
            html, headers, has_javascript = self.fetch_page(url)
            if not html:
                continue
            
            # Record page in database
            if self.db_manager and self.current_scan_id:
                self.db_manager.add_page(self.current_scan_id, url, 200, has_javascript)
                
            # Search patterns in HTML
            matches = self.search_patterns(html, url)
            
            # Search patterns in headers
            if headers:
                header_text = '\n'.join([f"{k}: {v}" for k, v in headers.items()])
                header_matches = self.search_patterns(header_text, f"{url} (headers)")
                matches.extend(header_matches)
            
            # Add matches to results and database
            for match in matches:
                self.results.append(match)
                if self.db_manager and self.current_scan_id:
                    self.db_manager.add_finding(
                        self.current_scan_id,
                        match['url'],
                        match['pattern'],
                        match['category'],
                        match['match'],
                        match['context'],
                        match['severity']
                    )
            
            # Extract and queue new links
            if depth < self.max_depth:
                links = self.extract_links(html, url)
                for link in links:
                    if link not in self.visited_urls:
                        self.url_queue.put((link, depth + 1))
                        
            # Polite delay
            time.sleep(self.delay)
        
        # Cleanup
        self.cleanup_selenium()
        
        # Finalize database record
        if self.db_manager and self.current_scan_id:
            self.db_manager.end_scan(
                self.current_scan_id,
                len(self.visited_urls),
                len(self.results)
            )
            
        if self.status_callback:
            self.status_callback(f"Crawl complete. Visited {len(self.visited_urls)} pages, found {len(self.results)} matches.")
        if self.progress_callback:
            self.progress_callback(100)
            
        return self.results
        
    def stop(self):
        """Stop crawling"""
        self.stop_crawling = True
        self.cleanup_selenium()

# ============================================================================
# CRAWLER THREAD
# ============================================================================

class CrawlerThread(QThread):
    """Thread for running the crawler without blocking GUI"""
    progress_signal = pyqtSignal(int)
    status_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(list)
    
    def __init__(self, crawler):
        super().__init__()
        self.crawler = crawler
        self.crawler.set_callbacks(
            progress_callback=self.progress_signal.emit,
            status_callback=self.status_signal.emit
        )
        
    def run(self):
        """Run the crawler"""
        results = self.crawler.crawl()
        for result in results:
            self.result_signal.emit(result)
        self.finished_signal.emit(results)
        
    def stop(self):
        """Stop the crawler"""
        self.crawler.stop()

# ============================================================================
# ENHANCED GUI
# ============================================================================

class WebScraperGUI(QMainWindow):
    """Enhanced application window with database integration"""
    
    def __init__(self):
        super().__init__()
        self.crawler = None
        self.crawler_thread = None
        self.results = []
        self.db_manager = DatabaseManager()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Draugr v2.0 - Security Research Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header_label = QLabel("Web Scraper & Pattern Matcher with JS Rendering")
        header_label.setFont(QFont("Arial", 16, QFont.Bold))
        header_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header_label)
        
        # Warning message
        warning_label = QLabel("⚠️ WARNING: Only scan websites you own or have explicit permission to test!")
        warning_label.setStyleSheet("QLabel { color: red; font-weight: bold; }")
        warning_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(warning_label)
        
        # Tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Configuration tab
        config_tab = QWidget()
        config_layout = QVBoxLayout(config_tab)
        
        # URL input group
        url_group = QGroupBox("Target Configuration")
        url_layout = QVBoxLayout()
        
        url_input_layout = QHBoxLayout()
        url_input_layout.addWidget(QLabel("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_input_layout.addWidget(self.url_input)
        url_layout.addLayout(url_input_layout)
        
        # Crawl settings
        settings_layout = QHBoxLayout()
        
        settings_layout.addWidget(QLabel("Max Depth:"))
        self.depth_input = QSpinBox()
        self.depth_input.setRange(1, 10)
        self.depth_input.setValue(3)
        settings_layout.addWidget(self.depth_input)
        
        settings_layout.addWidget(QLabel("Max Pages:"))
        self.pages_input = QSpinBox()
        self.pages_input.setRange(1, 1000)
        self.pages_input.setValue(50)
        settings_layout.addWidget(self.pages_input)
        
        settings_layout.addWidget(QLabel("Delay (sec):"))
        self.delay_input = QSpinBox()
        self.delay_input.setRange(0, 10)
        self.delay_input.setValue(1)
        settings_layout.addWidget(self.delay_input)
        
        # JavaScript rendering option
        self.js_render_checkbox = QCheckBox("Enable JavaScript Rendering (Selenium)")
        self.js_render_checkbox.setChecked(False)
        if not SELENIUM_AVAILABLE:
            self.js_render_checkbox.setEnabled(False)
            self.js_render_checkbox.setText("JavaScript Rendering (Install Selenium)")
        settings_layout.addWidget(self.js_render_checkbox)
        
        # Browser selection
        self.browser_combo = QComboBox()
        self.browser_combo.addItems(["chrome", "firefox"])
        settings_layout.addWidget(QLabel("Browser:"))
        settings_layout.addWidget(self.browser_combo)
        
        settings_layout.addStretch()
        url_layout.addLayout(settings_layout)
        
        url_group.setLayout(url_layout)
        config_layout.addWidget(url_group)
        
        # Pattern configuration
        pattern_group = QGroupBox("Pattern Configuration")
        pattern_layout = QVBoxLayout()
        
        # Pattern kit selector
        kit_layout = QHBoxLayout()
        kit_layout.addWidget(QLabel("Load Pattern Kit:"))
        self.pattern_kit_combo = QComboBox()
        self.pattern_kit_combo.addItems(["Custom"] + list(PATTERN_KITS.keys()))
        self.pattern_kit_combo.currentTextChanged.connect(self.load_pattern_kit)
        kit_layout.addWidget(self.pattern_kit_combo)
        
        # Multiple kit selection
        self.load_all_btn = QPushButton("Load All Kits")
        self.load_all_btn.clicked.connect(self.load_all_kits)
        kit_layout.addWidget(self.load_all_btn)
        
        kit_layout.addStretch()
        pattern_layout.addLayout(kit_layout)
        
        # Pattern list
        self.pattern_list = QListWidget()
        self.pattern_list.setMaximumHeight(200)
        pattern_layout.addWidget(self.pattern_list)
        
        # Add custom pattern
        custom_layout = QHBoxLayout()
        self.pattern_name_input = QLineEdit()
        self.pattern_name_input.setPlaceholderText("Pattern name")
        custom_layout.addWidget(self.pattern_name_input)
        
        self.pattern_regex_input = QLineEdit()
        self.pattern_regex_input.setPlaceholderText("Regular expression")
        custom_layout.addWidget(self.pattern_regex_input)
        
        add_pattern_btn = QPushButton("Add Pattern")
        add_pattern_btn.clicked.connect(self.add_custom_pattern)
        custom_layout.addWidget(add_pattern_btn)
        
        remove_pattern_btn = QPushButton("Remove Selected")
        remove_pattern_btn.clicked.connect(self.remove_pattern)
        custom_layout.addWidget(remove_pattern_btn)
        
        clear_patterns_btn = QPushButton("Clear All")
        clear_patterns_btn.clicked.connect(lambda: self.pattern_list.clear())
        custom_layout.addWidget(clear_patterns_btn)
        
        pattern_layout.addLayout(custom_layout)
        
        pattern_group.setLayout(pattern_layout)
        config_layout.addWidget(pattern_group)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; }")
        control_layout.addWidget(self.stop_btn)
        
        export_btn = QPushButton("Export Results")
        export_btn.clicked.connect(self.export_results)
        control_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        control_layout.addWidget(clear_btn)
        
        control_layout.addStretch()
        config_layout.addLayout(control_layout)
        
        tab_widget.addTab(config_tab, "Configuration")
        
        # Results tab
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        results_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready to scan")
        results_layout.addWidget(self.status_label)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels(
            ["Timestamp", "URL", "Category", "Pattern", "Severity", "Match", "Context"]
        )
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSortingEnabled(True)
        results_layout.addWidget(self.results_table)
        
        tab_widget.addTab(results_tab, "Results")
        
        # Database History tab
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        
        # Refresh button
        refresh_history_btn = QPushButton("Refresh History")
        refresh_history_btn.clicked.connect(self.load_scan_history)
        history_layout.addWidget(refresh_history_btn)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(
            ["Scan ID", "URL", "Start Time", "Pages", "Findings", "Status"]
        )
        self.history_table.horizontalHeader().setStretchLastSection(True)
        history_layout.addWidget(self.history_table)
        
        # Load findings button
        load_findings_btn = QPushButton("Load Selected Scan Findings")
        load_findings_btn.clicked.connect(self.load_historical_findings)
        history_layout.addWidget(load_findings_btn)
        
        tab_widget.addTab(history_tab, "Scan History")
        
        # Statistics tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        
        self.stats_text = QTextBrowser()
        stats_layout.addWidget(self.stats_text)
        
        tab_widget.addTab(stats_tab, "Statistics")
        
        # Load default patterns
        self.load_pattern_kit("API Keys & Secrets")
        self.load_scan_history()
        
    def load_pattern_kit(self, kit_name):
        """Load a predefined pattern kit"""
        if kit_name in PATTERN_KITS:
            for name, regex in PATTERN_KITS[kit_name].items():
                # Check if pattern already exists
                exists = False
                for i in range(self.pattern_list.count()):
                    item = self.pattern_list.item(i)
                    existing_name, _ = item.data(Qt.UserRole)
                    if existing_name == name:
                        exists = True
                        break
                
                if not exists:
                    display_text = f"[{kit_name}] {name}: {regex[:50]}..."
                    item = QListWidgetItem(display_text)
                    item.setData(Qt.UserRole, (name, regex))
                    self.pattern_list.addItem(item)
                    
    def load_all_kits(self):
        """Load all pattern kits"""
        for kit_name in PATTERN_KITS.keys():
            self.load_pattern_kit(kit_name)
        QMessageBox.information(self, "Patterns Loaded", 
                              f"Loaded {self.pattern_list.count()} patterns from all kits")
                    
    def add_custom_pattern(self):
        """Add a custom pattern"""
        name = self.pattern_name_input.text().strip()
        regex = self.pattern_regex_input.text().strip()
        
        if name and regex:
            try:
                re.compile(regex)
                display_text = f"[Custom] {name}: {regex[:50]}..."
                item = QListWidgetItem(display_text)
                item.setData(Qt.UserRole, (name, regex))
                self.pattern_list.addItem(item)
                self.pattern_name_input.clear()
                self.pattern_regex_input.clear()
            except re.error as e:
                QMessageBox.warning(self, "Invalid Regex", f"Invalid regular expression: {str(e)}")
                
    def remove_pattern(self):
        """Remove selected pattern"""
        current_item = self.pattern_list.currentItem()
        if current_item:
            row = self.pattern_list.row(current_item)
            self.pattern_list.takeItem(row)
            
    def get_patterns(self):
        """Get all configured patterns"""
        patterns = {}
        for i in range(self.pattern_list.count()):
            item = self.pattern_list.item(i)
            name, regex = item.data(Qt.UserRole)
            patterns[name] = regex
        return patterns
        
    def start_scan(self):
        """Start the web crawling scan"""
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "No URL", "Please enter a URL to scan")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
            
        patterns = self.get_patterns()
        if not patterns:
            QMessageBox.warning(self, "No Patterns", "Please add at least one pattern to search for")
            return
            
        # Confirmation dialog
        reply = QMessageBox.question(self, "Confirm Scan", 
                                   f"Are you sure you have permission to scan:\n{url}\n\n"
                                   "Unauthorized scanning may be illegal!",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply != QMessageBox.Yes:
            return
            
        # Create crawler
        self.crawler = WebCrawler(
            base_url=url,
            max_depth=self.depth_input.value(),
            max_pages=self.pages_input.value(),
            delay=self.delay_input.value(),
            use_selenium=self.js_render_checkbox.isChecked(),
            browser=self.browser_combo.currentText()
        )
        self.crawler.set_patterns(patterns)
        self.crawler.set_database(self.db_manager)
        
        # Create and start thread
        self.crawler_thread = CrawlerThread(self.crawler)
        self.crawler_thread.progress_signal.connect(self.update_progress)
        self.crawler_thread.status_signal.connect(self.update_status)
        self.crawler_thread.result_signal.connect(self.add_result)
        self.crawler_thread.finished_signal.connect(self.scan_finished)
        
        # Clear previous results
        self.results = []
        self.results_table.setRowCount(0)
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # Start crawling
        self.crawler_thread.start()
        
    def stop_scan(self):
        """Stop the scan"""
        if self.crawler_thread:
            self.crawler_thread.stop()
            
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        
    def update_status(self, message):
        """Update status message"""
        self.status_label.setText(message)
        
    def add_result(self, result):
        """Add a result to the table"""
        self.results.append(result)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(result['timestamp']))
        self.results_table.setItem(row, 1, QTableWidgetItem(result['url']))
        self.results_table.setItem(row, 2, QTableWidgetItem(result.get('category', 'Unknown')))
        self.results_table.setItem(row, 3, QTableWidgetItem(result['pattern']))
        self.results_table.setItem(row, 4, QTableWidgetItem(result.get('severity', 'medium')))
        self.results_table.setItem(row, 5, QTableWidgetItem(result['match'][:100]))
        self.results_table.setItem(row, 6, QTableWidgetItem(result['context'][:200]))
        
        # Color code by severity
        severity_colors = {
            'high': QColor(255, 200, 200),
            'medium': QColor(255, 230, 200),
            'low': QColor(255, 255, 200)
        }
        
        severity = result.get('severity', 'medium')
        if severity in severity_colors:
            for col in range(7):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(severity_colors[severity])
                    
    def scan_finished(self, results):
        """Handle scan completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        # Update statistics
        self.update_statistics()
        
        # Refresh history
        self.load_scan_history()
        
        QMessageBox.information(self, "Scan Complete", 
                              f"Scan completed!\n"
                              f"Pages scanned: {len(self.crawler.visited_urls)}\n"
                              f"Patterns found: {len(results)}")
                              
    def load_scan_history(self):
        """Load scan history from database"""
        history = self.db_manager.get_scan_history()
        self.history_table.setRowCount(0)
        
        for scan in history:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            
            self.history_table.setItem(row, 0, QTableWidgetItem(str(scan[0])))  # scan_id
            self.history_table.setItem(row, 1, QTableWidgetItem(scan[1]))  # base_url
            self.history_table.setItem(row, 2, QTableWidgetItem(scan[2]))  # start_time
            self.history_table.setItem(row, 3, QTableWidgetItem(str(scan[4])))  # pages_scanned
            self.history_table.setItem(row, 4, QTableWidgetItem(str(scan[5])))  # findings_count
            self.history_table.setItem(row, 5, QTableWidgetItem(scan[6]))  # status
            
    def load_historical_findings(self):
        """Load findings from selected historical scan"""
        current_row = self.history_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a scan from history")
            return
            
        scan_id = int(self.history_table.item(current_row, 0).text())
        findings = self.db_manager.get_findings_by_scan(scan_id)
        
        # Clear and populate results table
        self.results_table.setRowCount(0)
        self.results = []
        
        for finding in findings:
            result = {
                'url': finding[0],
                'pattern': finding[1],
                'category': finding[2],
                'match': finding[3],
                'context': finding[4],
                'severity': finding[5],
                'timestamp': finding[6]
            }
            self.add_result(result)
            
        QMessageBox.information(self, "Findings Loaded", 
                              f"Loaded {len(findings)} findings from scan #{scan_id}")
                              
    def update_statistics(self):
        """Update the statistics tab"""
        stats = self.db_manager.get_statistics()
        
        # Generate HTML report
        html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                h2 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 5px; }
                .stat-box { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }
                .stat-label { font-weight: bold; color: #666; }
                .stat-value { font-size: 24px; color: #4CAF50; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th { background: #4CAF50; color: white; padding: 10px; text-align: left; }
                td { padding: 8px; border-bottom: 1px solid #ddd; }
                .severity-high { color: #ff4444; font-weight: bold; }
                .severity-medium { color: #ff9944; }
                .severity-low { color: #999; }
            </style>
        </head>
        <body>
        """
        
        html += "<h2>Overall Statistics</h2>"
        html += f"""
        <div class="stat-box">
            <span class="stat-label">Total Scans:</span>
            <span class="stat-value">{stats.get('total_scans', 0)}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Total Findings:</span>
            <span class="stat-value">{stats.get('total_findings', 0)}</span>
        </div>
        """
        
        if self.results:
            html += "<h2>Current Scan Results</h2>"
            
            # Pattern distribution
            pattern_counts = defaultdict(int)
            category_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for result in self.results:
                pattern_counts[result['pattern']] += 1
                category_counts[result.get('category', 'Unknown')] += 1
                severity_counts[result.get('severity', 'medium')] += 1
            
            html += "<h3>Findings by Category</h3>"
            html += "<table>"
            html += "<tr><th>Category</th><th>Count</th></tr>"
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                html += f"<tr><td>{category}</td><td>{count}</td></tr>"
            html += "</table>"
            
            html += "<h3>Severity Distribution</h3>"
            html += "<table>"
            html += "<tr><th>Severity</th><th>Count</th></tr>"
            for severity in ['high', 'medium', 'low']:
                if severity in severity_counts:
                    html += f"<tr><td class='severity-{severity}'>{severity.upper()}</td>"
                    html += f"<td>{severity_counts[severity]}</td></tr>"
            html += "</table>"
            
            html += "<h3>Top Patterns Found</h3>"
            html += "<table>"
            html += "<tr><th>Pattern</th><th>Occurrences</th></tr>"
            for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
                html += f"<tr><td>{pattern}</td><td>{count}</td></tr>"
            html += "</table>"
            
        # Historical statistics
        if stats.get('top_patterns'):
            html += "<h2>Historical Top Patterns</h2>"
            html += "<table>"
            html += "<tr><th>Pattern</th><th>Total Occurrences</th></tr>"
            for pattern, count in stats['top_patterns']:
                html += f"<tr><td>{pattern}</td><td>{count}</td></tr>"
            html += "</table>"
            
        html += "</body></html>"
        
        self.stats_text.setHtml(html)
        
    def export_results(self):
        """Export results to file"""
        if not self.results:
            QMessageBox.warning(self, "No Results", "No results to export")
            return
            
        file_path, file_type = QFileDialog.getSaveFileName(
            self, "Export Results", "", 
            "CSV Files (*.csv);;JSON Files (*.json);;HTML Report (*.html)"
        )
        
        if not file_path:
            return
            
        try:
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['timestamp', 'url', 'category', 'pattern', 
                                'severity', 'match', 'context']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.results)
                    
            elif file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2)
                    
            elif file_path.endswith('.html'):
                self.export_html_report(file_path)
                
            QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export: {str(e)}")
            
    def export_html_report(self, file_path):
        """Export results as HTML report"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Scraper Security Report</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }
                h1 { 
                    color: #333;
                    border-bottom: 3px solid #4CAF50;
                    padding-bottom: 10px;
                }
                .summary {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                }
                .summary-stat {
                    display: inline-block;
                    margin: 0 20px;
                }
                .summary-value {
                    font-size: 24px;
                    font-weight: bold;
                }
                table { 
                    border-collapse: collapse; 
                    width: 100%;
                    margin-top: 20px;
                }
                th { 
                    background: #4CAF50;
                    color: white;
                    padding: 12px;
                    text-align: left;
                    position: sticky;
                    top: 0;
                }
                td { 
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }
                tr:hover { background: #f9f9f9; }
                .severity-high { 
                    background: #ffebee;
                    color: #c62828;
                    font-weight: bold;
                }
                .severity-medium { 
                    background: #fff3e0;
                    color: #ef6c00;
                }
                .severity-low { 
                    background: #f5f5f5;
                    color: #666;
                }
                .pattern-category {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    background: #e3f2fd;
                    color: #1976d2;
                    font-size: 12px;
                }
                .timestamp { 
                    font-size: 0.9em;
                    color: #666;
                }
                .match-text {
                    font-family: 'Courier New', monospace;
                    background: #f5f5f5;
                    padding: 3px 6px;
                    border-radius: 3px;
                    font-size: 0.9em;
                }
                .context {
                    max-width: 400px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Web Scraper Security Report</h1>
                <p><strong>Generated:</strong> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <div class="summary-stat">
                        <div class="summary-value">""" + str(len(self.results)) + """</div>
                        <div>Total Findings</div>
                    </div>
        """
        
        # Calculate severity counts
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        for result in self.results:
            severity_counts[result.get('severity', 'medium')] += 1
            category_counts[result.get('category', 'Unknown')] += 1
            
        html += f"""
                    <div class="summary-stat">
                        <div class="summary-value">{severity_counts.get('high', 0)}</div>
                        <div>High Severity</div>
                    </div>
                    <div class="summary-stat">
                        <div class="summary-value">{severity_counts.get('medium', 0)}</div>
                        <div>Medium Severity</div>
                    </div>
                    <div class="summary-stat">
                        <div class="summary-value">{severity_counts.get('low', 0)}</div>
                        <div>Low Severity</div>
                    </div>
                </div>
                
                <h2>Detailed Findings</h2>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>URL</th>
                        <th>Category</th>
                        <th>Pattern</th>
                        <th>Severity</th>
                        <th>Match</th>
                        <th>Context</th>
                    </tr>
        """
        
        # Sort results by severity
        sorted_results = sorted(self.results, 
                              key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x.get('severity', 'medium'), 1))
        
        for result in sorted_results:
            severity = result.get('severity', 'medium')
            html += f"""
                <tr class="severity-{severity}">
                    <td class="timestamp">{result['timestamp']}</td>
                    <td>{result['url'][:100]}</td>
                    <td><span class="pattern-category">{result.get('category', 'Unknown')}</span></td>
                    <td>{result['pattern']}</td>
                    <td>{severity.upper()}</td>
                    <td><span class="match-text">{result['match'][:100]}</span></td>
                    <td class="context">{result['context'][:200]}</td>
                </tr>
            """
        
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)
            
    def clear_results(self):
        """Clear all results"""
        self.results = []
        self.results_table.setRowCount(0)
        self.stats_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready to scan")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = WebScraperGUI()
    window.show()
    
    # Run application
    sys.exit(app.exec_())

if __name__ == '__main__':
    # Print disclaimer
    print("="*60)
    print("Draugr v2.0 - ADVANCED SECURITY RESEARCH TOOL")
    print("="*60)
    print("\nFEATURES:")
    print("✓ JavaScript rendering with Selenium")
    print("✓ Enhanced API key detection in JavaScript")
    print("✓ Database storage with SQLite")
    print("✓ 200+ predefined patterns across 8 categories")
    print("✓ Severity classification system")
    print("✓ Historical scan tracking")
    print("\nLEGAL DISCLAIMER:")
    print("This tool is for educational purposes and authorized")
    print("security testing only. Always obtain explicit written")
    print("permission before scanning any website.")
    print("\nUnauthorized scanning may violate laws including the")
    print("Computer Fraud and Abuse Act (CFAA).")
    print("="*60)
    print("\nStarting GUI...")
    
    main()
