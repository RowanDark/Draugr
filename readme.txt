================================================================================
                    Draugr v2.0 - SECURITY RESEARCH TOOL
================================================================================

DESCRIPTION
-----------
Advanced web scraper with pattern matching capabilities designed for authorized
security testing and educational purposes. Features JavaScript rendering, 
database storage, and comprehensive pattern detection for API keys, credentials,
and sensitive information.

Version: 2.0
Author: Security Research Tool
License: Educational Use Only

WARNING: This tool is for authorized testing only. Unauthorized scanning of
websites may violate computer fraud and abuse laws. Always obtain explicit
written permission before scanning any website.

================================================================================

FEATURES
--------
- Recursive web crawling with depth and page limits
- JavaScript rendering using Selenium WebDriver
- 200+ predefined regex patterns across 8 categories
- SQLite database for persistent storage
- robots.txt compliance
- Real-time GUI with progress tracking
- Multiple export formats (CSV, JSON, HTML)
- Historical scan tracking and analysis
- Severity classification system
- Pattern categorization and management

================================================================================

INSTALLATION
------------

1. System Requirements:
   - Python 3.7 or higher
   - 4GB RAM minimum (8GB recommended for JS rendering)
   - Windows, macOS, or Linux operating system

2. Install Python Dependencies:
   pip install -r requirements.txt

3. Browser Drivers (for JavaScript rendering):
   
   For Chrome:
   - Download ChromeDriver from https://chromedriver.chromium.org/
   - Extract and add to system PATH
   
   For Firefox:
   - Download GeckoDriver from https://github.com/mozilla/geckodriver/releases
   - Extract and add to system PATH

4. Verify Installation:
   python draugr_main.py

================================================================================

USAGE GUIDE
-----------

Basic Scan:
1. Launch the application: python draugr_main.py
2. Enter target URL (must have permission to scan)
3. Configure scan depth and max pages
4. Select pattern kits or add custom patterns
5. Click "Start Scan"
6. Review results in Results tab
7. Export findings as needed

Advanced Configuration:
- Max Depth: How many link levels to follow (default: 3)
- Max Pages: Maximum pages to scan (default: 50)
- Delay: Seconds between requests (default: 1)
- JavaScript Rendering: Enable for dynamic content sites
- Browser: Choose Chrome or Firefox for JS rendering

Pattern Management:
- Use predefined pattern kits from dropdown menu
- Click "Load All Kits" to load all 200+ patterns
- Add custom patterns with name and regex
- Mix predefined and custom patterns as needed

Database Features:
- All scans automatically saved to scanner_results.db
- View scan history in "Scan History" tab
- Load previous scan findings for review
- Statistics tab shows aggregate data

Export Options:
- CSV: Spreadsheet compatible format
- JSON: Structured data format
- HTML: Professional security report

================================================================================

PATTERN CATEGORIES
------------------

1. API Keys & Secrets (40+ patterns)
   - AWS, Google Cloud, Azure credentials
   - GitHub, GitLab, Bitbucket tokens
   - Payment service keys (Stripe, PayPal, Square)
   - JWT tokens and bearer tokens
   - Social media API keys

2. Database & Infrastructure (15+ patterns)
   - Connection strings (MongoDB, PostgreSQL, MySQL)
   - SSH and PGP private keys
   - Docker registry authentication
   - Kubernetes configurations

3. Financial Data (14+ patterns)
   - Credit card numbers (all major types)
   - Social Security Numbers
   - IBAN and SWIFT codes
   - Cryptocurrency addresses

4. Common Endpoints (20+ patterns)
   - Admin panels and backends
   - Configuration files (.env, .config)
   - Backup and database files
   - Source code and build files
   - Version control directories (.git, .svn)

5. Sensitive Information (15+ patterns)
   - Email addresses and phone numbers
   - Usernames and passwords in text
   - Private IP addresses and MAC addresses
   - UUIDs and various hash formats

6. JavaScript Specific (14+ patterns)
   - API keys in JS variables
   - localStorage/sessionStorage secrets
   - Hardcoded URLs with authentication
   - Config objects with credentials

7. Security Headers & Vulnerabilities (15+ patterns)
   - Missing security headers
   - Version disclosure
   - SQL injection indicators
   - XSS vulnerability patterns
   - Debug mode indicators

8. Cloud Storage & CDN (10+ patterns)
   - S3 bucket URLs
   - Azure blob storage
   - Google Cloud Storage
   - Firebase storage URLs

================================================================================

COMMAND LINE OPTIONS
--------------------

While primarily GUI-based, the crawler engine can be used programmatically:

    from draugr import WebCrawler
    
    crawler = WebCrawler(
        base_url="https://example.com",
        max_depth=3,
        max_pages=100,
        delay=1.0,
        use_selenium=True
    )
    crawler.set_patterns(patterns_dict)
    results = crawler.crawl()

================================================================================

LEGAL COMPLIANCE
----------------

This tool includes features to ensure legal and ethical use:

1. robots.txt Compliance:
   - Automatically checks and respects robots.txt
   - Skips disallowed paths
   - Configurable user-agent strings

2. Rate Limiting:
   - Configurable delay between requests
   - Prevents accidental DoS conditions
   - Polite crawling by default

3. Permission Verification:
   - Requires user confirmation before each scan
   - Displays warning messages about legal requirements
   - Logs all scan activities to database

LEGAL REQUIREMENTS:
- Obtain explicit written permission before scanning
- Respect website terms of service
- Follow applicable laws (CFAA, GDPR, etc.)
- Use only for authorized security testing
- Do not disrupt services or cause harm

================================================================================

TROUBLESHOOTING
---------------

Issue: Selenium not working
Solution: 
- Install selenium: pip install selenium
- Download appropriate browser driver
- Add driver to system PATH
- Verify with: python -c "from selenium import webdriver"

Issue: PyQt5 import error
Solution:
- Reinstall PyQt5: pip install --upgrade PyQt5
- On Linux: sudo apt-get install python3-pyqt5

Issue: SSL certificate errors
Solution:
- Update certificates: pip install --upgrade certifi
- Tool handles SSL errors gracefully by default

Issue: Database locked error
Solution:
- Close other instances of the application
- Delete scanner_results.db if corrupted
- Database will regenerate automatically

Issue: High memory usage with JS rendering
Solution:
- Reduce max_pages setting
- Disable JS rendering if not needed
- Close other browser instances

================================================================================

PERFORMANCE OPTIMIZATION
------------------------

For Large Sites:
- Set reasonable max_pages (100-200)
- Increase delay to respect server resources
- Use specific pattern kits instead of all patterns
- Disable JS rendering if not required

For JavaScript-Heavy Sites:
- Enable JS rendering only when needed
- Allow 2-3 seconds per page for rendering
- Monitor memory usage
- Consider scanning in segments

For Fast Scanning:
- Disable JS rendering
- Use minimal pattern set
- Reduce delay (with permission)
- Increase max_pages if server allows

================================================================================

DATABASE SCHEMA
---------------

The SQLite database (scanner_results.db) contains:

scans table:
- scan_id: Primary key
- base_url: Starting URL
- start_time: Scan initiation time
- end_time: Scan completion time
- pages_scanned: Total pages visited
- findings_count: Total patterns matched
- status: running/complete

findings table:
- finding_id: Primary key
- scan_id: Foreign key to scans
- url: Where pattern was found
- pattern_name: Pattern that matched
- pattern_category: Category of pattern
- matched_text: Actual text matched
- context: Surrounding text
- severity: high/medium/low
- timestamp: When found
- hash: MD5 hash for deduplication

pages table:
- page_id: Primary key
- scan_id: Foreign key to scans
- url: Page URL
- status_code: HTTP response code
- has_javascript: Boolean flag
- timestamp: When scanned

custom_patterns table:
- pattern_id: Primary key
- name: Pattern name
- regex: Regular expression
- category: Pattern category
- severity: Risk level
- created_at: Creation time

================================================================================

BEST PRACTICES
--------------

1. Pre-Scan Checklist:
   - Verify permission to scan target
   - Review robots.txt manually
   - Start with small depth/page limits
   - Test patterns on known content

2. During Scanning:
   - Monitor progress and status
   - Stop scan if unexpected behavior
   - Check server response in status bar
   - Save results periodically

3. Post-Scan Analysis:
   - Review high severity findings first
   - Verify matches aren't false positives
   - Document findings properly
   - Export reports for documentation

4. Responsible Disclosure:
   - Report findings to appropriate parties
   - Follow responsible disclosure timelines
   - Do not exploit found vulnerabilities
   - Maintain confidentiality as required

================================================================================

SUPPORT AND UPDATES
--------------------

This tool is provided for educational purposes. For questions or issues:

1. Check this README for solutions
2. Review the source code comments
3. Test with simplified configurations
4. Ensure all dependencies are installed

Remember: This tool is powerful and must be used responsibly. Always prioritize
ethical considerations and legal compliance in security testing.

================================================================================

CHANGELOG
---------

Version 2.0 (Current):
- Added JavaScript rendering with Selenium
- Implemented SQLite database storage
- Expanded to 200+ regex patterns
- Added severity classification
- Enhanced GUI with history tracking
- Improved export formats

Version 1.0:
- Initial release
- Basic crawling and pattern matching
- PyQt5 GUI interface
- CSV/JSON export

================================================================================

DISCLAIMER
----------

THIS SOFTWARE IS PROVIDED "AS IS" FOR EDUCATIONAL PURPOSES ONLY. THE AUTHOR
ASSUMES NO LIABILITY FOR MISUSE OR DAMAGE CAUSED BY THIS SOFTWARE. USERS ARE
SOLELY RESPONSIBLE FOR ENSURING LEGAL COMPLIANCE AND OBTAINING PROPER
AUTHORIZATION BEFORE USE.

BY USING THIS SOFTWARE, YOU AGREE TO:
- Use it only for authorized security testing
- Obtain explicit permission before scanning
- Comply with all applicable laws
- Accept all risks and responsibilities

================================================================================
                              END OF README
================================================================================
