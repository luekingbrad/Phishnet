PhishNet – Phishing URL Risk Analyzer
PhishNet is a Python-based cybersecurity tool that analyzes URLs for potential phishing indicators and assigns a risk score based on several detection techniques. The script evaluates URLs using keyword detection, Shannon entropy analysis, and domain age verification to identify suspicious patterns commonly associated with phishing attacks.
The tool processes a list of URLs from a text file and generates a structured CSV report that can be reviewed by analysts or imported into other security tools.

Features
PhishNet analyzes URLs using multiple indicators commonly used in phishing detection:
Suspicious Keyword Detection
Scans URLs for commonly used phishing keywords such as login, verify, secure, update, and password.
Shannon Entropy Calculation
Measures the randomness of characters within a URL. Highly random strings can indicate obfuscation or automatically generated phishing domains.
Domain Age Analysis
Uses WHOIS lookups to determine how long a domain has existed. Newly registered domains are often associated with phishing campaigns.
Risk Scoring System
Combines all indicators into a cumulative score to help identify potentially malicious URLs.
CSV Output Reporting
Generates a report file that can easily be analyzed in Excel or other security tools.

Requirements
Python 3.8 or newer
Install required dependency:
pip install python-whois
Standard Python libraries used:
csv
math
datetime
urllib.parse

Installation
Clone the repository:
git clone https://github.com/yourusername/phishnet.git
Navigate to the project folder:
cd phishnet
Install dependencies:
pip install python-whois

Usage
Create a text file named:
sample_urls.txt
Add one URL per line.
Example:
https://google.com
https://secure-login-update.example.com
http://verify-account-now.security-check.net
Run the script:
python phishnet_script.py
The script will analyze each URL and generate:
phishnet_report.csv

Example Output
domain_age_days
entropy
length
score
suspicious_keywords
url
4000
3.2
18
0
0
https://google.com
25
5.7
82
7
3
http://secure-login-update.example.com

Higher scores indicate more potential phishing indicators.

How the Risk Score Works
PhishNet assigns points based on several indicators:
Indicator
Condition
Score Impact
Suspicious Keywords
Each keyword found
+2
Entropy
Entropy greater than 4.0
+2
URL Length
Longer than 75 characters
+1
Domain Age
Domain younger than 100 days
+2
Unknown Domain Age
WHOIS lookup fails
+1

The final score helps analysts quickly identify URLs that warrant further investigation.

Project Structure
phishnet/
│
├── phishnet_script.py
├── sample_urls.txt
├── phishnet_report.csv
└── README.md

Possible Future Improvements
Integration with VirusTotal API
Real-time URL scanning
HTML dashboard output
Email or SIEM integration
Machine learning based classification

Educational Purpose
This project was created as part of a cybersecurity scripting assignment focused on developing practical Python tools for security analysis.

License
This project is released for educational and research purposes.

If you'd like, I can also help you add three things that make GitHub repos look much more professional:
1️⃣ Badges (Python version, license, etc.)
2️⃣ A screenshot of the CSV output
3️⃣ A GIF demo of the script running
Those make projects stand out a lot when professors or employers look at them.
