# PhishNet — AI-Assisted Email URL Analysis Tool

PhishNet is a Python-based URL analysis tool designed to identify characteristics commonly associated with phishing and suspicious URLs. The project combines keyword analysis, Shannon entropy, URL length, WHOIS domain-age information, and a weighted risk-scoring system to classify URLs as **Low, Medium, or High risk**.

The current version supports batch URL analysis from a text file and automatically generates a CSV results report and summary statistics.

## Project Overview

Phishing attacks frequently rely on deceptive URLs designed to imitate legitimate services, encourage credential submission, or conceal malicious destinations.

PhishNet analyzes URLs for several indicators associated with suspicious activity and combines those indicators into a risk score.

The project evaluates:

* Suspicious phishing-related keywords
* URL entropy
* URL length
* Domain age
* Unknown domain age
* Overall risk score
* Risk classification

The goal is to demonstrate how multiple URL characteristics can be combined into a lightweight automated phishing-analysis workflow.

## Analysis Workflow

```text
sample_urls.txt
       │
       ▼
   PhishNet
       │
       ├── Suspicious Keyword Analysis
       │
       ├── Shannon Entropy Analysis
       │
       ├── URL Length Analysis
       │
       └── WHOIS Domain Age Analysis
       │
       ▼
   Risk Scoring
       │
       ▼
Low / Medium / High
       │
       ├── analysis_results.csv
       │
       └── Summary Report
```

## Key Features

### Suspicious Keyword Detection

PhishNet checks URLs for keywords commonly associated with phishing attempts, including:

```text
account
banking
confirm
login
password
secure
update
verify
```

Each detected keyword contributes to the URL's overall risk score.

### Shannon Entropy Analysis

PhishNet calculates Shannon entropy to identify URLs containing unusually random-looking character patterns.

Higher entropy can indicate URL structures designed to obscure or randomize content.

URLs with entropy greater than `4.0` receive additional risk points.

### URL Length Analysis

Long URLs can be suspicious when combined with other phishing indicators.

PhishNet adds to the risk score when a URL exceeds `75` characters.

### WHOIS Domain-Age Analysis

PhishNet uses WHOIS information to determine the approximate age of a domain.

Recently created domains can receive additional risk points because newly registered domains may be associated with temporary phishing infrastructure.

The program also handles situations where WHOIS information is unavailable.

### Weighted Risk Scoring

PhishNet combines the results of its analysis into a single numerical score.

The scoring system considers:

| Indicator               | Condition              | Score |
| ----------------------- | ---------------------- | ----: |
| Suspicious keywords     | Each detected keyword  |    +2 |
| High entropy            | Entropy > 4.0          |    +2 |
| Long URL                | Length > 75 characters |    +1 |
| Recently created domain | Domain age < 100 days  |    +2 |
| Unknown domain age      | WHOIS unavailable      |    +1 |

The final score determines the risk classification:

| Score | Risk   |
| ----: | ------ |
|   0–2 | Low    |
|   3–5 | Medium |
|    6+ | High   |

## Batch URL Analysis

URLs are loaded from:

```text
sample_urls.txt
```

The application processes each URL sequentially and displays progress during analysis.

Example:

```text
[1/20] Analyzing: https://www.google.com
[2/20] Analyzing: https://www.amazon.com
```

The project includes a mixture of:

* Legitimate domains
* Suspicious login URLs
* Brand impersonation URLs
* Random-looking domains
* URL shorteners
* Long URLs
* Test URLs

This provides a varied dataset for demonstrating the analysis process.

## CSV Reporting

After processing the URLs, PhishNet generates:

```text
analysis_results.csv
```

The report contains:

```text
url
suspicious_keywords
entropy
length
domain_age_days
score
risk
```

This makes the analysis results easy to review, filter, and further process using spreadsheet or data-analysis tools.

The generated CSV report is intentionally excluded from the public repository because it is a runtime-generated artifact.

## Summary Reporting

PhishNet also generates a console-based summary report after analysis.

The summary includes:

* Total URLs analyzed
* High-risk URL count
* Medium-risk URL count
* Low-risk URL count
* Highest-risk URLs
* Individual risk scores
* Generated CSV report location

This provides a quick overview of the results without requiring the user to open the CSV file.

## Technologies Used

* Python
* CSV
* WHOIS
* URL parsing
* Shannon entropy
* Mathematical scoring
* Automated risk classification

### Python Libraries

The project uses:

```text
python-whois
python-dateutil
six
```

## Project Structure

```text
PhishNet/
│
├── .gitignore
├── LICENSE
├── README.md
├── main.py
├── requirements.txt
├── sample_urls.txt
│
└── screenshots/
```

### Core Files

**`main.py`**

Contains the primary PhishNet analysis engine, including:

* Suspicious keyword detection
* Shannon entropy calculation
* WHOIS domain-age lookup
* URL parsing
* Risk scoring
* Risk classification
* Batch URL processing
* CSV report generation
* Summary reporting

**`sample_urls.txt`**

Contains the test URLs used by PhishNet during analysis.

**`requirements.txt`**

Contains the Python dependencies required to run the project.

**`screenshots/`**

Contains visual documentation of the PhishNet analysis process and results.

**`LICENSE`**

Contains the MIT License governing use and distribution of the project.

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd PhishNet
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate the environment on macOS/Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run PhishNet

```bash
python3 main.py
```

PhishNet will automatically load the URLs from:

```text
sample_urls.txt
```

and generate:

```text
analysis_results.csv
```

The program will also display the analysis progress and summary report in the terminal.

## Example Output

The application produces a summary similar to:

```text
==================================================
           PHISHNET SUMMARY REPORT
==================================================

URLs Analyzed : 20

Risk Distribution
-----------------
High   : X
Medium : X
Low    : X

Highest Risk URLs
-----------------
Score: XX | High   | example-url
Score: XX | High   | example-url
Score: XX | Medium | example-url

CSV Report:
analysis_results.csv

Analysis Complete!
==================================================
```

Actual results can vary depending on WHOIS availability and the characteristics of the URLs being analyzed.

## Security Considerations

PhishNet is an **analysis and educational tool**, not a definitive phishing-detection system.

A URL classified as Low risk should not automatically be considered safe, and a High-risk classification does not independently prove that a URL is malicious.

WHOIS information may also be unavailable or incomplete. PhishNet accounts for this by assigning an unknown domain-age condition when the lookup cannot be completed.

The project should therefore be viewed as a **risk-assessment aid** that can help prioritize URLs for further investigation.

## Skills Demonstrated

This project demonstrates practical experience with:

* Python development
* Cybersecurity automation
* Phishing analysis
* URL analysis
* WHOIS investigation
* Shannon entropy
* Risk scoring
* Security-oriented data processing
* CSV report generation
* Batch processing
* Exception handling
* Automated security classification
* Command-line reporting
* Git/GitHub project organization

## Project Goals

The primary goal of PhishNet was to create a practical security tool capable of automatically analyzing URLs and identifying characteristics associated with phishing activity.

The project demonstrates how multiple technical indicators can be combined into an automated risk-scoring workflow rather than relying on a single detection method.

## Future Development

Potential future improvements include:

* Machine-learning-based URL classification
* Expanded phishing indicator libraries
* Domain reputation lookups
* DNS analysis
* SSL/TLS certificate analysis
* Threat-intelligence integration
* Improved URL-shortener analysis
* Visualization dashboards
* Automated report generation
* Additional phishing detection heuristics

## Author

**Bradley Lueking**

Cybersecurity | AI | Security Operations | GRC

PhishNet was developed as part of a hands-on cybersecurity portfolio demonstrating practical security automation, analysis, and Python development.
