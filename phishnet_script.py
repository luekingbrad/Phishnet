import os
import csv
import math
import whois
import datetime
import contextlib
import io
from urllib.parse import urlparse

# List of suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "account",
    "banking",
    "confirm",
    "login",
    "password",
    "secure",
    "update",
    "verify"
]


def check_suspicious_keywords(url):
    """
    Check if the URL contains suspicious phishing keywords.
    Returns the number of suspicious keywords found.
    """
    count = 0
    for keyword in SUSPICIOUS_KEYWORDS:
       if keyword in url.lower():
           count += 1
    return count


def calculate_entropy(string):
    """
    Calculate Shannon entropy of a string to detect randomness.
    """
    probabilities = [
       float(string.count(char)) / len(string)
       for char in dict.fromkeys(string)
    ]

    entropy = -sum(
       p * math.log(p, 2)
       for p in probabilities
    )

    return entropy


def get_domain_age(domain):
    """
    Retrieve domain age using WHOIS.
    Returns -1 if unavailable.
    """
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            w = whois.whois(domain)
        
        creation_date = w.creation_date

        if isinstance(creation_date, list):
           creation_date = creation_date[0]

        if creation_date is None:
           return -1

        today = datetime.datetime.now()
        age = (today - creation_date).days

        return age

    except Exception:
       print(f"WHOIS lookup unavailable: {domain}")
       return -1

def analyze_url(url):
    """
    Analyze a single URL and assign a phishing risk score.
    """
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]

    suspicious_count = check_suspicious_keywords(url)
    entropy = calculate_entropy(url)
    length = len(url)
    domain_age = get_domain_age(domain)

    score = 0

   # Suspicious keywords
    if suspicious_count > 0:
       score += suspicious_count * 2

   # Random-looking URL
    if entropy > 4.0:
       score += 2

   # Long URLs can be suspicious
    if length > 75:
       score += 1

   # Recently created domains
    if domain_age != -1 and domain_age < 100:
       score += 2

   # Unknown domain age
    if domain_age == -1:
       score += 1

    if score >= 6:
       risk = "High"
    elif score >= 3:
       risk = "Medium"
    else:
       risk = "Low"


    return {
        "url": url,
        "suspicious_keywords": suspicious_count,
        "entropy": round(entropy, 2),
        "length": length,
        "domain_age_days": domain_age,
        "score": score,
        "risk": risk
    }


def analyze_urls_from_file(input_file, output_csv):
    """
    Read URLs from a text file, analyze each one,
    and write the results to a CSV report.
    """
    with open(input_file, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    results = []

    total_urls = len(urls)

    for index, url in enumerate(urls, start=1):

        print(f"[{index}/{total_urls}] Analyzing: {url}")

        result = analyze_url(url)

        if result is not None:
            results.append(result)

    with open(output_csv, "w", newline="") as csvfile:
        fieldnames = [
            "url",
            "suspicious_keywords",
            "entropy",
            "length",
            "domain_age_days",
            "score",
            "risk"
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for row in results:
            writer.writerow(row)

    # ----------------------------
    # Build Summary Statistics
    # ----------------------------

    high = sum(1 for r in results if r["risk"] == "High")
    medium = sum(1 for r in results if r["risk"] == "Medium")
    low = sum(1 for r in results if r["risk"] == "Low")

    highest_risk = sorted(
        results,
        key=lambda x: x["score"],
        reverse=True
    )

    print("\n" + "=" * 50)
    print("           PHISHNET SUMMARY REPORT")
    print("=" * 50)

    print(f"\nURLs Analyzed : {len(results)}")

    print("\nRisk Distribution")
    print("-" * 17)
    print(f"High   : {high}")
    print(f"Medium : {medium}")
    print(f"Low    : {low}")

    print("\nHighest Risk URLs")
    print("-" * 17)

    for item in highest_risk[:5]:
        print(
            f"Score: {item['score']:>2} | "
            f"{item['risk']:<6} | "
            f"{item['url']}"
        )

    print("\nCSV Report:")
    print(output_csv)

    print("\nAnalysis Complete!")
    print("=" * 50)

if __name__ == "__main__":

    script_dir = os.path.dirname(os.path.abspath(__file__))

    input_file = os.path.join(script_dir, "sample_urls.txt")
    output_file = os.path.join(script_dir, "analysis_results.csv")

    analyze_urls_from_file(input_file, output_file)
