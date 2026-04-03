import csv
import math
import re
import whois
import datetime
from urllib.parse import urlparse

# List of suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = ["account", "banking", "confirm", "login", "password", "secure", "update", "verify"]

def check_suspicious_keywords(url):
   """Check if the URL contains suspicious phishing keywords"""
   count = 0
   for keyword in SUSPICIOUS_KEYWORDS:
      if keyword in url.lower():
         count += 1
   return count

def calculate_entropy(string):
   """Calculate Shannon entropy of a string to detect randomness."""
   prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
   entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
   return entropy

def get_domain_age(domain):
   """Get domain age in days."""
   try:
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
      return -1

def analyze_url(url):
   parsed = urlparse(url)
   domain = parsed.netloc or parsed.path.split('/')[0]
   suspicious_count = check_suspicious_keywords(url)
   entropy = calculate_entropy(url)
   length = len(url)
   domain_age = get_domain_age(domain)

   # Scoring (custom logic - higher = more suspicious)
   score = 0
   if suspicious_count > 0:
      score += suspicious_count * 2
   if entropy > 4.0:
      score += 2
   if length > 75:
      score += 1
   if domain_age != -1 and domain_age < 100:
      score += 2
   if domain_age == -1:
      score += 1


   return {
       "url": url,
       "suspicious_keywords": suspicious_count,
       "entropy": round(entropy, 2),
       "length": length,
       "domain_age_days": domain_age,
       "score": score
   }


def analyze_urls_from_file(input_file, output_csv):
   with open(input_file, 'r') as f:
       urls = [line.strip() for line in f.readlines() if line.strip()]

   results = []
   for url in urls:
      result = analyze_url(url)
      results.append(result)

   with open(output_csv, 'w', newline='') as csvfile:
      fieldnames = ["domain_age_days", "entropy", "length", "score", "suspicious_keywords", "url"]
      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
      writer.writeheader()
      for row in results:
         writer.writerow(row)

   print(f"Analysis complete. Results written to {output_csv}")

if __name__ == '__main__':
   input_file = 'sample_urls.txt'
   output_file = 'phishnet_report.csv'
   analyze_urls_from_file(input_file, output_file)
