import requests
import re
from urllib.parse import urlparse

API_KEY = "fd8f0a4544622ca63fa0565ff510d70e3299061a9c674da41e7c822629c6c8b533f7857a8549bb91"


def is_url(value):
    pattern = r"^(http|https)://"
    return re.match(pattern, value)


def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc


def analyze_ip(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    data = response.json()

    if "data" not in data:
        return {
            "ip": ip,
            "score": 0,
            "threat_level": "UNKNOWN",
            "country": "Unknown"
        }

    score = data["data"]["abuseConfidenceScore"]
    country = data["data"]["countryCode"]

    if score > 70:
        level = "HIGH"
    elif score > 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "ip": ip,
        "score": score,
        "threat_level": level,
        "country": country
    }


def analyze_target(value):

    # إذا كان URL
    if is_url(value):

        domain = extract_domain(value)

        suspicious_words = ["login", "verify", "secure", "bank", "account"]

        score = 0

        for word in suspicious_words:
            if word in value.lower():
                score += 30

        if len(value) > 75:
            score += 20

        if score > 70:
            level = "HIGH"
        elif score > 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "ip": domain,
            "score": score,
            "threat_level": level,
            "country": "Unknown"
        }

    # إذا كان IP
    else:
        return analyze_ip(value)