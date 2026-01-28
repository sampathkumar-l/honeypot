import requests

API_KEY = "Enter Your API"

def check_ip(ip):
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
    data = response.json()["data"]

    score = data["abuseConfidenceScore"]

    if score > 50:
        level = "Malicious"
    elif score > 20:
        level = "Suspicious"
    else:
        level = "Low"

    return {
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "score": score,
        "level": level
    }
