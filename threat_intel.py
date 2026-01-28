import requests

API_KEY = "e02690943eb74bbc1f8886acb3c872ce5bac9cc5b878b057fa0ae426ac982bb46b617c490914fa5b"

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
