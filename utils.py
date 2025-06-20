import requests
from config import BASE_URL, HEADERS


def check_hash(file_hash):
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        total = sum(stats.values())

        print(f"\n🔍 [HASH] {file_hash}")
        print(f"🦠 Malicious: {malicious_count} / {total}")
        print("🚨 Detected By:")
        for engine, result in attributes.get('last_analysis_results', {}).items():
            if result.get('category') == "malicious":
                print(f" - {engine}: {result.get('result', 'N/A')}")
    else:
        print(f"[!] Error: Unable to fetch data for hash {file_hash}. Status: {response.status_code}")


def check_ip(ip):
    url = f"{BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        try:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())

            print(f"\n🌐 [IP] {ip}")
            print(f"🦠 Malicious: {malicious} / {total}")
            print(f"📍 Country: {attributes.get('country', 'N/A')}")
            print(f"🏢 ISP: {attributes.get('asn_owner', 'N/A')}")
        except Exception as e:
            print("❌ Failed to parse JSON response:", e)
    else:
        print(f"[!] Failed to check IP: {ip}. Status: {response.status_code}")
