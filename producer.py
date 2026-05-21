import json
import time
import requests
from datetime import datetime, timedelta
from kafka import KafkaProducer
from config import OTX_API_KEY, KAFKA_SERVERS, KAFKA_TOPIC, POLL_INTERVAL_SEC

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda x: json.dumps(x).encode("utf-8")
)

sent_ids   = set()
BASE_URL   = "https://otx.alienvault.com/api/v1"
HEADERS    = {"X-OTX-API-KEY": OTX_API_KEY}

def fetch_pulses(since_days=1, page=1):
    since  = (datetime.utcnow() - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S")
    params = {"modified_since": since, "limit": 50, "page": page}

    for attempt in range(3):
        try:
            resp = requests.get(
                f"{BASE_URL}/pulses/activity",
                headers=HEADERS,
                params=params,
                timeout=30
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 504:
                print(f"  ⚠️  504 Timeout, retry {attempt+1}/3...")
                time.sleep(5 * (attempt + 1))
            else:
                print(f"  ❌ HTTP {resp.status_code}")
                return {}
        except requests.exceptions.RequestException as e:
            print(f"  ⚠️  Error: {e}, retry {attempt+1}/3...")
            time.sleep(5)
    return {}

def fetch_indicators(pulse_id):
    """Ambil detail indicators dari setiap pulse"""
    try:
        resp = requests.get(
            f"{BASE_URL}/pulses/{pulse_id}/indicators",
            headers=HEADERS,
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json().get("results", [])
    except:
        pass
    return []

def extract_features(pulse):
    indicators = pulse.get("indicators", [])

    # Hitung per tipe IoC
    ioc_types = {"IPv4": 0, "IPv6": 0, "domain": 0, "hostname": 0,
                 "URL": 0, "FileHash-MD5": 0, "FileHash-SHA256": 0,
                 "email": 0, "CVE": 0}
    for ioc in indicators:
        t = ioc.get("type", "")
        if t in ioc_types:
            ioc_types[t] += 1

    # Mapping attack tag ke kategori
    attack_map = {
        "Malware": 1, "Ransomware": 2, "Phishing": 3,
        "DDoS": 4,  "Botnet": 5,     "APT": 6,
        "Exploit": 7, "Trojan": 8,   "Spyware": 9,
    }
    tags         = pulse.get("tags", []) or []
    attack_label = next((attack_map[t] for t in tags if t in attack_map), 0)

    return {
        # Identifikasi
        "pulse_id"          : pulse.get("id", ""),
        "name"              : pulse.get("name", ""),
        "timestamp"         : pulse.get("modified", datetime.utcnow().isoformat()),
        "author"            : pulse.get("author_name", ""),

        # Konteks ancaman
        "tags"              : tags,
        "tlp"               : pulse.get("TLP", "white"),
        "adversary"         : pulse.get("adversary", "") or "",
        "targeted_countries": pulse.get("targeted_countries", []) or [],
        "malware_families"  : pulse.get("malware_families", []) or [],
        "attack_ids"        : [a.get("display_name", "") for a in (pulse.get("attack_ids") or [])],

        # Fitur numerik (untuk ML nanti)
        "indicator_count"   : len(indicators),
        "ipv4_count"        : ioc_types["IPv4"],
        "ipv6_count"        : ioc_types["IPv6"],
        "domain_count"      : ioc_types["domain"],
        "hostname_count"    : ioc_types["hostname"],
        "url_count"         : ioc_types["URL"],
        "md5_count"         : ioc_types["FileHash-MD5"],
        "sha256_count"      : ioc_types["FileHash-SHA256"],
        "email_count"       : ioc_types["email"],
        "cve_count"         : ioc_types["CVE"],
        "tag_count"         : len(tags),
        "references_count"  : len(pulse.get("references", []) or []),
        "has_adversary"     : 1 if pulse.get("adversary") else 0,
        "country_count"     : len(pulse.get("targeted_countries", []) or []),
        "attack_label"      : attack_label,
    }

def run():
    print("🚀 OTX Producer started — streaming → Kafka")
    first_run = True

    while True:
        print(f"\n🔍 Fetching OTX at {datetime.utcnow().isoformat()}")

        since_days = 7 if first_run else 1
        page       = 1
        total_sent = 0

        while True:
            data    = fetch_pulses(since_days=since_days, page=page)
            pulses  = data.get("results", [])
            has_next= data.get("next") is not None

            if not pulses:
                if page == 1:
                    print("ℹ️  No pulses found.")
                break

            for pulse in pulses:
                pid = pulse.get("id")
                if pid in sent_ids:
                    continue

                features = extract_features(pulse)
                producer.send(KAFKA_TOPIC, value=features)
                sent_ids.add(pid)
                total_sent += 1

                print(f"  ✅ [{features['attack_label']}] {features['name'][:55]:<55} | ioc: {features['indicator_count']:>4} | tlp: {features['tlp']}")

            producer.flush()

            if has_next:
                page += 1
                time.sleep(1)  # jangan terlalu agresif hit API
            else:
                break

        if total_sent > 0:
            print(f"  📤 Total sent: {total_sent} pulses | Total tracked: {len(sent_ids)}")
        
        first_run = False
        print(f"⏳ Next poll in {POLL_INTERVAL_SEC}s...")
        time.sleep(POLL_INTERVAL_SEC)

if __name__ == "__main__":
    run()