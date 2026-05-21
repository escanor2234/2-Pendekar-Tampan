import csv
import json
import os
import time
import requests
from datetime import datetime, timedelta
from kafka import KafkaProducer
from config import OTX_API_KEY, KAFKA_SERVERS, KAFKA_TOPIC, POLL_INTERVAL_SEC

# ── CSV CONFIG ────────────────────────────────────────────────────────────────
CSV_FILE = "otx_pulses.csv"

CSV_FIELDNAMES = [
    "pulse_id", "name", "timestamp", "author",
    "tags", "tlp", "adversary", "targeted_countries",
    "malware_families", "attack_ids",
    "indicator_count", "ipv4_count", "ipv6_count", "domain_count",
    "hostname_count", "url_count", "md5_count", "sha256_count",
    "email_count", "cve_count", "tag_count", "references_count",
    "has_adversary", "country_count", "attack_label",
]

def init_csv():
    """Buat file CSV dengan header jika belum ada."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
        print(f"📄 CSV created: {CSV_FILE}")
    else:
        print(f"📄 CSV already exists: {CSV_FILE} — appending rows")

def save_to_csv(features: dict):
    """Append satu baris ke CSV. List di-serialize ke string pipe-separated."""
    row = {}
    for field in CSV_FIELDNAMES:
        val = features.get(field, "")
        if isinstance(val, list):
            val = "|".join(str(v) for v in val)
        row[field] = val

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writerow(row)

# ── KAFKA ─────────────────────────────────────────────────────────────────────
producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVERS,
    value_serializer=lambda x: json.dumps(x).encode("utf-8")
)

BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS  = {"X-OTX-API-KEY": OTX_API_KEY}

# ── FEATURES ──────────────────────────────────────────────────────────────────
def extract_features(pulse):
    indicators = pulse.get("indicators", [])

    ioc_types = {
        "IPv4": 0, "IPv6": 0, "domain": 0, "hostname": 0,
        "URL": 0, "FileHash-MD5": 0, "FileHash-SHA256": 0,
        "email": 0, "CVE": 0,
    }
    for ioc in indicators:
        t = ioc.get("type", "")
        if t in ioc_types:
            ioc_types[t] += 1

    attack_map = {
        "Malware": 1, "Ransomware": 2, "Phishing": 3,
        "DDoS": 4,   "Botnet": 5,     "APT": 6,
        "Exploit": 7, "Trojan": 8,    "Spyware": 9,
    }
    tags         = pulse.get("tags", []) or []
    attack_label = next((attack_map[t] for t in tags if t in attack_map), 0)

    return {
        "pulse_id"          : pulse.get("id", ""),
        "name"              : pulse.get("name", ""),
        "timestamp"         : pulse.get("modified", datetime.utcnow().isoformat()),
        "author"            : pulse.get("author_name", ""),
        "tags"              : tags,
        "tlp"               : pulse.get("TLP", "white"),
        "adversary"         : pulse.get("adversary", "") or "",
        "targeted_countries": pulse.get("targeted_countries", []) or [],
        "malware_families"  : pulse.get("malware_families", []) or [],
        "attack_ids"        : [a.get("display_name", "") for a in (pulse.get("attack_ids") or [])],
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

# ── STATE PERSISTENCE ─────────────────────────────────────────────────────────
STATE_FILE = "producer_state.json"

def load_state():
    """
    Load sent_ids + last_fetch_time from disk.
    This prevents re-sending the same pulses across restarts.
    """
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        sent = set(state.get("sent_ids", []))
        last = state.get("last_fetch_time", None)
        print(f"♻️  Resumed state: {len(sent)} tracked IDs, last fetch: {last}")
        return sent, last
    return set(), None

def save_state(sent_ids, last_fetch_time):
    """Persist state to disk after each successful poll."""
    with open(STATE_FILE, "w") as f:
        json.dump({
            "sent_ids": list(sent_ids),
            "last_fetch_time": last_fetch_time,
        }, f)

# ── MAIN LOOP ─────────────────────────────────────────────────────────────────
def run():
    print("🚀 OTX Producer started — streaming → Kafka + CSV")
    init_csv()

    # Resume from last run (avoids duplicate sends on restart)
    sent_ids, last_fetch_time = load_state()

    while True:
        now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        print(f"\n🔍 Fetching OTX at {now_str}")

        # First run ever: look back 7 days. Otherwise: only since last fetch.
        if last_fetch_time is None:
            since_str = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
            print(f"   (first run — looking back 7 days from {since_str})")
        else:
            since_str = last_fetch_time
            print(f"   (incremental — since last fetch: {since_str})")

        page       = 1
        total_sent = 0

        while True:
            params = {"modified_since": since_str, "limit": 50, "page": page}
            data   = {}

            for attempt in range(3):
                try:
                    resp = requests.get(
                        f"{BASE_URL}/pulses/activity",
                        headers=HEADERS,
                        params=params,
                        timeout=30
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        break
                    elif resp.status_code == 504:
                        print(f"  ⚠️  504 Timeout, retry {attempt+1}/3...")
                        time.sleep(5 * (attempt + 1))
                    else:
                        print(f"  ❌ HTTP {resp.status_code}")
                        break
                except requests.exceptions.RequestException as e:
                    print(f"  ⚠️  Error: {e}, retry {attempt+1}/3...")
                    time.sleep(5)

            pulses   = data.get("results", [])
            has_next = data.get("next") is not None

            if not pulses:
                if page == 1:
                    print("ℹ️  No new pulses since last fetch.")
                break

            for pulse in pulses:
                pid = pulse.get("id")
                if pid in sent_ids:
                    continue

                features = extract_features(pulse)
                producer.send(KAFKA_TOPIC, value=features)
                save_to_csv(features)
                sent_ids.add(pid)
                total_sent += 1

                print(
                    f"  ✅ [{features['attack_label']}] "
                    f"{features['name'][:55]:<55} | "
                    f"ioc: {features['indicator_count']:>4} | "
                    f"tlp: {features['tlp']}"
                )

            producer.flush()

            if has_next:
                page += 1
                time.sleep(1)
            else:
                break

        if total_sent > 0:
            print(
                f"  📤 Total sent: {total_sent} pulses | "
                f"Total tracked: {len(sent_ids)} | "
                f"CSV: {CSV_FILE}"
            )

        # Persist state so next restart resumes correctly
        last_fetch_time = now_str
        save_state(sent_ids, last_fetch_time)

        print(f"⏳ Next poll in {POLL_INTERVAL_SEC}s...")
        time.sleep(POLL_INTERVAL_SEC)

if __name__ == "__main__":
    run()