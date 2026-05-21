# test_otx.py — jalankan ini dulu untuk cek koneksi
import requests
from config import OTX_API_KEY

headers = {"X-OTX-API-KEY": OTX_API_KEY}

# Cek user info
r = requests.get("https://otx.alienvault.com/api/v1/user/me", headers=headers)
print("User:", r.json().get("username"))

# Cek pulse terbaru tanpa filter subscribed
r2 = requests.get("https://otx.alienvault.com/api/v1/pulses/activity", headers=headers, params={"limit": 5})
print("Activity pulses:", len(r2.json().get("results", [])))
for p in r2.json().get("results", []):
    print(f"  - {p['name']}")