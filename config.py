import os

OTX_API_KEY       = os.getenv("OTX_API_KEY", "YOUR_OTX_API_KEY")
KAFKA_SERVERS     = os.getenv("KAFKA_SERVERS", "localhost:9092")
KAFKA_TOPIC       = "otx-threat-feed"
POLL_INTERVAL_SEC = 60  # polling tiap 1 menit