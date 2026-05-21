from pyspark.sql import SparkSession
from pyspark.sql.functions import from_json, col, size
from pyspark.sql.types import *
from config import KAFKA_SERVERS, KAFKA_TOPIC

schema = StructType([
    StructField("pulse_id",           StringType()),
    StructField("name",               StringType()),
    StructField("timestamp",          StringType()),
    StructField("author",             StringType()),
    StructField("tags",               ArrayType(StringType())),
    StructField("tlp",                StringType()),
    StructField("adversary",          StringType()),
    StructField("targeted_countries", ArrayType(StringType())),
    StructField("malware_families",   ArrayType(StringType())),
    StructField("attack_ids",         ArrayType(StringType())),
    StructField("indicator_count",    IntegerType()),
    StructField("ipv4_count",         IntegerType()),
    StructField("ipv6_count",         IntegerType()),
    StructField("domain_count",       IntegerType()),
    StructField("hostname_count",     IntegerType()),
    StructField("url_count",          IntegerType()),
    StructField("md5_count",          IntegerType()),
    StructField("sha256_count",       IntegerType()),
    StructField("email_count",        IntegerType()),
    StructField("cve_count",          IntegerType()),
    StructField("tag_count",          IntegerType()),
    StructField("references_count",   IntegerType()),
    StructField("has_adversary",      IntegerType()),
    StructField("country_count",      IntegerType()),
    StructField("attack_label",       IntegerType()),
])

spark = SparkSession.builder \
    .appName("OTXCyberStream") \
    .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.0") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

raw = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", KAFKA_SERVERS) \
    .option("subscribe", KAFKA_TOPIC) \
    .option("startingOffsets", "earliest") \
    .load()

parsed = raw \
    .select(from_json(col("value").cast("string"), schema).alias("d")) \
    .select("d.*")

# Stream 1: Detail tiap pulse
query_detail = parsed.select(
    "timestamp", "name", "tlp", "adversary",
    "indicator_count", "ipv4_count", "domain_count",
    "url_count", "cve_count", "country_count",
    "attack_label", "tags"
).writeStream \
    .outputMode("append") \
    .format("console") \
    .option("truncate", False) \
    .option("numRows", 20) \
    .trigger(processingTime="30 seconds") \
    .queryName("detail") \
    .start()

# Stream 2: Summary per attack label
summary = parsed.groupBy("attack_label", "tlp").count().orderBy("count", ascending=False)

query_summary = summary.writeStream \
    .outputMode("complete") \
    .format("console") \
    .option("truncate", False) \
    .trigger(processingTime="30 seconds") \
    .queryName("summary") \
    .start()

query_detail.awaitTermination()