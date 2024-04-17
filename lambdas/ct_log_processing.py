#!/usr/bin/env python3

import json
import os
import logging
import base64
import requests
from OpenSSL import crypto
from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, GreedyBytes, GreedyRange
import boto3

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
sqs = boto3.client('sqs')

# DynamoDB Table Name
STATE_TABLE = os.getenv("STATE_TABLE")
DOMAIN_TABLE = os.getenv("DOMAINS_TABLE")

# SQS Queue
QUEUE_URL=os.getenv('SQS_QUEUE_URL')

# S3 Bucket for problematic logs
S3_BUCKET = os.getenv("S3_BUCKET")

# SHARDING
LAMBDA_SHARD_NUMBER = int(os.getenv("LAMBDA_SHARD_NUMBER"))

# Define structures for parsing the Merkle tree headers and certificates
MerkleTreeHeader = Struct(
    "Version" / Byte,
    "MerkleLeafType" / Byte,
    "Timestamp" / Int64ub,
    "LogEntryType" / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry" / GreedyBytes,
)
Certificate = Struct("Length" / Int24ub, "CertData" / Bytes(lambda ctx: ctx.Length))
CertificateChain = Struct("ChainLength" / Int24ub, "Chain" / GreedyRange(Certificate))

# Amazon domain filtering logic
def endswith_tuple():
    endswith = []
    tld_country_list = (
        "af",
        "ax",
        "al",
        "dz",
        "as",
        "ad",
        "ao",
        "ai",
        "aq",
        "ag",
        "ar",
        "am",
        "aw",
        "ac",
        "au",
        "at",
        "az",
        "bs",
        "bh",
        "bd",
        "bb",
        "eus",
        "by",
        "be",
        "bz",
        "bj",
        "bm",
        "bt",
        "bo",
        "bq",
        "ba",
        "bw",
        "bv",
        "br",
        "io",
        "vg",
        "bn",
        "bg",
        "bf",
        "mm",
        "bi",
        "kh ",
        "cm",
        "ca",
        "cv",
        "cat",
        "ky",
        "cf",
        "td",
        "cl",
        "cn",
        "cx",
        "cc",
        "co",
        "km",
        "cd",
        "cg",
        "ck",
        "cr",
        "ci",
        "hr",
        "cu",
        "cw",
        "cy",
        "cz",
        "dk",
        "dj",
        "dm",
        "do",
        "tl",
        "ec",
        "eg",
        "sv",
        "gq",
        "er",
        "ee ",
        "et",
        "eu",
        "fk",
        "fo",
        "fm",
        "fj",
        "fi",
        "fr",
        "gf",
        "pf",
        "tf",
        "ga",
        "gal",
        "gm",
        "ps ",
        "ge",
        "de ",
        "gh",
        "gi",
        "gr",
        "gl",
        "gd",
        "gp",
        "gu",
        "gt",
        "gg",
        "gn",
        "gw",
        "gy",
        "ht",
        "hm",
        "hn",
        "hk",
        "hu",
        "is ",
        "in",
        "id",
        "ir",
        "iq",
        "ie",
        "im",
        "il",
        "it",
        "jm",
        "jp",
        "je",
        "jo",
        "kz",
        "ke",
        "ki",
        "kw",
        "kg",
        "la",
        "lv",
        "lb",
        "ls",
        "lr",
        "ly",
        "li",
        "lt",
        "lu",
        "mo ",
        "mk ",
        "mg",
        "mw",
        "my",
        "mv",
        "ml",
        "mt",
        "mh",
        "mq",
        "mr",
        "mu",
        "yt",
        "mx",
        "md",
        "mc",
        "mn",
        "me",
        "ms",
        "ma ",
        "mz",
        "mm",
        "na",
        "nr",
        "np",
        "nl",
        "nc",
        "nz",
        "ni",
        "ne",
        "ng",
        "nu",
        "nf",
        "nc.tr",
        "kp ",
        "mk ",
        "mp",
        "no",
        "om",
        "pk",
        "pw ",
        "ps",
        "pa",
        "pg",
        "py",
        "pe",
        "ph",
        "pn",
        "pl",
        "pt",
        "pr",
        "qa",
        "ro",
        "ru",
        "rw",
        "re",
        "bq",
        "an ",
        "bl",
        "gp",
        "fr ",
        "sh",
        "kn",
        "lc",
        "mf",
        "gp",
        "fr ",
        "pm",
        "vc",
        "ws ",
        "sm",
        "st",
        "sa",
        "sn",
        "rs ",
        "sc",
        "sl",
        "sg",
        "bq",
        "an",
        ".nl ",
        "sx",
        "an ",
        "sk",
        "si",
        "sb ",
        "so",
        "so",
        "za ",
        "gs",
        "kr",
        "ss",
        "es ",
        "lk",
        "sd",
        "sr",
        "sj",
        "sz",
        "se",
        "ch",
        "sy",
        "tw",
        "tj",
        "tz",
        "th",
        "tg",
        "tk",
        "to",
        "tt",
        "tn",
        "tr",
        "tm",
        "tc",
        "tv",
        "ug",
        "ua ",
        "ae",
        "uk",
        "us",
        "vi",
        "uy",
        "uz",
        "vu",
        "va",
        "ve",
        "vn",
        "wf",
        "eh ",
        "ye",
        "zm",
        "zw",
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
    )
    # Domains you are looking for
    base_domains = ["example.com"]
    for base_domain in base_domains:
        for tld in tld_country_list:
            endswith.append(f".{base_domain}.{tld}")
    return tuple(endswith)


def dns_filter(dns_name):
    endswith = endswith_tuple()
    return dns_name.endswith(endswith)


def get_subject_alt_name(cert):
    san_extension = None
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            san_extension = ext
            break
    if san_extension:
        san_list = str(san_extension).split(", ")
        dns_names = [name.partition(":")[2] for name in san_list if name.startswith("DNS")]
        return dns_names
    return []


def process_log_entry(entry, url, current_position):
    """
    Process each log entry and extract filtered DNS names.
    """
    try:
        leaf_input = base64.b64decode(entry['leaf_input'])
        mth = MerkleTreeHeader.parse(leaf_input)
        if mth.LogEntryType == "X509LogEntryType":
            cert_data = Certificate.parse(mth.Entry).CertData
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
            dns_names = get_subject_alt_name(cert)
            filtered_dns_names = list(filter(dns_filter, dns_names))
            if filtered_dns_names:
                # Write to SQS queue for further processing
                sqs.send_message(
                    QueueUrl=QUEUE_URL,
                    MessageBody=json.dumps({
                        'domain': filtered_dns_names,
                        'log_url': f"{url}ct/v1/get-entries?start={current_position}&end={current_position}",
                    })
                )
                logger.info(f"Successfully processed: {filtered_dns_names} from {url}")
            else:
                logger.info("No Amazon Domains found yet")
    except Exception as e:
        logger.error(f"{str(e)}: Unable to process {url}")
        pass


def fetch_and_process_ct_log_entries(ct_log_url, start, end):
    entries_url = f"{ct_log_url}ct/v1/get-entries"
    params = {'start': start, 'end': end}
    throttled = False
    try:
        response = requests.get(entries_url, params=params, timeout=5)
        if response.status_code == 200:
            log_entries = response.json()['entries']
            for entry in log_entries:
                process_log_entry(entry, ct_log_url, start)
        else:
            throttled = True
            return throttled
    except Exception as e:
        # Log to S3 Bucket for problematic logs
        logger.error(f"str{e}: Unable to process {ct_log_url}ct/v1/get-entries?start={start}&end={end}")
        return throttled

def lambda_handler(event, context):
    # Fetch CTL URLs from DynamoDB
    state_table = dynamodb.Table(STATE_TABLE)
    response = state_table.scan()
    ct_log_urls = [item['url'] for item in response['Items']]
    throttled = False
    for ct_log_url in ct_log_urls:
        logger.info(f"Searching {ct_log_url}")
        # Fetch state from DynamoDB
        state = state_table.get_item(Key={'url': ct_log_url}).get('Item', {})
        lambda_start_key = f"lambda_{LAMBDA_SHARD_NUMBER}_start"
        lambda_end_key = f"lambda_{LAMBDA_SHARD_NUMBER}_end"
        start_position = int(state.get(lambda_start_key, 0))
        end_position = int(state.get(lambda_end_key, 0))
        if start_position >= end_position:
            continue
        last_successful_position = start_position
        update_batch_counter = 0
        for current_position in range(start_position, end_position):
            try:
                throttled = fetch_and_process_ct_log_entries(ct_log_url, current_position, current_position)
                if throttled == True:
                    s3.put_object(Bucket=S3_BUCKET, Key=f'{ct_log_url}.json', Body=json.dumps({'url': f"{ct_log_url}ct/v1/get-entries?start={current_position}&end={current_position}", 'retry_exceeded': True}))
                    state_table.update_item(
                        Key={'url': ct_log_url},
                        UpdateExpression="SET " + lambda_start_key + " = :pos",
                        ExpressionAttributeValues={':pos': last_successful_position,}
                    )
                    break
                last_successful_position = current_position
                update_batch_counter += 1
                if update_batch_counter >= 100:
                    state_table.update_item(
                        Key={'url': ct_log_url},
                        UpdateExpression="SET " + lambda_start_key + " = :pos",
                        ExpressionAttributeValues={':pos': last_successful_position,}
                    )
                    update_batch_counter = 0
            except Exception as e:
                logger.error(f"Error at {ct_log_url} position {current_position}: {str(e)}")
                continue
        state_table.update_item(
                        Key={'url': ct_log_url},
                        UpdateExpression="SET " + lambda_start_key + " = :pos",
                        ExpressionAttributeValues={':pos': last_successful_position,}
                    )
        