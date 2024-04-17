#!/usr/bin/env python3

import json
import boto3
import os
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# intitialize the DDB client
dynamodb = boto3.resource("dynamodb")

def lambda_handler(event, context):
    table = dynamodb.Table(os.getenv("DOMAINS_TABLE"))
    for record in event["Records"]:
        message = json.loads(record["body"])
        domains = message["domain"]
        url = message["log_url"]
        for domain in domains:
            try:
                # Write the domain and log url to the DDB tabke
                response = table.put_item(Item={
                    "domain": domain,
                    "log_url": url,
                })
                logging.info(f"Wrote {domain} to DynamoDB")
            except Exception as e:
                logger.error(f"Error writing {domain} to DDB: {str(e)}")
                continue
    return {
        'statusCode': 200,
        'body': json.dumps("Processed SQS messages successfully")
    }