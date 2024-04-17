#!/usr/bin/env python3

import requests
import os
import json
import boto3
import logging
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

def lambda_handler(event, context):
    # Table names
    ct_log_table_name = os.getenv('CT_LOG_TABLE_NAME')
    state_table_name = os.getenv('STATE_TABLE_NAME')

    # Initialize DynamoDB clients
    dynamodb = boto3.resource('dynamodb')
    ct_log_table = dynamodb.Table(ct_log_table_name)
    state_table = dynamodb.Table(state_table_name)

    # Scan the CT Log URLs table
    try:
        response = ct_log_table.scan()
    except ClientError as e:
        logger.error("Error fetching CT log URLs from DynamoDB:", e.response['Error']['Message'])
        return {"statusCode": 500, "body": json.dumps("Error reading CT Log Table")}

    # Initialize state table records
    for item in response["Items"]:
        ct_log_url = item["url"]
        try:
            sth_response = requests.get(f"{ct_log_url}ct/v1/get-sth", timeout=5)
            if sth_response.status_code == 200:
                sth_data = sth_response.json()
                tree_size = sth_data.get('tree_size', 0)
                try:
                    state_table.put_item(Item={
                        'url': ct_log_url,
                        'tree_size': tree_size, 
                        'current_position': 0,
                        'retry_count': 0
                    })
                    logger.info(f"Initialized state for {ct_log_url}")
                except ClientError as e:
                    logger.error(f"Error initializing state for {ct_log_url}: {e.response['Error']['Message']}")
            else:
                pass
        except Exception as e:
            logger.error(f"Error fetching STH for {ct_log_url}: {e}")
            continue

    return {"statusCode": 200, "body": json.dumps("State table updated successfully")}