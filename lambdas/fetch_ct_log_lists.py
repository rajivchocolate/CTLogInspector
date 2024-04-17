#!/usr/bin/env python3

import json
import os
import boto3
import requests

def fetch_ct_log_data(url):
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch CT logs: HTTP Status Code {response.status_code}")
    return response.json()

def handler(event, context):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.getenv('TABLE_NAME'))
    ct_log_list_url = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
    try:
        log_list_json = fetch_ct_log_data(ct_log_list_url)
        for operator in log_list_json.get("operators", []):
            for log in operator.get("logs", []):
                log_url = log.get("url")
                description = log.get("description")
                if log_url:
                    # Using the URL as the primary key and including the description
                    table.put_item(Item={'url': log_url, 'description': description})
        return {"statusCode": 200, "body": json.dumps("CT logs processed successfully.")}
    except Exception as e:
        print(f"Error: {e}")
        return {"statusCode": 500, "body": json.dumps("Error processing CT logs.")}