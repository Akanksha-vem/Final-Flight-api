import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# Initialize the DynamoDB resource
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # Replace 'your-region' with your AWS region
table = dynamodb.Table('APILog1')  # Replace 'APILogTable' with your DynamoDB table name

def put_item_api_log(log_item):
    """
    Store a log entry in DynamoDB.

    :param log_item: Dictionary containing the log entry data.
    """
    try:
        table.put_item(Item=log_item)
        print(f"Successfully stored log: {log_item}")
    except ClientError as e:
        print(f"Error storing log in DynamoDB: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"Unexpected error storing log in DynamoDB: {e}")
