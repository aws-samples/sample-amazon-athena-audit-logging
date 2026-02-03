"""
AWS Lambda Function: CloudTrail Backfill for Athena Audit Records
==================================================================

This Lambda function runs on a schedule to backfill CloudTrail user identity data
for audit records that initially had null user information.

Trigger: Amazon EventBridge scheduled rule (runs every 10 minutes)
Purpose: Fill in missing CloudTrail data after it becomes available

Why This is Needed:
CloudTrail events can take 5-15 minutes to appear in the LookupEvents API.
When the main enrichment Lambda runs immediately after a query completes,
CloudTrail data may not be available yet. This backfill Lambda runs periodically
to update records with missing user identity information.

How It Works:
1. Scans S3 for audit records modified in the last 15 minutes
2. Identifies records with null user_name (indicating missing CloudTrail data)
3. Looks up CloudTrail events for those queries
4. Updates S3 files with user identity information
5. Caches lookups by query_execution_id to avoid duplicate API calls

Environment Variables Required:
- AUDIT_BUCKET_NAME: S3 bucket name containing audit records

IAM Permissions Required:
- s3:ListBucket
- s3:GetObject
- s3:PutObject
- cloudtrail:LookupEvents
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
"""

import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get configuration from environment variables
AUDIT_BUCKET_NAME = os.environ.get('AUDIT_BUCKET_NAME')

# Initialize AWS clients
s3_client = boto3.client('s3')
cloudtrail_client = boto3.client('cloudtrail')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for backfilling CloudTrail data.
    
    Scans recent audit records and updates those with null CloudTrail data.
    
    Args:
        event: Scheduled event from EventBridge
        context: Lambda context object
        
    Returns:
        Response dictionary with processing statistics
    """
    try:
        logger.info("Starting CloudTrail backfill process")
        
        # Validate configuration
        if not AUDIT_BUCKET_NAME:
            raise ValueError("AUDIT_BUCKET_NAME environment variable is not set")
        
        # Get current date for partition scanning
        now = datetime.utcnow()
        year = now.strftime('%Y')
        month = now.strftime('%m')
        day = now.strftime('%d')
        
        # Scan today's partition for recent files
        prefix = f'athena-audit-logs/year={year}/month={month}/day={day}/'
        logger.info(f"Scanning S3 prefix: {prefix}")
        
        # Find records that need updating
        records_to_update = find_records_needing_backfill(prefix, now)
        logger.info(f"Found {len(records_to_update)} records to update")
        
        # Update records with CloudTrail data
        updated_count, failed_count = update_records_with_cloudtrail(records_to_update)
        
        logger.info(f"Backfill complete: {updated_count} updated, {failed_count} failed/not found")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'CloudTrail backfill completed',
                'records_scanned': len(records_to_update),
                'records_updated': updated_count,
                'records_failed': failed_count
            })
        }
    
    except Exception as e:
        logger.error(f"Error in backfill process: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error in backfill process',
                'error': str(e)
            })
        }


def find_records_needing_backfill(prefix: str, now: datetime) -> list:
    """
    Scan S3 for audit records that need CloudTrail backfill.
    
    Identifies records that:
    1. Were modified in the last 15 minutes
    2. Have null user_name field (indicating missing CloudTrail data)
    
    Args:
        prefix: S3 prefix to scan (today's partition)
        now: Current datetime for age filtering
        
    Returns:
        List of dictionaries with 'key' and 'record' fields
    """
    records_to_update = []
    
    try:
        # List objects in today's partition
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=AUDIT_BUCKET_NAME, Prefix=prefix)
        
        for page in pages:
            if 'Contents' not in page:
                continue
            
            for obj in page['Contents']:
                key = obj['Key']
                last_modified = obj['LastModified']
                
                # Only process files modified in last 15 minutes
                # This prevents re-processing old files on every run
                if (now - last_modified.replace(tzinfo=None)) > timedelta(minutes=15):
                    continue
                
                # Read the audit record
                try:
                    response = s3_client.get_object(Bucket=AUDIT_BUCKET_NAME, Key=key)
                    content = response['Body'].read().decode('utf-8')
                    audit_record = json.loads(content)
                    
                    # Check if CloudTrail data is null
                    # user_name is the key indicator - if it's null, we need to backfill
                    if audit_record.get('user_name') is None:
                        records_to_update.append({
                            'key': key,
                            'record': audit_record
                        })
                        logger.info(f"Found record with null CloudTrail data: {key}")
                
                except Exception as e:
                    logger.warning(f"Error reading {key}: {e}")
                    continue
    
    except ClientError as e:
        logger.error(f"Error listing S3 objects: {e}", exc_info=True)
        return []  # Return empty list instead of raising
    
    return records_to_update


def update_records_with_cloudtrail(records_to_update: list) -> tuple:
    """
    Update audit records with CloudTrail user identity data.
    
    Uses caching to avoid duplicate CloudTrail lookups for the same query_execution_id.
    This is important because multiple audit records might reference the same query.
    
    Args:
        records_to_update: List of records needing CloudTrail data
        
    Returns:
        Tuple of (updated_count, failed_count)
    """
    # Cache CloudTrail lookups by query_execution_id to avoid duplicates
    cloudtrail_cache = {}
    updated_count = 0
    failed_count = 0
    
    for item in records_to_update:
        key = item['key']
        audit_record = item['record']
        
        try:
            # Extract required fields
            query_execution_id = audit_record.get('query_execution_id')
            submission_time_str = audit_record.get('submission_time')
            
            if not query_execution_id or not submission_time_str:
                logger.warning(f"Missing required fields in {key}")
                failed_count += 1
                continue
            
            # Parse submission time
            submission_time = parse_submission_time(submission_time_str)
            
            # Check cache first to avoid duplicate CloudTrail lookups
            if query_execution_id in cloudtrail_cache:
                logger.info(f"Using cached CloudTrail data for query {query_execution_id}")
                cloudtrail_identity = cloudtrail_cache[query_execution_id]
            else:
                # Lookup CloudTrail event
                logger.info(f"Looking up CloudTrail for query {query_execution_id}")
                cloudtrail_identity = lookup_cloudtrail_identity(query_execution_id, submission_time)
                # Cache the result (even if None) to avoid repeated lookups
                cloudtrail_cache[query_execution_id] = cloudtrail_identity
            
            if cloudtrail_identity:
                # Update audit record with CloudTrail data
                audit_record['user_identity_type'] = cloudtrail_identity.get('user_identity_type')
                audit_record['user_arn'] = cloudtrail_identity.get('user_arn')
                audit_record['user_name'] = cloudtrail_identity.get('user_name')
                audit_record['principal_id'] = cloudtrail_identity.get('principal_id')
                audit_record['account_id'] = cloudtrail_identity.get('account_id')
                audit_record['source_ip'] = cloudtrail_identity.get('source_ip')
                audit_record['user_agent'] = cloudtrail_identity.get('user_agent')
                
                # Add backfill timestamp to track when data was filled in
                audit_record['cloudtrail_backfill_timestamp'] = datetime.utcnow().isoformat() + 'Z'
                
                # Write updated record back to S3
                s3_client.put_object(
                    Bucket=AUDIT_BUCKET_NAME,
                    Key=key,
                    Body=json.dumps(audit_record, default=str),
                    ContentType='application/json'
                )
                
                logger.info(f"Updated {key} with CloudTrail data for user {cloudtrail_identity.get('user_name')}")
                updated_count += 1
            else:
                logger.info(f"No CloudTrail data found yet for {query_execution_id}")
                failed_count += 1
        
        except Exception as e:
            logger.error(f"Error updating {key}: {e}", exc_info=True)
            failed_count += 1
    
    return updated_count, failed_count


def parse_submission_time(submission_time_str: str) -> datetime:
    """
    Parse submission time string to datetime object.
    
    Handles various timestamp formats with timezone information.
    
    Args:
        submission_time_str: ISO 8601 timestamp string
        
    Returns:
        datetime object
    """
    # Remove 'Z' suffix and timezone offset
    submission_time_clean = submission_time_str.replace('Z', '')
    
    # Remove timezone offset if present (e.g., +00:00)
    if '+' in submission_time_clean:
        submission_time_clean = submission_time_clean.split('+')[0]
    elif submission_time_clean.count('-') > 2:  # Has timezone offset like -00:00
        # Split from the right to preserve date hyphens
        parts = submission_time_clean.rsplit('-', 1)
        if ':' in parts[-1]:  # Last part looks like timezone
            submission_time_clean = parts[0]
    
    # Parse the cleaned datetime string
    if '.' in submission_time_clean:
        # Has microseconds
        return datetime.strptime(submission_time_clean, '%Y-%m-%dT%H:%M:%S.%f')
    else:
        # No microseconds
        return datetime.strptime(submission_time_clean, '%Y-%m-%dT%H:%M:%S')


def lookup_cloudtrail_identity(query_execution_id: str, submission_time: datetime) -> Optional[Dict[str, Any]]:
    """
    Look up user identity from CloudTrail StartQueryExecution events.
    
    Searches CloudTrail events within ±5 minutes of query submission time
    and matches by queryExecutionId in the response elements.
    
    Args:
        query_execution_id: Athena query execution ID to match
        submission_time: Query submission timestamp
        
    Returns:
        Dictionary with user identity fields, or None if not found
    """
    try:
        # Search CloudTrail events within ±5 minutes
        start_time = submission_time - timedelta(minutes=5)
        end_time = submission_time + timedelta(minutes=5)
        
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'StartQueryExecution'}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        
        # Find matching event by queryExecutionId
        for event in response.get('Events', []):
            cloudtrail_event_str = event.get('CloudTrailEvent')
            if not cloudtrail_event_str:
                continue
                
            cloudtrail_event = json.loads(cloudtrail_event_str)
            if not cloudtrail_event:
                continue
                
            response_elements = cloudtrail_event.get('responseElements')
            if not response_elements:
                continue
                
            event_query_id = response_elements.get('queryExecutionId')
            
            if event_query_id == query_execution_id:
                return extract_user_identity(cloudtrail_event)
        
        return None
        
    except Exception as e:
        logger.warning(f"CloudTrail lookup failed: {str(e)}", exc_info=True)
        return None

def extract_user_identity(cloudtrail_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract user identity fields from CloudTrail event.
    
    Handles different identity types: IAMUser, AssumedRole, Root
    
    Args:
        cloudtrail_event: Parsed CloudTrail event JSON
        
    Returns:
        Dictionary with user identity fields
    """
    if not cloudtrail_event:
        return {
            'user_identity_type': None,
            'user_arn': None,
            'user_name': None,
            'principal_id': None,
            'account_id': None,
            'source_ip': None,
            'user_agent': None,
        }
    
    user_identity = cloudtrail_event.get('userIdentity', {})
    if not user_identity:
        return {
            'user_identity_type': None,
            'user_arn': None,
            'user_name': None,
            'principal_id': None,
            'account_id': None,
            'source_ip': None,
            'user_agent': None,
        }
    
    identity_type = user_identity.get('type')
    
    # Extract username based on identity type
    user_name = None
    if identity_type == 'IAMUser':
        user_name = user_identity.get('userName')
    elif identity_type == 'AssumedRole':
        session_context = user_identity.get('sessionContext', {})
        if session_context:
            session_issuer = session_context.get('sessionIssuer', {})
            if session_issuer:
                user_name = session_issuer.get('userName')
    elif identity_type == 'Root':
        user_name = 'root'
    
    return {
        'user_identity_type': identity_type,
        'user_arn': user_identity.get('arn'),
        'user_name': user_name,
        'principal_id': user_identity.get('principalId'),
        'account_id': user_identity.get('accountId'),
        'source_ip': cloudtrail_event.get('sourceIPAddress'),
        'user_agent': cloudtrail_event.get('userAgent'),
    }