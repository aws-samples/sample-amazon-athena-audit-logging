"""
AWS Lambda Function: Athena Query Audit Enrichment
===================================================

This Lambda function enriches Athena query events with detailed metadata and user identity information.

Trigger: Amazon EventBridge rule on Athena query state changes (SUCCEEDED, FAILED, CANCELLED)
Output: Enriched audit records stored in S3 with date-based partitioning

Architecture:
1. EventBridge triggers Lambda when Athena query reaches terminal state
2. Lambda fetches detailed query metadata from Athena API
3. Lambda looks up user identity from CloudTrail API
4. Lambda combines all data into enriched audit record
5. Lambda writes record to S3 with partitioned path (year/month/day)

Environment Variables Required:
- AUDIT_BUCKET_NAME: S3 bucket name for storing audit records
- CLOUDTRAIL_LOOKUP_ENABLED: Enable/disable CloudTrail lookup (default: true)

Optional Filtering Environment Variables:
- AUDIT_WORKGROUPS_FILTER: Comma-separated list of workgroups to audit
- AUDIT_DATABASES_FILTER: Comma-separated list of databases to audit
- AUDIT_TABLES_FILTER: Comma-separated list of table names to audit
- AUDIT_FILTER_LOGIC: Filter logic - "OR" (default) or "AND"
  * OR: Audit if query matches ANY filter (broad filtering)
  * AND: Audit if query matches ALL configured filters (precise filtering)

IAM Permissions Required:
- athena:GetQueryExecution
- cloudtrail:LookupEvents
- s3:PutObject
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
"""

import json
import os
import logging
import uuid
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get configuration from environment variables
AUDIT_BUCKET_NAME = os.environ.get('AUDIT_BUCKET_NAME')
CLOUDTRAIL_LOOKUP_ENABLED = os.environ.get('CLOUDTRAIL_LOOKUP_ENABLED', 'true').lower() == 'true'

# Optional: Filter by specific tables (comma-separated list)
# Example: "employees,customers,transactions"
# Leave empty to audit all tables
AUDIT_TABLES_FILTER = os.environ.get('AUDIT_TABLES_FILTER', '').strip()

# Optional: Filter by specific databases (comma-separated list)
# Example: "production_db,sensitive_db"
# Leave empty to audit all databases
AUDIT_DATABASES_FILTER = os.environ.get('AUDIT_DATABASES_FILTER', '').strip()

# Optional: Filter by specific workgroups (comma-separated list)
# Example: "production-workgroup,sensitive-workgroup"
# Leave empty to audit all workgroups
AUDIT_WORKGROUPS_FILTER = os.environ.get('AUDIT_WORKGROUPS_FILTER', '').strip()

# Optional: Filter logic (OR or AND)
# OR: Audit if ANY filter matches (default)
# AND: Audit if ALL filters match (more restrictive)
AUDIT_FILTER_LOGIC = os.environ.get('AUDIT_FILTER_LOGIC', 'OR').upper()

# Initialize AWS clients
athena_client = boto3.client('athena')
cloudtrail_client = boto3.client('cloudtrail')
s3_client = boto3.client('s3')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for processing Athena query audit events.
    
    This function orchestrates the entire enrichment process:
    1. Parse EventBridge event
    2. Fetch query details from Athena
    3. Look up user identity from CloudTrail
    4. Build enriched audit record
    5. Write to S3 with partitioned path
    
    Args:
        event: EventBridge event containing Athena query state change
        context: Lambda context object
        
    Returns:
        Response dictionary with status and audit record details
    """
    query_execution_id = None
    
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Validate configuration
        if not AUDIT_BUCKET_NAME:
            raise ValueError("AUDIT_BUCKET_NAME environment variable is not set")
        
        # Step 1: Parse EventBridge event
        query_execution_id = event['detail']['queryExecutionId']
        current_state = event['detail']['currentState']
        
        logger.info(f"Processing query {query_execution_id} with state {current_state}")
        
        # Step 2: Fetch query execution details from Athena API
        logger.info("Fetching query execution details from Athena")
        query_execution = get_query_execution_with_retry(query_execution_id)
        
        # Step 3: Extract metadata from Athena response
        logger.info("Extracting metadata from Athena response")
        athena_metadata = extract_athena_metadata(query_execution)
        
        # Step 3.5: Apply filters if configured
        if not should_audit_query(athena_metadata):
            logger.info(f"Query {query_execution_id} filtered out based on configuration. Skipping audit.")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Query filtered - not audited',
                    'query_execution_id': query_execution_id,
                    'reason': 'Does not match audit filters'
                })
            }
        
        # Step 4: Look up user identity from CloudTrail (if enabled)
        cloudtrail_identity = None
        if CLOUDTRAIL_LOOKUP_ENABLED:
            logger.info("Looking up user identity from CloudTrail")
            submission_time = query_execution['QueryExecution']['Status']['SubmissionDateTime']
            cloudtrail_identity = lookup_cloudtrail_identity(query_execution_id, submission_time)
            
            if cloudtrail_identity:
                logger.info(f"Found CloudTrail identity for user: {cloudtrail_identity.get('user_name')}")
            else:
                logger.warning(f"No CloudTrail identity found for query {query_execution_id}")
        
        # Step 5: Build enriched audit record
        logger.info("Building enriched audit record")
        audit_record = build_audit_record(athena_metadata, cloudtrail_identity, event)
        
        # Step 6: Write audit record to S3
        logger.info(f"Writing audit record to S3 bucket: {AUDIT_BUCKET_NAME}")
        s3_key = write_to_s3(AUDIT_BUCKET_NAME, audit_record)
        
        logger.info(f"Successfully wrote audit record to s3://{AUDIT_BUCKET_NAME}/{s3_key}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Audit record created successfully',
                'query_execution_id': query_execution_id,
                'state': current_state,
                'audit_id': audit_record['audit_id'],
                's3_key': s3_key
            })
        }
        
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error processing audit event',
                'query_execution_id': query_execution_id,
                'error': str(e)
            })
        }

def get_query_execution_with_retry(query_execution_id: str, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetch query execution details from Athena API with exponential backoff retry.
    
    Retries on throttling and transient errors with delays: 1s, 2s, 4s
    
    Args:
        query_execution_id: Athena query execution ID
        max_retries: Maximum number of retry attempts
        
    Returns:
        Athena GetQueryExecution API response
    """
    retryable_errors = ['ThrottlingException', 'ServiceUnavailableException', 
                       'InternalServerException', 'TooManyRequestsException']
    retry_delays = [1, 2, 4]
    
    for attempt in range(max_retries + 1):
        try:
            response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
            return response
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            
            if error_code in retryable_errors and attempt < max_retries:
                delay = retry_delays[attempt] if attempt < len(retry_delays) else retry_delays[-1]
                logger.warning(f"Retryable error {error_code}. Retrying in {delay}s...")
                time.sleep(delay)
                continue
            else:
                raise


def extract_athena_metadata(query_execution_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from Athena GetQueryExecution response.
    
    Extracts query details, execution statistics, timing information, and error details.
    
    Args:
        query_execution_response: Response from Athena GetQueryExecution API
        
    Returns:
        Dictionary containing extracted metadata fields
    """
    query_exec = query_execution_response['QueryExecution']
    status = query_exec.get('Status', {})
    statistics = query_exec.get('Statistics', {})
    context = query_exec.get('QueryExecutionContext', {})
    result_config = query_exec.get('ResultConfiguration', {})
    athena_error = status.get('AthenaError', {})
    
    return {
        'query_execution_id': query_exec.get('QueryExecutionId'),
        'query_text': query_exec.get('Query', ''),
        'statement_type': query_exec.get('StatementType', ''),
        'database_name': context.get('Database', ''),
        'catalog_name': context.get('Catalog', ''),
        'workgroup_name': query_exec.get('WorkGroup', ''),
        'query_state': status.get('State', ''),
        'submission_time': status.get('SubmissionDateTime'),
        'completion_time': status.get('CompletionDateTime'),
        'execution_time_ms': statistics.get('EngineExecutionTimeInMillis'),
        'queue_time_ms': statistics.get('QueryQueueTimeInMillis'),
        'data_scanned_bytes': statistics.get('DataScannedInBytes'),
        'result_reused': statistics.get('ResultReuseInformation', {}).get('ReusedPreviousResult', False),
        'output_location': result_config.get('OutputLocation', ''),
        'error_category': athena_error.get('ErrorCategory'),
        'error_type': athena_error.get('ErrorType'),
        'error_message': athena_error.get('ErrorMessage'),
    }


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


def build_audit_record(athena_metadata: Dict[str, Any], cloudtrail_identity: Optional[Dict[str, Any]], 
                       event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build enriched audit record combining Athena metadata and CloudTrail identity.
    
    Args:
        athena_metadata: Extracted Athena metadata
        cloudtrail_identity: CloudTrail user identity (or None)
        event: Original EventBridge event
        
    Returns:
        Complete audit record dictionary
    """
    audit_id = str(uuid.uuid4())
    enrichment_timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Build base record from Athena metadata
    audit_record = {
        'audit_id': audit_id,
        'enrichment_timestamp': enrichment_timestamp,
        'event_time': event.get('time'),
        **athena_metadata
    }
    
    # Format timestamps
    if audit_record.get('submission_time'):
        audit_record['submission_time'] = format_timestamp(audit_record['submission_time'])
    if audit_record.get('completion_time'):
        audit_record['completion_time'] = format_timestamp(audit_record['completion_time'])
    
    # Add CloudTrail identity fields (null if not available)
    if cloudtrail_identity:
        audit_record.update(cloudtrail_identity)
    else:
        audit_record.update({
            'user_identity_type': None,
            'user_arn': None,
            'user_name': None,
            'principal_id': None,
            'account_id': None,
            'source_ip': None,
            'user_agent': None,
        })
    
    return audit_record


def format_timestamp(timestamp: Any) -> str:
    """Convert timestamp to ISO 8601 string with Z suffix."""
    if isinstance(timestamp, datetime):
        return timestamp.isoformat() + 'Z'
    if isinstance(timestamp, str):
        return timestamp if timestamp.endswith('Z') else timestamp + 'Z'
    return str(timestamp)


def should_audit_query(athena_metadata: Dict[str, Any]) -> bool:
    """
    Determine if a query should be audited based on configured filters.
    
    Checks against optional filters for:
    - Specific tables (AUDIT_TABLES_FILTER)
    - Specific databases (AUDIT_DATABASES_FILTER)
    - Specific workgroups (AUDIT_WORKGROUPS_FILTER)
    
    Filter Logic (controlled by AUDIT_FILTER_LOGIC):
    - OR (default): Audit if query matches ANY filter
    - AND: Audit if query matches ALL configured filters
    
    If no filters are configured, all queries are audited.
    
    Args:
        athena_metadata: Extracted Athena metadata
        
    Returns:
        True if query should be audited, False otherwise
    """
    # If no filters configured, audit everything
    if not AUDIT_TABLES_FILTER and not AUDIT_DATABASES_FILTER and not AUDIT_WORKGROUPS_FILTER:
        return True
    
    # Determine which filters are configured
    has_workgroup_filter = bool(AUDIT_WORKGROUPS_FILTER)
    has_database_filter = bool(AUDIT_DATABASES_FILTER)
    has_table_filter = bool(AUDIT_TABLES_FILTER)
    
    # Check each filter
    workgroup_match = False
    database_match = False
    table_match = False
    
    # Check workgroup filter
    if has_workgroup_filter:
        workgroup_list = [w.strip().lower() for w in AUDIT_WORKGROUPS_FILTER.split(',')]
        query_workgroup = athena_metadata.get('workgroup_name', '').lower()
        workgroup_match = query_workgroup in workgroup_list
        if workgroup_match:
            logger.info(f"Query matches workgroup filter: {query_workgroup}")
    
    # Check database filter
    if has_database_filter:
        database_list = [d.strip().lower() for d in AUDIT_DATABASES_FILTER.split(',')]
        query_database = athena_metadata.get('database_name', '').lower()
        database_match = query_database in database_list
        if database_match:
            logger.info(f"Query matches database filter: {query_database}")
    
    # Check table filter
    if has_table_filter:
        table_list = [t.strip().lower() for t in AUDIT_TABLES_FILTER.split(',')]
        query_text = athena_metadata.get('query_text', '').lower()
        
        # Simple table name matching in query text
        for table_name in table_list:
            if table_name in query_text:
                table_match = True
                logger.info(f"Query matches table filter: {table_name}")
                break
    
    # Apply filter logic
    if AUDIT_FILTER_LOGIC == 'AND':
        # AND logic: All configured filters must match
        filters_to_check = []
        if has_workgroup_filter:
            filters_to_check.append(workgroup_match)
        if has_database_filter:
            filters_to_check.append(database_match)
        if has_table_filter:
            filters_to_check.append(table_match)
        
        result = all(filters_to_check)
        if result:
            logger.info("Query matches ALL filters (AND logic)")
        else:
            logger.info("Query does not match ALL filters (AND logic)")
        return result
    else:
        # OR logic (default): Any filter match is sufficient
        result = (
            (has_workgroup_filter and workgroup_match) or
            (has_database_filter and database_match) or
            (has_table_filter and table_match)
        )
        if result:
            logger.info("Query matches at least one filter (OR logic)")
        else:
            logger.info("Query does not match any configured filters (OR logic)")
        return result


def write_to_s3(bucket_name: str, audit_record: Dict[str, Any]) -> str:
    """
    Write audit record to S3 with date-based partitioning.
    
    Creates partitioned path: athena-audit-logs/year=YYYY/month=MM/day=DD/{uuid}.json
    
    Args:
        bucket_name: S3 bucket name
        audit_record: Complete audit record
        
    Returns:
        S3 object key where record was written
    """
    # Parse submission time for partitioning
    submission_time_str = audit_record['submission_time'].rstrip('Z')
    dt = datetime.fromisoformat(submission_time_str)
    
    # Generate partitioned path
    year = dt.strftime('%Y')
    month = dt.strftime('%m')
    day = dt.strftime('%d')
    audit_id = audit_record['audit_id']
    
    s3_key = f"athena-audit-logs/year={year}/month={month}/day={day}/{audit_id}.json"
    
    # Write to S3
    s3_client.put_object(
        Bucket=bucket_name,
        Key=s3_key,
        Body=json.dumps(audit_record, default=str),
        ContentType='application/json'
    )
    
    logger.info(f"Wrote audit record to s3://{bucket_name}/{s3_key}")
    return s3_key
