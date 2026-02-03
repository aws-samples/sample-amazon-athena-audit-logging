# Implementing Comprehensive Audit Logging for Amazon Athena Queries 

This solution provides comprehensive audit logging for Amazon Athena queries, enriching query metadata with user identity information from CloudTrail. The system captures Athena query executions and stores enriched audit records in S3 for compliance and analysis purposes.

## Architecture Overview

The solution consists of:
- **Enrichment Lambda**: Captures Athena query events and creates initial audit records
- **Backfill Lambda**: Enriches audit records with CloudTrail user identity data
- **S3 Storage**: Stores audit records in partitioned JSON format
- **Athena Table**: Enables SQL querying of audit logs
- **EventBridge Rules**: Triggers Lambda functions on events and schedules

## Architecture Diagram

![Audit Logging for Amazon Athena Architecture](Images/Audit-Logging-for-Amazon-Athena.png)

## Step 1: Create S3 Bucket for Audit Records

First, create an S3 bucket to store the enriched audit records. This bucket will contain JSON files organized by date partitions.

- Open the **Amazon S3 console**
- Choose **Create bucket**
- Enter a bucket name (e.g., `athena-audit-logs-<account-id>`)
- Choose your preferred **AWS Region**
- Leave other settings as default
- Choose **Create bucket**

**Note:** Record the bucket name—you'll need for the Lambda function configuration.

## Step 2: Create IAM Role for Lambda Functions

Create an IAM role that grants the Lambda functions permissions to access Athena, CloudTrail, S3, and CloudWatch Logs.

- Open the **IAM console**
- In the navigation pane, choose **Roles**
- Choose **Create role**
- Select **AWS service** as the trusted entity type
- Select **Lambda** as the use case
- Choose **Next**
- On the permissions page, do **NOT** select any existing policies
- Scroll to the bottom and click **Next**
- Enter a role name (e.g., `AthenaAuditLambdaRole`)
- Choose **Create role**
- After clicking "**Create role**," you'll see a success message
- Click on the name of the role you just created in the success message
- You're now on the role details page, Click the **Permissions** tab
- Click the **Add permissions** dropdown button
- Select **Create inline policy** from the dropdown menu
- On the policy creation page, select the **JSON** tab
- In the **JSON** tab, paste the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AthenaAccess",
            "Effect": "Allow",
            "Action": [
                "athena:GetQueryExecution"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudTrailAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::athena-audit-logs-<account-id>",
                "arn:aws:s3:::athena-audit-logs-<account-id>/*"
            ]
        },
        {
            "Sid": "CloudWatchLogsAccess",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

- Replace `<account-id>` with your AWS account ID
- Choose **Next: Tags**, then **Next: Review**
- Enter a policy name (e.g., `AthenaAuditLambdaPolicy`)
- Choose **Create policy**

## Step 3: Create the Enrichment Lambda Function

Create the Lambda function that enriches Athena query events with metadata and user identity.

- Open the **AWS Lambda console**
- Choose **Create function**
- Select **Author from scratch**
- Enter function name: `athena-audit-enrichment`
- Select **Runtime**: **Python 3.14**
- Under **Permissions**, choose **Use an existing role**
- Select the role you created in Step 2
- Choose **Create function**
- In the **Code** tab, replace the default code with the contents of `lambda_enrichment.py` (provided in the attached files)
- In the **Configuration** tab, choose **Environment variables**
- Choose **Edit**, then **Add environment variable**
- Add the following variables:
  - Key: `AUDIT_BUCKET_NAME`, Value: `athena-audit-logs-<account-id>` (your bucket name)
  - Key: `CLOUDTRAIL_LOOKUP_ENABLED`, Value: `true`
- **Optional**: Add filtering environment variables to audit only specific tables/databases/workgroups:
    By default, the solution audits **all** Athena queries in your account. However, you can configure filters to audit only specific queries based on workgroups, databases, or tables.

    You can use any combination of these three filters:

    - **`AUDIT_WORKGROUPS_FILTER`** - Comma-separated list of workgroup names to audit (e.g., `production-workgroup,sensitive-workgroup`)
    - **`AUDIT_DATABASES_FILTER`** - Comma-separated list of database names to audit (e.g., `production_db,sensitive_db,analytics_db`)
    - **`AUDIT_TABLES_FILTER`** - Comma-separated list of table names to audit (e.g., `employees,customers,transactions`)
    - **`AUDIT_FILTER_LOGIC`** - How to combine multiple filters: OR (Default) or AND 
   
    **Important Notes**:
    - Filter values are **case-insensitive** (e.g., `Production-Workgroup` matches `production-workgroup`)
    - Table filtering uses **simple text matching** in the query text (e.g., `employees` matches any query containing "employees")
    - If **no filters** are configured, **all queries** are audited
    - Filters only apply to the enrichment Lambda - the backfill Lambda updates whatever the enrichment Lambda created


    ##### **OR Logic (Default Behavior)**

   - **When to use**: You want to audit queries that match **ANY** of your configured filters (broad filtering)

   - **How it works**: A query is audited if it matches **at least one** filter

    ##### **AND Logic (Precise Filtering)**

    - **When to use**: You want to audit queries that match **ALL** of your configured filters (narrow, precise filtering)

   - **How it works**: A query is audited **only if** it matches **every** configured filter

    **⚠️ IMPORTANT**: You **MUST** explicitly set `AUDIT_FILTER_LOGIC=AND` to use AND logic



- Choose **Save**
- In the **Configuration** tab, choose **General configuration**
- Choose **Edit**
- Set **Timeout** to `1 minute`
- Set **Memory** to `256 MB`
- Choose **Save**
- Choose **Deploy** to save your function code

## Step 4: Create CloudWatch Log Group

Create a CloudWatch Log Group for the Lambda function to write logs.

- Open the **CloudWatch console**
- In the navigation pane, choose **Log Management** under **Logs**
- Choose **Create log group**
- Enter log group name: `/aws/lambda/athena-audit-enrichment`
- Choose **Create**

**Best Practice:** Configure log retention (e.g., 30 days) to manage costs and comply with data retention policies.

## Step 5: Create EventBridge Rule for Athena Query Events

Create an EventBridge rule that triggers the Lambda function when Athena queries complete.

- Open the **Amazon EventBridge console**
- In the navigation pane, choose **Rules** under **Buses**
- Choose **Create rule**
- Enter rule name: `athena-query-state-change-rule`
- Enter description: `Trigger audit enrichment for Athena query completions`
- Enable the rule on the selected event bus
- Choose **Next**
- Under **Event source**, select **AWS events or EventBridge partner events**
- Under **Event pattern**, choose **Custom pattern (JSON editor)**
- Paste the following event pattern:

```json
{
    "source": ["aws.athena"],
    "detail-type": ["Athena Query State Change"],
    "detail": {
        "currentState": ["SUCCEEDED", "FAILED", "CANCELED"]
    }
}
```

- Choose **Next**
- Under **Target types**, select **AWS service**
- Under **Select a target**, choose **Lambda function**
- Under **Function**, select `athena-audit-enrichment`
- Choose **Next**
- Review the configuration and choose **Create rule**

**Note:** Add appropriate tags to all resources for cost allocation and tracking across your organization.

## Step 6: Test the Enrichment Lambda

Test the solution by running an Athena query and verifying the audit record is created.

- Open the **Amazon Athena console**
- Run a simple query (e.g., `SELECT 1`)
- Wait for the query to complete
- Open the **S3 console** and navigate to your audit bucket
- Browse to the partition for today's date: `athena-audit-logs/year=YYYY/month=MM/day=DD/`
- You should see a JSON file with a UUID filename
- Download and open the file to verify it contains enriched audit data

**Note:** The `user_name` and other CloudTrail fields may be `null` initially. This is expected—the backfill Lambda will populate them within 10-15 minutes.

## Step 7: Create the Backfill Lambda Function

Create the scheduled Lambda function that backfills missing CloudTrail data.

- Open the **AWS Lambda console**
- Choose **Create function**
- Select **Author from scratch**
- Enter function name: `athena-audit-cloudtrail-backfill`
- Select **Runtime**: **Python 3.14**
- Under **Permissions**, choose **Use an existing role**
- Select the role you created in Step 2 (same role as enrichment Lambda)
- Choose **Create function**
- In the **Code** tab, replace the default code with the contents of `lambda_backfill.py` (provided in the attached files)
- In the **Configuration** tab, choose **Environment variables**
- Choose **Edit**, then **Add environment variable**
- Add the following variable:
  - **Key**: `AUDIT_BUCKET_NAME`, **Value**: `athena-audit-logs-<account-id>` (your bucket name)
- Choose **Save**
- In the **Configuration** tab, choose **General configuration**
- Choose **Edit**
- Set **Timeout** to `2 minutes`
- Set **Memory** to `256 MB`
- Choose **Save**
- Choose **Deploy** to save your function code

## Step 8: Create CloudWatch Log Group for Backfill Lambda

Create a CloudWatch Log Group for the backfill Lambda function.

- Open the **CloudWatch console**
- In the navigation pane, choose **Log groups**
- Choose **Create log group**
- Enter log group name: `/aws/lambda/athena-audit-cloudtrail-backfill`
- Choose **Create**

## Step 9: Create EventBridge Schedule for Backfill Lambda

Create a scheduled rule that runs the backfill Lambda every 10 minutes.

- Open the **Amazon EventBridge console**
- In the navigation pane, choose **Schedules** under **Scheduler**
- Choose **Create schedule**
- Enter schedule name: `athena-audit-backfill-schedule`
- Enter description: `Run CloudTrail backfill every 10 minutes`
- Use default **Schedule group**
- Under **Schedule pattern**, select **Recurring Schedule**
- Select **Rate-based Schedule** type
- Configure **Rate expression** for every 10 minutes
- Choose **Off** under **Flexible time window**
- Choose **Next**
- Under **Target details**, choose **Lambda function**
- Under **Function**, select `athena-audit-cloudtrail-backfill`
- Choose **Next**
- Review the configuration and choose **Create schedule**

**Note:** Choose schedule frequency as per your organization's requirements and cost considerations.

## Step 10: Create Athena Table for Querying Audit Logs

Create an Athena table that allows you to query the audit logs using SQL.

- Open the **Amazon Athena console**
- In the query editor, run the following DDL statement (replace `<account-id>` with your AWS account ID):

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS athena_audit_logs (
    audit_id STRING,
    query_execution_id STRING,
    query_text STRING,
    statement_type STRING,
    database_name STRING,
    catalog_name STRING,
    workgroup_name STRING,
    query_state STRING,
    submission_time STRING,
    completion_time STRING,
    execution_time_ms BIGINT,
    queue_time_ms BIGINT,
    data_scanned_bytes BIGINT,
    result_reused BOOLEAN,
    output_location STRING,
    error_category STRING,
    error_type STRING,
    error_message STRING,
    user_identity_type STRING,
    user_arn STRING,
    user_name STRING,
    principal_id STRING,
    account_id STRING,
    source_ip STRING,
    user_agent STRING,
    event_time STRING,
    enrichment_timestamp STRING,
    cloudtrail_backfill_timestamp STRING
)
PARTITIONED BY (
    year STRING,
    month STRING,
    day STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://athena-audit-logs-<account-id>/athena-audit-logs/';
```

- After creating the table, run the following command to load partitions:

```sql
MSCK REPAIR TABLE athena_audit_logs;
```

- Test the table by running a query:

```sql
SELECT query_execution_id, user_name, query_state, submission_time
FROM athena_audit_logs
LIMIT 10;
```

## Step 11: Test and Validate the Complete Solution

Validate that both the enrichment and backfill processes are working correctly.

- Run multiple Athena queries from the **Athena console**
- Wait 2-3 minutes and check the **S3 bucket** for new audit records
- Verify initial records have some null CloudTrail fields (this is expected)
- Wait 10-15 minutes for the **backfill Lambda** to run
- Check the same S3 files again—they should now have complete user identity information
- Query the audit table in **Athena** to verify you can analyze the logs:

```sql
SELECT
    user_name,
    COUNT(*) as query_count,
    SUM(data_scanned_bytes) / 1024 / 1024 / 1024 as total_gb_scanned
FROM athena_audit_logs
WHERE year = '2026' AND month = '01'
GROUP BY user_name
ORDER BY query_count DESC;
```


## Cleanup

If you want to remove the solution, follow these steps:

1. **Delete EventBridge rules:**
   - `athena-query-state-change-rule`
   - `athena-audit-backfill-schedule`

2. **Delete Lambda functions:**
   - `athena-audit-enrichment`
   - `athena-audit-cloudtrail-backfill`

3. **Delete CloudWatch Log Groups:**
   - `/aws/lambda/athena-audit-enrichment`
   - `/aws/lambda/athena-audit-cloudtrail-backfill`

4. **Delete IAM role and policy:**
   - `AthenaAuditLambdaRole`
   - `AthenaAuditLambdaPolicy`

5. **Delete Athena table (optional):**
   ```sql
   DROP TABLE athena_audit_logs;
   ```

6. **Delete S3 bucket (optional):**
   - Empty the bucket first, then delete it

**Warning:** Deleting the S3 bucket will permanently remove all audit records. Consider archiving them first if needed for compliance.
