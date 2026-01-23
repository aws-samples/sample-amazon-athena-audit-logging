# Implementing Comprehensive Audit Logging for Amazon Athena Queries 

This article demonstrates how to implement comprehensive audit logging for Amazon Athena queries with enriched user identity information. This solution helps organizations in regulated industries meet compliance requirements by providing detailed query audit trails with user attribution. 

## Introduction 

In regulated industries such as healthcare, financial services, and government, maintaining detailed audit trails of data access is not just a best practice- it's a compliance requirement. Organizations subject to regulations like HIPAA, SOX, GDPR, and FedRAMP must demonstrate who accessed what data, when, and from where. AWS Enterprise Support frequently partners with customers in these industries to help them implement robust auditing solutions that meet stringent regulatory requirements. 

Amazon Athena is a powerful serverless query service that allows organizations to analyze data in Amazon S3 using standard SQL. However, while Athena provides basic query history through its console and API, this information lacks the detailed user attribution and enriched metadata required for comprehensive audit trails in regulated environments. Specifically, Athena's native query history doesn't capture: 

- **User identity details**: IAM user/role names, ARNs, and principal IDs 

- **Source IP addresses**: Where queries originated from 

- **User agent information**: What tools or applications were used 

- **Enriched query metadata**: Detailed execution statistics and error information 

- **Long-term retention**: Query history beyond Athena's retention limits 

- **SQL-query able format**: Ability to analyze audit logs using Athena itself 

 

During compliance audits and security assessments, organizations must be able to answer questions like "Who ran queries against our sensitive patient data last quarter?" or "Which users accessed financial records from outside our corporate network?" Without enriched audit logging, answering these questions requires manual correlation of multiple AWS service logs—a time-consuming and error-prone process.

This case study demonstrates how AWS Enterprise Support collaborates with customers to architect and implement enhanced audit logging solutions for Athena. By combining Amazon EventBridge, AWS Lambda, AWS CloudTrail, and Amazon S3, we create a comprehensive audit trail that captures every query with full user attribution and detailed metadata. The solution seamlessly integrates with Athena's existing architecture and provides a SQL-queryable audit log that compliance teams can easily analyze. 

## Solution Overview 

This solution implements a two-stage enrichment process that captures comprehensive audit information for every Athena query: 

### Stage 1: Real-time Enrichment 

When an Athena query completes, Amazon EventBridge triggers an AWS Lambda function that: 

- Fetches detailed query metadata from the Athena API (execution statistics, data scanned, errors) 

- Attempts to look up user identity from AWS CloudTrail (IAM user/role, source IP, user agent) 

- Combines all information into an enriched audit record 

- Stores the record in Amazon S3 with date-based partitioning 

### Stage 2: Backfill Process 

Because CloudTrail events can take 5-15 minutes to appear in the LookupEvents API, some queries may initially have null user identity information. A scheduled Lambda function runs every 10 minutes to: 

- Scan recent audit records for missing user identity data 

- Look up CloudTrail events that are now available 

- Update S3 audit records with complete user attribution 

 

This two-stage approach ensures that audit records are created immediately (for real-time alerting) while also guaranteeing complete user attribution once CloudTrail data becomes available. The solution is cost-effective, requiring no additional infrastructure beyond serverless components that scale automatically. 

 

The enriched audit records are stored in S3 with Hive-style partitioning (`year=YYYY/month=MM/day=DD/`), making them immediately query able through Athena itself. This allows compliance teams to run SQL queries against the audit log, such as: 

```
-- Find all queries by a specific user in the last 30 days 

SELECT query_execution_id, query_text, submission_time, data_scanned_bytes 

FROM athena_audit_logs 

WHERE user_name = 'john.doe' 

  AND submission_time >= current_date - interval '30' day; 

 

-- Identify queries from outside corporate network 

SELECT user_name, source_ip, query_text, submission_time 

FROM athena_audit_logs 

WHERE source_ip NOT LIKE '10.%' 

  AND submission_time >= current_date - interval '7' day; 
```

## Prerequisites 

To implement this solution, you need the following prerequisites: 

- AWS Account with Amazon Athena workgroups configured 

- AWS CloudTrail enabled in your account (management events) 

- Amazon S3 bucket for storing audit records 

- IAM permissions to create Lambda functions, IAM roles, and EventBridge rules 

- Basic familiarity with AWS Lambda, EventBridge, and Athena

## Solution Implementation 

### Step 1: Create S3 Bucket for Audit Records

First, create an S3 bucket to store the enriched audit records. This bucket will contain JSON files organized by date partitions. 

- Open the Amazon S3 console 

- Choose Create bucket 

- Enter a bucket name (e.g., `athena-audit-logs-<account-id>`) 

- Choose your preferred AWS Region 

- Leave other settings as default 

- Choose Create bucket 


Note: Record the bucket name—you'll need for the Lambda function configuration. 


### Step 2: Create IAM Role for Lambda Functions 

Create an IAM role that grants the Lambda functions permissions to access Athena, CloudTrail, S3, and CloudWatch Logs. 

- Open the IAM console 

- In the navigation pane, choose Roles 

- Choose Create role 

- Select AWS service as the trusted entity type 

- Select Lambda as the use case 

- Choose Next 

- On the permissions page, do NOT select any existing policies 

- Scroll to the bottom and click Next 

- Enter a role name (e.g., `AthenaAuditLambdaRole`) 

- Choose Create role 

- After clicking "Create role," you'll see a success message 

- Click on the name of the role you just created in the success message 

- You're now on the role details page, Click the Permissions tab 

- Click the Add permissions dropdown button 

- Select Create inline policy from the dropdown menu 

- On the policy creation page, select the JSON tab 

- In the JSON tab, paste the following policy:

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

- Choose Next: Tags, then Next: Review 

- Enter a policy name (e.g., `AthenaAuditLambdaPolicy`) 

- Choose Create policy

### Step 3: Create the Enrichment Lambda Function 

Create the Lambda function that enriches Athena query events with metadata and user identity. 

- Open the AWS Lambda console 

- Choose Create function 

- Select Author from scratch 

- Enter function name: `athena-audit-enrichment` 

- Select Runtime: Python 3.14 

- Under Permissions, choose Use an existing role 

- Select the role you created in Step 2 

- Choose Create function 

- In the Code tab, replace the default code with the contents of `lambda_enrichment.py` (provided in the attached files) 

- In the Configuration tab, choose Environment variables 

- Choose Edit, then Add environment variable 

- Add the following variables: 

   - Key: `AUDIT_BUCKET_NAME`, Value: `athena-audit-logs-<account-id>` (your bucket name) 

   - Key: `CLOUDTRAIL_LOOKUP_ENABLED`, Value: `true` 

- Optional: Add filtering environment variables to audit only specific tables/databases/workgroups: 

    - Key: `AUDIT_WORKGROUPS_FILTER`, Value: `production-workgroup,sensitive-workgroup` (comma-separated list) 

    - Key: `AUDIT_DATABASES_FILTER`, Value: `production_db,sensitive_db` (comma-separated list) 

    - Key: `AUDIT_TABLES_FILTER`, Value: `employees,customers,transactions` (comma-separated list) 

     - Note: If no filters are set, ALL queries are audited. If any filter is set, only queries matching at least one filter are audited. 

- Choose Save 

- In the Configuration tab, choose General configuration 

- Choose Edit 

- Set Timeout to `1 minute` 

- Set Memory to `256 MB` 

- Choose Save 

- Choose Deploy to save your function code 