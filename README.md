# CloudwatchFH2HEC
Cloudwatch Logs Transform for Firehose: formats into Splunk HEC Event

Lambda Function taken from AWS Repository to convert the Cloudwatch Logs into Splunk HEC Events.

Function takes the AWS Kinesis Firehose ARN and uses this for "Host", the LogGroup name and the subscription filter name for "Source". "Sourcetype" is set as "aws:cloudtrail" if the Log Group name contains CloudTrail, "aws:cloudwatchlogs:vpcflow" if the Log Group name contains VPC, or for all other cases taken from an environment variable in the Lambda function settings (SPLUNK_SOURCETYPE).

Index is not set in the function, but could easily be added by contents of LogGroup name or Subscription Filter name.

Instructions to set this up are in the file here: SETUP.pdf
