# CloudwatchFH2HEC
Cloudwatch Logs Transform for Firehose: formats into Splunk HEC Event

Lambda Function taken from AWS Repository to convert the Cloudwatch Logs into Splunk HEC Events.

Function takes the AWS Kinesis Firehose ARN and uses this for "Host", the LogGroup name for "Source". "Sourcetype" is set from an environment variable in the Lambda function settings (SPLUNK_SOURCETYPE).
Index is not set in the function, but could easily be added by another function environment variable.

Some use cases may require sourcetype to be set by the function - example: LogGroup prefix may identify sourcetype.
