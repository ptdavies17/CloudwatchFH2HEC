# Copyright 2014, Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""
For processing data sent to Firehose by Cloudwatch Logs subscription filters.

Cloudwatch Logs sends to Firehose records that look like this:

{
  "messageType": "DATA_MESSAGE",
  "owner": "123456789012",
  "logGroup": "log_group_name",
  "logStream": "log_stream_name",
  "subscriptionFilters": [
    "subscription_filter_name"
  ],
  "logEvents": [
    {
      "id": "01234567890123456789012345678901234567890123456789012345",
      "timestamp": 1510109208016,
      "message": "log message 1"
    },
    {
      "id": "01234567890123456789012345678901234567890123456789012345",
      "timestamp": 1510109208017,
      "message": "log message 2"
    }
    ...
  ]
}

The data is additionally compressed with GZIP.

The code below will:

1) Gunzip the data
2) Parse the json
3) Set the result to ProcessingFailed for any record whose messageType is not DATA_MESSAGE, thus redirecting them to the
   processing error output. Such records do not contain any log events. You can modify the code to set the result to
   Dropped instead to get rid of these records completely.
4) For records whose messageType is DATA_MESSAGE, extract the individual log events from the logEvents field, and pass
   each one to the transformLogEvent method. You can modify the transformLogEvent method to perform custom
   transformations on the log events.
5) Concatenate the result from (4) together and set the result as the data of the record returned to Firehose. Note that
   this step will not add any delimiters. Delimiters should be appended by the logic within the transformLogEvent
   method.
6) Any individual record exceeding 6,000,000 bytes in size after decompression, processing and base64-encoding is marked
   as Dropped, and the original record is split into two and re-ingested back into Firehose or Kinesis. The re-ingested
   records should be about half the size compared to the original, and should fit within the size limit the second time
   round.
7) When the total data size (i.e. the sum over multiple records) after decompression, processing and base64-encoding
   exceeds 6,000,000 bytes, any additional records are re-ingested back into Firehose or Kinesis.
8) The retry count for intermittent failures during re-ingestion is set 20 attempts. If you wish to retry fewer number
   of times for intermittent failures you can lower this value.
"""

import base64
import json
import gzip
import boto3
import os

def transformLogEvent(log_event,acct,arn,loggrp,logstrm,filterName):
    """Transform each log event.

    The default implementation below just extracts the message and appends a newline to it.

    Args:
    log_event (dict): The original log event. Structure is {"id": str, "timestamp": long, "message": str}
    acct: The aws account from where the Cloudwatch event came from
    arn: The ARN of the Kinesis Stream
    loggrp: The Cloudwatch log group name
    logstrm: The Cloudwatch logStream name (not used below)
    filterName: The Cloudwatch Subscription filter for the Stream
    Returns:
    str: The transformed log event.
        In the case below, Splunk event details are set as:
        time = event time for the Cloudwatch Log
        host = ARN of Firehose
        source = filterName (of cloudwatch Log) contatinated with LogGroup Name
        sourcetype is set as -
            aws:cloudtrail if the Log Group name contains CloudTrail
            aws:cloudwatchlogs:vpcflow if the Log Group name contains VPC
            the environment variable contents of SPLUNK_SOURCETYPE for all other cases
    """
    
    region_name=arn.split(':')[3]
    # note that the region_name is taken from the region for the Stream, this won't change if Cloudwatch from another account/region. Not used for this example function
    if "CloudTrail" in loggrp:
        sourcetype="aws:cloudtrail"
    elif "VPC" in loggrp:
        sourcetype="aws:cloudwatchlogs:vpcflow"
    else:
        sourcetype=os.environ['SPLUNK_SOURCETYPE']
    
    return_message = '{"time": ' + str(log_event['timestamp']) + ',"host": "' + arn  +'","source": "' + filterName +':' + loggrp + '"'
    return_message = return_message + ',"sourcetype":"' + sourcetype  + '"'
    return_message = return_message + ',"event": ' + json.dumps(log_event['message']) + '}\n'
    
    return return_message + '\n'


def processRecords(records,arn):
    for r in records:
        data = loadJsonGzipBase64(r['data'])
        recId = r['recordId']
        # CONTROL_MESSAGE are sent by CWL to check if the subscription is reachable.
        # They do not contain actual data.
        if data['messageType'] == 'CONTROL_MESSAGE':
            yield {
                'result': 'Dropped',
                'recordId': recId
            }
        elif data['messageType'] == 'DATA_MESSAGE':
            joinedData = ''.join([transformLogEvent(e,data['owner'],arn,data['logGroup'],data['logStream'],data['subscriptionFilters'][0]) for e in data['logEvents']])
            dataBytes = joinedData.encode("utf-8")
            encodedData = base64.b64encode(dataBytes).decode('utf-8')
            yield {
                'data': encodedData,
                'result': 'Ok',
                'recordId': recId
            }
        else:
            yield {
                'result': 'ProcessingFailed',
                'recordId': recId
            }

def splitCWLRecord(cwlRecord):
    """
    Splits one CWL record into two, each containing half the log events.
    Serializes and compreses the data before returning. That data can then be
    re-ingested into the stream, and it'll appear as though they came from CWL
    directly.
    """
    logEvents = cwlRecord['logEvents']
    mid = len(logEvents) // 2
    rec1 = {k:v for k, v in cwlRecord.items()}
    rec1['logEvents'] = logEvents[:mid]
    rec2 = {k:v for k, v in cwlRecord.items()}
    rec2['logEvents'] = logEvents[mid:]
    return [gzip.compress(json.dumps(r).encode('utf-8')) for r in [rec1, rec2]]

def putRecordsToFirehoseStream(streamName, records, client, attemptsMade, maxAttempts):
    failedRecords = []
    codes = []
    errMsg = ''
    # if put_record_batch throws for whatever reason, response['xx'] will error out, adding a check for a valid
    # response will prevent this
    response = None
    try:
        response = client.put_record_batch(DeliveryStreamName=streamName, Records=records)
    except Exception as e:
        failedRecords = records
        errMsg = str(e)

    # if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
    if not failedRecords and response and response['FailedPutCount'] > 0:
        for idx, res in enumerate(response['RequestResponses']):
            # (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
            if not res.get('ErrorCode'):
                continue

            codes.append(res['ErrorCode'])
            failedRecords.append(records[idx])

        errMsg = 'Individual error codes: ' + ','.join(codes)

    if failedRecords:
        if attemptsMade + 1 < maxAttempts:
            print('Some records failed while calling PutRecordBatch to Firehose stream, retrying. %s' % (errMsg))
            putRecordsToFirehoseStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
        else:
            raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))


def putRecordsToKinesisStream(streamName, records, client, attemptsMade, maxAttempts):
    failedRecords = []
    codes = []
    errMsg = ''
    # if put_records throws for whatever reason, response['xx'] will error out, adding a check for a valid
    # response will prevent this
    response = None
    try:
        response = client.put_records(StreamName=streamName, Records=records)
    except Exception as e:
        failedRecords = records
        errMsg = str(e)

    # if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
    if not failedRecords and response and response['FailedRecordCount'] > 0:
        for idx, res in enumerate(response['Records']):
            # (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
            if not res.get('ErrorCode'):
                continue

            codes.append(res['ErrorCode'])
            failedRecords.append(records[idx])

        errMsg = 'Individual error codes: ' + ','.join(codes)

    if failedRecords:
        if attemptsMade + 1 < maxAttempts:
            print('Some records failed while calling PutRecords to Kinesis stream, retrying. %s' % (errMsg))
            putRecordsToKinesisStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
        else:
            raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))


def createReingestionRecord(isSas, originalRecord, data=None):
    if data is None:
        data = base64.b64decode(originalRecord['data'])
    r = {'Data': data}
    if isSas:
        r['PartitionKey'] = originalRecord['kinesisRecordMetadata']['partitionKey']
    return r


def loadJsonGzipBase64(base64Data):
    return json.loads(gzip.decompress(base64.b64decode(base64Data)))


def lambda_handler(event, context):
    isSas = 'sourceKinesisStreamArn' in event
    streamARN = event['sourceKinesisStreamArn'] if isSas else event['deliveryStreamArn']
    region = streamARN.split(':')[3]
    streamName = streamARN.split('/')[1]
    records = list(processRecords(event['records'],streamARN))
    projectedSize = 0
    recordListsToReingest = []

    for idx, rec in enumerate(records):
        originalRecord = event['records'][idx]

        if rec['result'] != 'Ok':
            continue

        # If a single record is too large after processing, split the original CWL data into two, each containing half
        # the log events, and re-ingest both of them (note that it is the original data that is re-ingested, not the 
        # processed data). If it's not possible to split because there is only one log event, then mark the record as
        # ProcessingFailed, which sends it to error output.
        if len(rec['data']) > 6000000:
            cwlRecord = loadJsonGzipBase64(originalRecord['data'])
            if len(cwlRecord['logEvents']) > 1:
                rec['result'] = 'Dropped'
                recordListsToReingest.append(
                    [createReingestionRecord(isSas, originalRecord, data) for data in splitCWLRecord(cwlRecord)])
            else:
                rec['result'] = 'ProcessingFailed'
                print(('Record %s contains only one log event but is still too large after processing (%d bytes), ' +
                    'marking it as %s') % (rec['recordId'], len(rec['data']), rec['result']))
            del rec['data']
        else:
            projectedSize += len(rec['data']) + len(rec['recordId'])
            # 6000000 instead of 6291456 to leave ample headroom for the stuff we didn't account for
            if projectedSize > 6000000:
                recordListsToReingest.append([createReingestionRecord(isSas, originalRecord)])
                del rec['data']
                rec['result'] = 'Dropped'

    # call putRecordBatch/putRecords for each group of up to 500 records to be re-ingested
    if recordListsToReingest:
        recordsReingestedSoFar = 0
        client = boto3.client('kinesis' if isSas else 'firehose', region_name=region)
        maxBatchSize = 500
        flattenedList = [r for sublist in recordListsToReingest for r in sublist]
        for i in range(0, len(flattenedList), maxBatchSize):
            recordBatch = flattenedList[i:i + maxBatchSize]
            # last argument is maxAttempts
            args = [streamName, recordBatch, client, 0, 20]
            if isSas:
                putRecordsToKinesisStream(*args)
            else:
                putRecordsToFirehoseStream(*args)
            recordsReingestedSoFar += len(recordBatch)
            print('Reingested %d/%d' % (recordsReingestedSoFar, len(flattenedList)))

    print('%d input records, %d returned as Ok or ProcessingFailed, %d split and re-ingested, %d re-ingested as-is' % (
        len(event['records']),
        len([r for r in records if r['result'] != 'Dropped']),
        len([l for l in recordListsToReingest if len(l) > 1]),
        len([l for l in recordListsToReingest if len(l) == 1])))

    return {'records': records}
