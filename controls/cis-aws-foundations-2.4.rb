# encoding: UTF-8

control "2.4" do
  title "Ensure CloudTrail trails are integrated with CloudWatch Logs"
  desc  "AWS CloudTrail is a web service that records AWS API calls made in a
given AWS account. The recorded information includes the identity of the API
caller, the time of the API call, the source IP address of the API caller, the
request parameters, and the response elements returned by the AWS service.
CloudTrail uses Amazon S3 for log file storage and delivery, so log files are
stored durably. In addition to capturing CloudTrail logs within a specified S3
bucket for long term analysis, realtime analysis can be performed by
configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is
enabled in all regions in an account, CloudTrail sends log files from all those
regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs
be sent to CloudWatch Logs.

    Note: The intent of this recommendation is to ensure AWS account activity
is being captured, monitored, and appropriately alarmed on. CloudWatch Logs is
a native way to accomplish this using AWS services but does not preclude the
use of an alternate solution.
  "
  desc  "rationale", "Sending CloudTrail logs to CloudWatch Logs will
facilitate real-time and historic activity logging based on user, API,
resource, and IP address, and provides opportunity to establish alarms and
notifications for anomalous or sensitivity account activity."
  desc  "check", "
    Perform the following to ensure CloudTrail is configured as prescribed:

    Via the AWS management Console

    1. Sign in to the AWS Management Console and open the CloudTrail console at
[https://console.aws.amazon.com/cloudtrail/](https://console.aws.amazon.com/cloudtrail/)
    2. Under `All Buckets` , click on the target bucket you wish to evaluate
    3. Click `Properties` on the top right of the console
    4. Click `Trails` in the left menu
    5. Ensure a `CloudWatch Logs` log group is configured and has a recent
(~one day old) `Last log file delivered` timestamp.

    Via CLI

    1. Run the following command to get a listing of existing trails:
    ```
     aws cloudtrail describe-trails

    ```
    2. Ensure `CloudWatchLogsLogGroupArn` is not empty and note the value of
the `Name` property.
    3. Using the noted value of the `Name` property, run the following command:
    ```
     aws cloudtrail get-trail-status --name

    ```
    4. Ensure the `LatestcloudwatchLogdDeliveryTime` property is set to a
recent (~one day old) timestamp.
  "
  desc  "fix", "
    Perform the following to establish the prescribed state:

    Via the AWS management Console

    1. Sign in to the AWS Management Console and open the CloudTrail console at
[https://console.aws.amazon.com/cloudtrail/](https://console.aws.amazon.com/cloudtrail/)
    2. Under All Buckets, click on the target bucket you wish to evaluate
    3. Click Properties on the top right of the console
    4. Click `Trails` in the left menu
    5. Click on each trail where no `CloudWatch Logs` are defined
    6. Go to the `CloudWatch Logs` section and click on `Configure`
    7. Define a new or select an existing log group
    8. Click on `Continue`
    9. Configure IAM Role which will deliver CloudTrail events to CloudWatch
Logs
     - Create/Select an `IAM Role` and `Policy Name`
     - Click `Allow` to continue

    Via CLI
    ```
    aws cloudtrail update-trail --name
     --cloudwatch-logs-log-group-arn  --cloudwatch-logs-role-arn
    ```
  "
  impact 0.3
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag cis_controls: "TITLE:Activate audit logging CONTROL:6.2
DESCRIPTION:Ensure that local logging has been enabled on all systems and
networking devices.;TITLE:Central Log Management CONTROL:6.5 DESCRIPTION:Ensure
that appropriate logs are being aggregated to a central log management system
for analysis and review.;"
  tag ref: "https://aws.amazon.com/cloudtrail/:CIS CSC v6.0 #6.6, #14.6"
end

