# encoding: UTF-8

control "aws-foundations-cis-3.4" do
  title "Ensure CloudTrail trails are integrated with CloudWatch Logs "
  desc "AWS CloudTrail is a web service that records AWS API calls made in a given AWS account. The 
recorded information includes the identity of the API caller, the time of the API call, the 
source IP address of the API caller, the request parameters, and the response elements 
returned by the AWS service. CloudTrail uses Amazon S3 for log file storage and delivery, so 
log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 
bucket for long term analysis, real time analysis can be performed by configuring CloudTrail 
to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, 
CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is 
recommended that CloudTrail logs be sent to CloudWatch Logs.

Note: The intent of this 
recommendation is to ensure AWS account activity is being captured, monitored, and 
appropriately alarmed on. CloudWatch Logs is a native way to accomplish this using AWS 
services but does not preclude the use of an alternate solution. "
  desc "rationale", "Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity 
logging based on user, API, resource, and IP address, and provides opportunity to establish 
alarms and notifications for anomalous or sensitivity account activity. "
  desc "check", "Perform the following to ensure CloudTrail is configured as prescribed:

**From 
Console:**

1. Login to the CloudTrail console at 
`https://console.aws.amazon.com/cloudtrail/`
2. Under `Trails` , click on the 
CloudTrail you wish to evaluate
3. Under the `CloudWatch Logs` section.
4. Ensure a 
`CloudWatch Logs` log group is configured and listed.
5. Under `General details` confirm 
`Last log file delivered` has a recent (~one day old) timestamp.

**From Command 
Line:**

1. Run the following command to get a listing of existing trails:
```
 aws 
cloudtrail describe-trails
```
2. Ensure `CloudWatchLogsLogGroupArn` is not empty 
and note the value of the `Name` property.
3. Using the noted value of the `Name` property, 
run the following command:
```
 aws cloudtrail get-trail-status --name 
<trail_name>
```
4. Ensure the `LatestcloudwatchLogdDeliveryTime` property is set to 
a recent (~one day old) timestamp.

If the `CloudWatch Logs` log group is not setup and the 
delivery time is not recent refer to the remediation below. "
  desc "fix", "Perform the following to establish the prescribed state:

**From Console:**

1. 
Login to the CloudTrail console at `https://console.aws.amazon.com/cloudtrail/`
2. 
Select the `Trail` the needs to be updated.
3. Scroll down to `CloudWatch Logs`
4. Click 
`Edit`
5. Under `CloudWatch Logs` click the box `Enabled`
6. Under `Log Group` pick new or 
select an existing log group
7. Edit the `Log group name` to match the CloudTrail or pick the 
existing CloudWatch Group.
8. Under `IAM Role` pick new or select an existing.
9. Edit the 
`Role name` to match the CloudTrail or pick the existing IAM Role.
10. Click `Save 
changes.

**From Command Line:**
```
aws cloudtrail update-trail --name 
<trail_name> --cloudwatch-logs-log-group-arn <cloudtrail_log_group_arn> 
--cloudwatch-logs-role-arn <cloudtrail_cloudwatchLogs_role_arn>
``` "
  desc "impact", "Note: By default, CloudWatch Logs will store Logs indefinitely unless a specific retention 
period is defined for the log group. When choosing the number of days to retain, keep in mind the 
average days it takes an organization to realize they have been breached is 210 days (at the 
time of this writing). Since additional time is required to research a breach, a minimum 365 
day retention policy allows time for detection and research. You may also wish to archive the 
logs to a cheaper storage service rather than simply deleting them. See the following AWS 
resource to manage CloudWatch Logs retention periods:

1. https://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/SettingLogRetention.html "
  impact 0.5
  ref 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html'
  tag nist: []
  tag severity: "medium "
end