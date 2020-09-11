# encoding: UTF-8

control "aws-foundations-cis-2.4" do
  title "Ensure CloudTrail trails are integrated with CloudWatch Logs"
  desc  "AWS CloudTrail is a web service that records AWS API calls made in a given AWS account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.

    Note: The intent of this recommendation is to ensure AWS account activity is being captured, monitored, and appropriately alarmed on. CloudWatch Logs is a native way to accomplish this using AWS services but does not preclude the use of an alternate solution."
  desc  "rationale", "Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides opportunity to establish alarms and notifications for anomalous or sensitivity account activity."
  desc  "check", "Perform the following to ensure CloudTrail is configured as prescribed:

    Via the AWS management Console
    1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail/](https://console.aws.amazon.com/cloudtrail/)
    2. Under `All Buckets` , click on the target bucket you wish to evaluate
    3. Click `Properties` on the top right of the console
    4. Click `Trails` in the left menu
    5. Ensure a `CloudWatch Logs` log group is configured and has a recent (~one day old) `Last log file delivered` timestamp.

    Via CLI
    1. Run the following command to get a listing of existing trails:
    ```
     aws cloudtrail describe-trails
    ```
    2. Ensure `CloudWatchLogsLogGroupArn` is not empty and note the value of the `Name` property.
    3. Using the noted value of the `Name` property, run the following command:
    ```
     aws cloudtrail get-trail-status --name
    ```
    4. Ensure the `LatestcloudwatchLogdDeliveryTime` property is set to a recent (~one day old) timestamp."
  desc  "fix", "Perform the following to establish the prescribed state:

    Via the AWS management Console
    1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail/](https://console.aws.amazon.com/cloudtrail/)
    2. Under All Buckets, click on the target bucket you wish to evaluate
    3. Click Properties on the top right of the console
    4. Click `Trails` in the left menu
    5. Click on each trail where no `CloudWatch Logs` are defined
    6. Go to the `CloudWatch Logs` section and click on `Configure`
    7. Define a new or select an existing log group
    8. Click on `Continue`
    9. Configure IAM Role which will deliver CloudTrail events to CloudWatch Logs
     - Create/Select an `IAM Role` and `Policy Name`
     - Click `Allow` to continue

    Via CLI
    ```
    aws cloudtrail update-trail --name
     --cloudwatch-logs-log-group-arn  --cloudwatch-logs-role-arn
    ```"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-12', 'SI-4(2)']
  tag notes: nil
  tag comment: "Note: By default, CloudWatch Logs will store Logs indefinitely unless a specific retention period is defined for the log group. When choosing the number of days to retain, keep in mind the average days it takes an organization to realize they have been breached is 210 days (at the time of this writing). Since additional time is required to research a breach, a minimum 365 day retention policy allows time for detection and research. You may also wish to archive the logs to a cheaper storage service rather than simply deleting them. See the following AWS resource to manage CloudWatch Logs retention periods:
  1. http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/SettingLogRetention.html"
  tag cis_controls: "TITLE:Activate audit logging CONTROL:6.2 DESCRIPTION:Ensure that local logging has been enabled on all systems and networking devices.;TITLE:Central Log Management CONTROL:6.5 DESCRIPTION:Ensure that appropriate logs are being aggregated to a central log management system for analysis and review.;"
  tag ref: "https://aws.amazon.com/cloudtrail/:CIS CSC v6.0 #6.6, #14.6"

  
  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      its('cloud_watch_logs_log_group_arn') { should_not be_nil }
      its('delivered_logs_days_ago') { should cmp <= 1 }
    end
  end
end