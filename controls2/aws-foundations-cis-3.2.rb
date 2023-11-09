# encoding: UTF-8

control "aws-foundations-cis-3.2" do
  title "Ensure CloudTrail log file validation is enabled "
  desc "CloudTrail log file validation creates a digitally signed digest file containing a hash of 
each log that CloudTrail writes to S3. These digest files can be used to determine whether a log 
file was changed, deleted, or unchanged after CloudTrail delivered the log. It is 
recommended that file validation be enabled on all CloudTrails. "
  desc "rationale", "Enabling log file validation will provide additional integrity checking of CloudTrail 
logs. "
  desc "check", "Perform the following on each trail to determine if log file validation is 
enabled:

**From Console:**

1. Sign in to the AWS Management Console and open the IAM 
console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
2. 
Click on `Trails` on the left navigation pane
3. For Every Trail:
- Click on a trail via the 
link in the _Name_ column
- Under the `General details` section, ensure `Log file 
validation` is set to `Enabled` 

**From Command Line:**
```
aws cloudtrail 
describe-trails
```
Ensure `LogFileValidationEnabled` is set to `true` for each trail "
  desc "fix", "Perform the following to enable log file validation on a given trail:

**From 
Console:**

1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
2. 
Click on `Trails` on the left navigation pane
3. Click on target trail
4. Within the 
`General details` section click `edit`
5. Under the `Advanced settings` section
6. 
Check the enable box under `Log file validation` 
7. Click `Save changes` 

**From 
Command Line:**
```
aws cloudtrail update-trail --name <trail_name> 
--enable-log-file-validation
```
Note that periodic validation of logs using these 
digests can be performed by running the following command:
```
aws cloudtrail 
validate-logs --trail-arn <trail_arn> --start-time <start_time> --end-time 
<end_time>
``` "
  desc "default_value", "Not Enabled "
  impact 0.5
  ref 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html'
  tag nist: []
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["8.11"]}
  ]
end