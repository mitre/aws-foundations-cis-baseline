# encoding: UTF-8

control "aws-foundations-cis-3.5" do
  title "Ensure AWS Config is enabled in all regions "
  desc "AWS Config is a web service that performs configuration management of supported AWS 
resources within your account and delivers log files to you. The recorded information 
includes the configuration item (AWS resource), relationships between configuration 
items (AWS resources), any configuration changes between resources. It is recommended AWS 
Config be enabled in all regions. "
  desc "rationale", "The AWS configuration item history captured by AWS Config enables security analysis, 
resource change tracking, and compliance auditing. "
  desc "check", "Process to evaluate AWS Config configuration per region

**From Console:**

1. Sign 
in to the AWS Management Console and open the AWS Config console at [https://console.aws.amazon.com/config/](https://console.aws.amazon.com/config/).
1. 
On the top right of the console select target Region.
1. If a Config recorder is enabled in 
this region, you should navigate to the Settings page from the navigation menu on the left hand 
side. If a Config recorder is not yet enabled in this region then you should select \"Get 
Started\".
1. Ensure \"Record all resources supported in this region\" is checked.
1. 
Ensure \"Include global resources (e.g., AWS IAM resources)\" is checked, unless it is enabled 
in another region (this is only required in one region)
1. Ensure the correct S3 bucket has 
been defined.
1. Ensure the correct SNS topic has been defined.
1. Repeat steps 2 to 7 for 
each region.

**From Command Line:**

1. Run this command to show all AWS Config 
recorders and their properties:
```
aws configservice 
describe-configuration-recorders
```
2. Evaluate the output to ensure that all 
recorders have a `recordingGroup` object which includes `\"allSupported\": true`. 
Additionally, ensure that at least one recorder has `\"includeGlobalResourceTypes\": 
true`

Note: There is one more parameter \"ResourceTypes\" in recordingGroup object. We 
don't need to check the same as whenever we set \"allSupported\": true, AWS enforces resource 
types to be empty (\"ResourceTypes\":[])

Sample Output:

```
{
 
\"ConfigurationRecorders\": [
 {
 \"recordingGroup\": {
 \"allSupported\": true,
 
\"resourceTypes\": [],
 \"includeGlobalResourceTypes\": true
 },
 \"roleARN\": 
\"arn:aws:iam::<AWS_Account_ID>:role/service-role/<config-role-name>\",
 \"name\": 
\"default\"
 }
 ]
}
```

3. Run this command to show the status for all AWS Config 
recorders:
```
aws configservice 
describe-configuration-recorder-status
```
4. In the output, find recorders with 
`name` key matching the recorders that were evaluated in step 2. Ensure that they include 
`\"recording\": true` and `\"lastStatus\": \"SUCCESS\"` "
  desc "fix", "To implement AWS Config configuration:

**From Console:**

1. Select the region you 
want to focus on in the top right of the console
2. Click Services
3. Click Config
4. If a 
Config recorder is enabled in this region, you should navigate to the Settings page from the 
navigation menu on the left hand side. If a Config recorder is not yet enabled in this region 
then you should select \"Get Started\".
5. Select \"Record all resources supported in this 
region\"
6. Choose to include global resources (IAM resources)
7. Specify an S3 bucket in 
the same account or in another managed AWS account
8. Create an SNS Topic from the same AWS 
account or another managed AWS account

**From Command Line:**

1. Ensure there is an 
appropriate S3 bucket, SNS topic, and IAM role per the [AWS Config Service prerequisites](http://docs.aws.amazon.com/config/latest/developerguide/gs-cli-prereq.html).
2. 
Run this command to create a new configuration recorder:
```
aws configservice 
put-configuration-recorder --configuration-recorder 
name=default,roleARN=arn:aws:iam::012345678912:role/myConfigRole 
--recording-group allSupported=true,includeGlobalResourceTypes=true
```
3. 
Create a delivery channel configuration file locally which specifies the channel 
attributes, populated from the prerequisites set up previously:
```
{
 \"name\": 
\"default\",
 \"s3BucketName\": \"my-config-bucket\",
 \"snsTopicARN\": 
\"arn:aws:sns:us-east-1:012345678912:my-config-notice\",
 
\"configSnapshotDeliveryProperties\": {
 \"deliveryFrequency\": \"Twelve_Hours\"
 
}
}
```
4. Run this command to create a new delivery channel, referencing the json 
configuration file made in the previous step:
```
aws configservice 
put-delivery-channel --delivery-channel file://deliveryChannel.json
```
5. Start 
the configuration recorder by running the following command:
```
aws configservice 
start-configuration-recorder --configuration-recorder-name default
``` "
  desc "impact", "It is recommended AWS Config be enabled in all regions. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/cli/latest/reference/configservice/describe-configuration-recorder-status.html:https://docs.aws.amazon.com/cli/latest/reference/configservice/describe-configuration-recorders.html:https://docs.aws.amazon.com/config/latest/developerguide/gs-cli-prereq.html'
  tag nist: []
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["1.1"]}
  ]
end