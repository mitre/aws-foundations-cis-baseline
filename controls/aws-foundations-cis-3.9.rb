control 'aws-foundations-cis-3.9' do
  title 'Ensure VPC flow logging is enabled in all VPCs '
  desc "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to
and from network interfaces in your VPC. After you've created a flow log, you can view and
retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled
for packet \"Rejects\" for VPCs. "
  desc 'rationale', "VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to
detect anomalous traffic or insight during security workflows. "
  desc 'check', "Perform the following to determine if VPC Flow logs are enabled:

**From
Console:**

1. Sign into the management console
2. Select `Services` then `VPC`
3. In
the left navigation pane, select `Your VPCs`
4. Select a VPC
5. In the right pane, select
the `Flow Logs` tab.
6. Ensure a Log Flow exists that has `Active` in the `Status`
column.

**From Command Line:**

1. Run `describe-vpcs` command (OSX/Linux/UNIX)
to list the VPC networks available in the current AWS region:
```
aws ec2 describe-vpcs
--region <region> --query Vpcs[].VpcId
```
2. The command output returns the `VpcId`
available in the selected region.
3. Run `describe-flow-logs` command (OSX/Linux/UNIX)
using the VPC ID to determine if the selected virtual network has the Flow Logs feature
enabled:
```
aws ec2 describe-flow-logs --filter
\"Name=resource-id,Values=<vpc-id>\"
```
4. If there are no Flow Logs created for the
selected VPC, the command output will return an `empty list []`.
5. Repeat step 3 for other
VPCs available in the same region.
6. Change the region by updating `--region` and repeat
steps 1 - 5 for all the VPCs. "
  desc 'fix', "Perform the following to determine if VPC Flow logs is enabled:

**From Console:**

1.
Sign into the management console
2. Select `Services` then `VPC`
3. In the left
navigation pane, select `Your VPCs`
4. Select a VPC
5. In the right pane, select the `Flow
Logs` tab.
6. If no Flow Log exists, click `Create Flow Log`
7. For Filter, select
`Reject`
8. Enter in a `Role` and `Destination Log Group`
9. Click `Create Log Flow`
10.
Click on `CloudWatch Logs Group`

**Note:** Setting the filter to \"Reject\" will
dramatically reduce the logging data accumulation for this recommendation and provide
sufficient information for the purposes of breach detection, research and remediation.
However, during periods of least privilege security group engineering, setting this the
filter to \"All\" can be very helpful in discovering existing traffic flows required for proper
operation of an already running environment.

**From Command Line:**

1. Create a
policy document and name it as `role_policy_document.json` and paste the following
content:
```
{
 \"Version\": \"2012-10-17\",
 \"Statement\": [
 {
 \"Sid\": \"test\",

\"Effect\": \"Allow\",
 \"Principal\": {
 \"Service\": \"ec2.amazonaws.com\"
 },
 \"Action\":
\"sts:AssumeRole\"
 }
 ]
}
```
2. Create another policy document and name it as
`iam_policy.json` and paste the following content:
```
{
 \"Version\":
\"2012-10-17\",
 \"Statement\": [
 {
 \"Effect\": \"Allow\",
 \"Action\":[

\"logs:CreateLogGroup\",
 \"logs:CreateLogStream\",
 \"logs:DescribeLogGroups\",

\"logs:DescribeLogStreams\",
 \"logs:PutLogEvents\",
 \"logs:GetLogEvents\",

\"logs:FilterLogEvents\"
 ],
 \"Resource\": \"*\"
 }
 ]
}
```
3. Run the below command
to create an IAM role:
```
aws iam create-role --role-name <aws_support_iam_role>
--assume-role-policy-document file://<file-path>role_policy_document.json

```
4. Run the below command to create an IAM policy:
```
aws iam create-policy
--policy-name <ami-policy-name> --policy-document
file://<file-path>iam-policy.json
```
5. Run `attach-group-policy` command using
the IAM policy ARN returned at the previous step to attach the policy to the IAM role (if the
command succeeds, no output is returned):
```
aws iam attach-group-policy
--policy-arn arn:aws:iam::<aws-account-id>:policy/<iam-policy-name> --group-name
<group-name>
```
6. Run `describe-vpcs` to get the VpcId available in the selected
region:
```
aws ec2 describe-vpcs --region <region>
```
7. The command output
should return the VPC Id available in the selected region.
8. Run `create-flow-logs` to
create a flow log for the vpc:
```
aws ec2 create-flow-logs --resource-type VPC
--resource-ids <vpc-id> --traffic-type REJECT --log-group-name <log-group-name>
--deliver-logs-permission-arn <iam-role-arn>
```
9. Repeat step 8 for other vpcs
available in the selected region.
10. Change the region by updating --region and repeat
remediation procedure for other vpcs. "
  desc 'impact', "By default, CloudWatch Logs will store Logs indefinitely unless a specific retention period
is defined for the log group. When choosing the number of days to retain, keep in mind the
average days it takes an organization to realize they have been breached is 210 days (at the
time of this writing). Since additional time is required to research a breach, a minimum 365
day retention policy allows time for detection and research. You may also wish to archive the
logs to a cheaper storage service rather than simply deleting them. See the following AWS
resource to manage CloudWatch Logs retention periods:

1. https://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/SettingLogRetention.html "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html'
  tag nist: %w{AU-2 AU-7 AU-12}
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['8.2'] },
  ]

  only_if('No VPCs discovered', impact: 0.0) { !aws_vpcs.vpc_ids.empty? }

  aws_vpcs.vpc_ids.each do |vpc_id|
    describe aws_flow_log(vpc_id: vpc_id) do
      it { should exist }
    end
  end
end
