control 'cis-aws-foundations-4.4' do
  title 'Ensure the default security group of every VPC restricts all traffic'
  desc  "A VPC comes with a default security group whose initial settings deny
all inbound traffic, allow all outbound traffic, and allow all traffic between
instances assigned to the security group. If you don't specify a security group
when you launch an instance, the instance is automatically assigned to this
default security group. Security groups provide stateful filtering of
ingress/egress network traffic to AWS resources. It is recommended that the
default security group restrict all traffic.

'The default VPC in every region should have it's default security group
updated to comply. Any newly created VPCs will automatically contain a default
security group that will need remediation to comply with this recommendation.

'NOTE: When implementing this recommendation, VPC flow logging is invaluable in
determining the least privilege port access required by systems to work
properly because it can log all packet acceptances and rejections occurring
under the current security groups. This dramatically reduces the primary
barrier to least privilege engineering - discovering the minimum ports required
by systems in the environment. Even if the VPC flow logging recommendation in
this benchmark is not adopted as a permanent security measure, it should be
used during any period of discovery and engineering for least privileged
security groups."
  impact 0.7
  tag "rationale": "Configuring all VPC default security groups to restrict all
traffic will encourage least privilege security group development and mindful
placement of AWS resources into security groups which will in-turn reduce the
exposure of those resources."
  tag "cis_impact": "Implementing this recommendation in an existing VPC
containing operating resources requires extremely careful migration planning as
the default security groups are likely to be enabling many ports that are
unknown. Enabling VPC flow logging (of accepts) in an existing environment that
is know to be breach free will reveal the current pattern of ports being used
for each instance to communicate successfully."
  tag "cis_rid": '4.4'
  tag "cis_level": 2
  tag "csc_control": [['9.2'], '6.0']
  tag "nist": ['SC-7(5)', 'Rev_4']
  tag "cce_id": 'CCE-79201-0'
  tag "check": "Perform the following to determine if the account is configured
as prescribed:

'Security Group State

* Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
[https://console.aws.amazon.com/vpc/home]
* Repeat the next steps for all VPCs - including the default VPC in each AWS
region:
* In the left pane, click Security Groups
* For each default security group, perform the following:

* Select the default security group
* Click the Inbound Rules tab
* Ensure no rule exist
* Click the Outbound Rules tab
* Ensure no rules exist

'Security Group Members

* Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
[https://console.aws.amazon.com/vpc/home]
* Repeat the next steps for all default groups in all VPCs - including the
default VPC in each AWS region:
* In the left pane, click Security Groups
* Copy the id of the default security group.
* Change to the EC2 Management Console at
https://console.aws.amazon.com/ec2/v2/home
* In the filter column type 'Security Group ID : <security group id from #4>'"
  tag "fix": "Security Group Members

'Perform the following to implement the prescribed state:

* Identify AWS resources that exist within the default security group
* Create a set of least privilege security groups for those resources
* Place the resources in those security groups
* Remove the resources noted in #1 from the default security group

'Security Group State

* Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
[https://console.aws.amazon.com/vpc/home]
* Repeat the next steps for all VPCs - including the default VPC in each AWS
region:
* In the left pane, click Security Groups
* For each default security group, perform the following:

* Select the default security group
* Click the Inbound Rules tab
* Remove any inbound rules
* Click the Outbound Rules tab
* Remove any inbound rules

'Recommended:

'IAM groups allow you to edit the 'name' field. After remediating default
groups rules for all VPCs in all regions, edit this field to add text similar
to 'DO NOT USE. DO NOT ADD RULES'"

  aws_vpcs.vpc_ids.each do |vpc|
    describe aws_security_group(group_name: 'default', vpc_id: vpc) do
      its('inbound_rules') { should be_empty }
      its('outbound_rules') { should be_empty }
    end
  end
  if aws_vpcs.vpc_ids.empty?
    describe 'Control skipped because no vpcs were found' do
      skip 'This control is skipped since the aws_vpcs resource returned an empty vpc list'
    end
  end
end
