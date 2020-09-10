# encoding: UTF-8

control "aws-foundations-cis-4.3" do
  title "Ensure the default security group of every VPC restricts all traffic"
  desc  "A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group when you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic.

    The default VPC in every region should have its default security group updated to comply. Any newly created VPCs will automatically contain a default security group that will need remediation to comply with this recommendation.

    **NOTE:** When implementing this recommendation, VPC flow logging is invaluable in determining the least privilege port access required by systems to work properly because it can log all packet acceptances and rejections occurring under the current security groups. This dramatically reduces the primary barrier to least privilege engineering - discovering the minimum ports required by systems in the environment. Even if the VPC flow logging recommendation in this benchmark is not adopted as a permanent security measure, it should be used during any period of discovery and engineering for least privileged security groups."
  desc  "rationale", "Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources."
  desc  "check", "Perform the following to determine if the account is configured as prescribed:

    Security Group State

    1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
    2. Repeat the next steps for all VPCs - including the default VPC in each AWS region:
    3. In the left pane, click `Security Groups`
    4. For each default security group, perform the following:
    1. Select the `default` security group
    2. Click the `Inbound Rules` tab
    3. Ensure no rule exist
    4. Click the `Outbound Rules` tab
    5. Ensure no rules exist

    Security Group Members

    1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
    2. Repeat the next steps for all default groups in all VPCs - including the default VPC in each AWS region:
    3. In the left pane, click `Security Groups`
    4. Copy the id of the default security group.
    5. Change to the EC2 Management Console at https://console.aws.amazon.com/ec2/v2/home
    6. In the filter column type 'Security Group ID : < security group id from #4 >'"
  desc  "fix", "Security Group Members

    Perform the following to implement the prescribed state:

    1. Identify AWS resources that exist within the default security group
    2. Create a set of least privilege security groups for those resources
    3. Place the resources in those security groups
    4. Remove the resources noted in #1 from the default security group

    Security Group State

    1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
    2. Repeat the next steps for all VPCs - including the default VPC in each AWS region:
    3. In the left pane, click `Security Groups`
    4. For each default security group, perform the following:
    1. Select the `default` security group
    2. Click the `Inbound Rules` tab
    3. Remove any inbound rules
    4. Click the `Outbound Rules` tab
    5. Remove any inbound rules

    Recommended:

    IAM groups allow you to edit the \"name\" field. After remediating default groups rules for all VPCs in all regions, edit this field to add text similar to \"DO NOT USE. DO NOT ADD RULES\""
  impact 0.5
  tag severity: "Medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-3 (3)']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Protect Information through Access Control Lists CONTROL:14.6 DESCRIPTION:Protect all information stored on systems with file system, network share, claims, application, or database specific access control lists. These controls will enforce the principle that only authorized individuals should have access to the information based on their need to access the information as a part of their responsibilities.;"
  tag ref: "http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html:CIS CSC v6.0 #9.2"

  
  if aws_vpcs.vpc_ids.empty?
    describe 'Control skipped because no vpcs were found' do
      skip 'This control is skipped since the aws_vpcs resource returned an empty vpc list'
    end
  else
    aws_vpcs.vpc_ids.each do |vpc|
      describe aws_security_group(group_name: 'default', vpc_id: vpc) do
        its('inbound_rules') { should be_empty }
        its('outbound_rules') { should be_empty }
      end
    end
  end
end