# encoding: UTF-8

control "aws-foundations-cis-5.2" do
  title "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration 
ports "
  desc "Security groups provide stateful filtering of ingress and egress network traffic to AWS 
resources. It is recommended that no security group allows unrestricted ingress access to 
remote server administration ports, such as SSH to port `22` and RDP to port `3389`, using 
either the TDP (6), UDP (17) or ALL (-1) protocols "
  desc "rationale", "Public access to remote server administration ports, such as 22 and 3389, increases resource 
attack surface and unnecessarily raises the risk of resource compromise. "
  desc "check", "Perform the following to determine if the account is configured as prescribed:

1. Login 
to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
2. 
In the left pane, click `Security Groups` 
3. For each security group, perform the 
following:
1. Select the security group
2. Click the `Inbound Rules` tab
3. Ensure no 
rule exists that has a port range that includes port `22`, `3389`, using the protocols TDP (6), 
UDP (17) or ALL (-1) or other remote server administration ports for your environment and has a 
`Source` of `0.0.0.0/0` 

**Note:** A Port value of `ALL` or a port range such as `0-1024` 
are inclusive of port `22`, `3389`, and other remote server administration ports. "
  desc "fix", "Perform the following to implement the prescribed state:

1. Login to the AWS Management 
Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
2. 
In the left pane, click `Security Groups` 
3. For each security group, perform the 
following:
1. Select the security group
2. Click the `Inbound Rules` tab
3. Click the 
`Edit inbound rules` button
4. Identify the rules to be edited or removed
5. Either A) 
update the Source field to a range other than 0.0.0.0/0, or, B) Click `Delete` to remove the 
offending inbound rule
6. Click `Save rules` "
  desc "impact", "When updating an existing environment, ensure that administrators have access to remote 
server administration ports through another mechanism before removing access by deleting 
the 0.0.0.0/0 inbound rule. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html#deleting-security-group-rule'
  tag nist: []
  tag severity: "medium "
  tag cis_controls: [
    {"7" => ["9.2"]}
  ]
end