control 'aws-foundations-cis-5.1' do
  title 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports '
  desc "The Network Access Control List (NACL) function provide stateless filtering of ingress and
egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted
ingress access to remote server administration ports, such as SSH to port `22` and RDP to port
`3389`, using either the TDP (6), UDP (17) or ALL (-1) protocols "
  desc 'rationale',
       "Public access to remote server administration ports, such as 22 and 3389, increases resource
attack surface and unnecessarily raises the risk of resource compromise. "
  desc 'check',
       "**From Console:**

Perform the following to determine if the account is configured as
prescribed:
1. Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
2. In the left pane, click `Network ACLs`
3.
For each network ACL, perform the following:
 - Select the network ACL
 - Click the `Inbound
Rules` tab
 - Ensure no rule exists that has a port range that includes port `22`, `3389`,
using the protocols TDP (6), UDP (17) or ALL (-1) or other remote server administration ports
for your environment and has a `Source` of `0.0.0.0/0` and shows `ALLOW`

**Note:** A Port
value of `ALL` or a port range such as `0-1024` are inclusive of port `22`, `3389`, and other
remote server administration ports "
  desc 'fix',
       "**From Console:**

Perform the following:
1. Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
2. In the left pane, click `Network ACLs`
3.
For each network ACL to remediate, perform the following:
 - Select the network ACL
 - Click
the `Inbound Rules` tab
 - Click `Edit inbound rules`
 - Either A) update the Source field to
a range other than 0.0.0.0/0, or, B) Click `Delete` to remove the offending inbound rule
 -
Click `Save` "
  impact 0.5
  ref 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html:https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html#VPC_Security_Comparison'
  tag nist: ['CM-7(1)']
  tag severity: 'medium '
  tag cis_controls: [{ '7' => ['9.2'] }]

  only_if('This control takes a long time to run, excluding due to "disable_slow_controls"') { !input('disable_slow_controls') }

  active_ports = input('remote_management_port_ranges') - input('exempt_ports')
  active_protocols = input('remote_management_protocols') - input('exempt_protocols')
  acls = aws_network_acls.where { entries_cidr_blocks.include?('0.0.0.0/0') }.network_acl_ids - input('exempt_acl_ids')

  only_if('No non-exempt network ACLs with a 0.0.0.0/0 CIDR block entry were discovered', impact: 0.0) { !acls.empty? }

  acls.each do |network_acl_id|
    acl = aws_network_acl(network_acl_id: network_acl_id).acls
    active_ports.each do |pr|
      describe acl.where { cidr_block == '0.0.0.0/0' && rule_action == 'allow' && port_range == pr } do
        it { should_not exist }
      end
    end
    active_protocols.each do |p|
      describe acl.where { cidr_block == '0.0.0.0/0' && rule_action == 'allow' && protocol == p } do
        it { should_not exist }
      end
    end
  end
end
