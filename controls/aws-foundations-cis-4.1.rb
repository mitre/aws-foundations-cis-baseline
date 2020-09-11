# encoding: UTF-8

control "aws-foundations-cis-4.1" do
  title "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
  desc  "Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port `22` ."
  desc  "rationale", "Removing unfettered connectivity to remote console services, such as SSH, reduces a server's exposure to risk."
  desc  "check", "Perform the following to determine if the account is configured as prescribed:

    1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
    2. In the left pane, click `Security Groups`
    3. For each security group, perform the following:
    1. Select the security group
    2. Click the `Inbound Rules` tab
    3. Ensure no rule exists that has a port range that includes port `22` and has a `Source` of `0.0.0.0/0`

    Note: A Port value of `ALL` or a port range such as `0-1024` are inclusive of port `22` ."
  desc  "fix", "Perform the following to implement the prescribed state:

    1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
    2. In the left pane, click `Security Groups`
    3. For each security group, perform the following:
    1. Select the security group
    2. Click the `Inbound Rules` tab
    3. Identify the rules to be removed
    4. Click the `x` in the `Remove` column
    5. Click `Save`"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['CM-7(1)']
  tag notes: nil
  tag comment: "For updating an existing environment, care should be taken to ensure that administrators currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or 3389 through another security group."
  tag cis_controls: "TITLE:Ensure Only Approved Ports, Protocols and Services Are Running CONTROL:9.2 DESCRIPTION:Ensure that only network ports, protocols, and services listening on a system with validated business needs, are running on each system.;"


  exception_security_group_list = input('exception_security_group_list')

  aws_security_groups.group_ids.each do |group_id|
    if exception_security_group_list.include?(group_id)
      describe 'Security Group not inspected because it is defined as an exception' do
        skip "Security Group:: #{group_id} not inspected because it is defined in exception_security_group_list."
      end
    end

    next if exception_security_group_list.include?(group_id)

    describe aws_security_group(group_id) do
      it { should_not allow_in(port: 22, ipv4_range: '0.0.0.0/0') }
    end
  end
end