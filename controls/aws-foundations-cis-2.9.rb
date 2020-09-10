# encoding: UTF-8

control "aws-foundations-cis-2.9" do
  title "Ensure VPC flow logging is enabled in all VPCs"
  desc  "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet \"Rejects\" for VPCs."
  desc  "rationale", "VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows."
  desc  "check", "Perform the following to determine if VPC Flow logs is enabled:

    Via the Management Console:
    1. Sign into the management console
    2. Select `Services` then `VPC`
    3. In the left navigation pane, select `Your VPCs`
    4. Select a VPC
    5. In the right pane, select the `Flow Logs` tab.
    6. Ensure a Log Flow exists that has `Active` in the `Status` column."
  desc  "fix", "Perform the following to determine if VPC Flow logs is enabled:

    Via the Management Console:
    1. Sign into the management console
    2. Select `Services` then `VPC`
    3. In the left navigation pane, select `Your VPCs`
    4. Select a VPC
    5. In the right pane, select the `Flow Logs` tab.
    6. If no Flow Log exists, click `Create Flow Log`
    7. `For` Filter, select Reject
    8. Enter in a `Role` and `Destination Log Group`
    9. Click `Create Log Flow`
    10. Click on `CloudWatch Logs Group`

    **Note:** Setting the filter to \"Reject\" will dramatically reduce the logging data accumulation for this recommendation and provide sufficient information for the purposes of breach detection, research and remediation. However, during periods of least privilege security group engineering, setting this the filter to \"All\" can be very helpful in discovering existing traffic flows required for proper operation of an already running environment."
  impact 0.5
  tag severity: "Medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['SI-4(2)', 'AU-12']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Configure Monitoring Systems to Record Network Packets CONTROL:12.5 DESCRIPTION:Configure monitoring systems to record network packets passing through the boundary at each of the organization's network boundaries.;TITLE:Activate audit logging CONTROL:6.2 DESCRIPTION:Ensure that local logging has been enabled on all systems and networking devices.;"
  tag ref: "CIS CSC v6.0 #6.5, #12.9:http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html"

  
  aws_vpcs.vpc_ids.each do |vpc|
    describe aws_vpc(vpc) do
      it { should be_flow_logs_enabled }
    end
    describe.one do
      aws_vpc(vpc).flow_logs.each do |flow_log|
        describe 'flow log settings' do
          subject { flow_log }
          its('flow_log_status') { should cmp 'ACTIVE' }
        end
      end
    end
  end
  if aws_vpcs.vpc_ids.empty?
    describe 'Control skipped because no vpcs were found' do
      skip 'This control is skipped since the aws_vpcs resource returned an empty vpc list'
    end
  end
end