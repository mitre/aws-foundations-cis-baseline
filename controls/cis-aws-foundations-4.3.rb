control "cis-aws-foundations-4.3" do
  title "Ensure VPC flow logging is enabled in all VPCs"
  desc  "VPC Flow Logs is a feature that enables you to capture information
about the IP traffic going to and from network interfaces in your VPC. After
you've created a flow log, you can view and retrieve its data in Amazon
CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet
'Rejects' for VPCs."
  impact 0.7
  tag "rationale": "VPC Flow Logs provide visibility into network traffic that
traverses the VPC and can be used to detect anomalous traffic or insight during
security workflows."
  tag "cis_impact": "By default, CloudWatch Logs will store Logs indefinitely
unless a specific retention period is defined for the log group. When choosing
the number of days to retain, keep in mind the average days it takes an
organization to realize they have been breached is 210 days (at the time of
this writing). Since additional time is required to research a breach, a
minimum 365 day retention policy allows time for detection and research. You
may also wish to archive the logs to a cheaper storage service rather than
simply deleting them. See the following AWS resource to manage CloudWatch Logs
retention periods:

*
http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/SettingLogRetention.html"
  tag "cis_rid": "4.3"
  tag "cis_level": 2
  tag "cis_control_number": ""
  tag "nist": ["SI-4(4)", "Rev_4"]
  tag "cce_id": "CCE-79202-8"
  tag "check": "Perform the following to determine if VPC Flow logs is enabled:


'Via the Management Console:

* Sign into the management console
* Select Services then VPC
* In the left navigation pane, select Your VPCs
* Select a VPC
* In the right pane, select the Flow Logs tab.
* Ensure a Log Flow exists that has Active in the Status column."
  tag "fix": "Perform the following to determine if VPC Flow logs is enabled:

'Via the Management Console:

* Sign into the management console
* Select Services then VPC
* In the left navigation pane, select Your VPCs
* Select a VPC
* In the right pane, select the Flow Logs tab.
* If no Flow Log exists, click Create Flow Log
* For Filter, select Reject
* Enter in a Role and Destination Log Group
* Click Create Log Flow
* Click on CloudWatch Logs Group

'NOTE: Setting the filter to 'Reject' will dramatically reduce the logging data
accumulation for this recommendation and provide sufficient information for the
purposes of breach detection, research and remediation. However, during periods
of least privilege security group engineering, setting this the filter to 'All'
can be very helpful in discovering existing traffic flows required for proper
operation of an already running environment.

'
"
  aws_vpcs.vpc_ids.each do |vpc|
    describe aws_vpc(vpc) do
      it { should be_flow_logs_enabled }
    end
    describe.one do
      aws_vpc(vpc).flow_logs.each do |flow_log|
        describe "flow log settings" do
          subject { flow_log }
          its('traffic_type') { should cmp 'REJECT' }
        end
      end
    end
  end
  describe "Control skipped because no vpcs were found" do
    skip "This control is skipped since the aws_vpcs resource returned an empty vpc list"
  end if aws_vpcs.vpc_ids.empty?
end
