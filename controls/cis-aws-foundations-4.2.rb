control "cis-aws-foundations-4.2" do
  title "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
  desc  "Security groups provide stateful filtering of ingress/egress network
traffic to AWS resources. It is recommended that no security group allows
unrestricted ingress access to port 3389."
  impact 0.5
  tag "rationale": "Removing unfettered connectivity to remote console
services, such as RDP, reduces a server's exposure to risk."
  tag "cis_impact": "For updating an existing environment, care should be taken
to ensure that administrators currently relying on an existing ingress from
0.0.0.0/0 have access to ports 22 and/or 3389 through another security group."
  tag "cis_rid": "4.2"
  tag "cis_level": 1
  tag "cis_control_number": ""
  tag "nist": ""
  tag "cce_id": ""
  tag "check": "Perform the following to determine if the account is configured
as prescribed:

* Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
[https://console.aws.amazon.com/vpc/home]
* In the left pane, click Security Groups
* For each security group, perform the following:

* Select the security group
* Click the Inbound Rules tab
* Ensure no rule exists that has a port range that includes port 3389 and has a
Source of 0.0.0.0/0

Note: A Port value of ALL or a port range such as 1024-4098 are inclusive of
port 3389.
"
  tag "fix": "Perform the following to implement the prescribed state:

* Login to the AWS Management Console at
https://console.aws.amazon.com/vpc/home
[https://console.aws.amazon.com/vpc/home]
* In the left pane, click Security Groups
* For each security group, perform the following:

* Select the security group
* Click the Inbound Rules tab
* Identify the rules to be removed
* Click the x in the Remove column
* Click Save"
end
