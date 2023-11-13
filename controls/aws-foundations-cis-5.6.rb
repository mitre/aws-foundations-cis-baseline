control "aws-foundations-cis-5.6" do
  title "Ensure that EC2 Metadata Service only allows IMDSv2 "
  desc "When enabling the Metadata Service on AWS EC2 instances, users have the option of using either
Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance
Metadata Service Version 2 (IMDSv2; a session-oriented method). "
  desc "rationale",
       "Allowing Version 1 of the service may open EC2 instances to Server-Side Request Forgery
(SSRF) attacks, so Amazon recommends utilizing Version 2 for better instance security. "
  desc "check",
       "From Console:
1. Login to AWS Management Console and open the Amazon EC2 console using
https://console.aws.amazon.com/ec2/
2. Under the Instances menu, select
Instances.
3. For each Instance, select the instance, then choose Actions > Modify
instance metadata options.
4. If the Instance metadata service is enabled, verify whether
IMDSv2 is set to required.

From Command Line:
1. Use the describe-instances CLI
command
2. Ensure for all ec2 instances that the metadata-options.http-tokens setting is
set to required.
3. Repeat for all active regions.
```
aws ec2 describe-instances
--filters \"Name=metadata-options.http-tokens\",\"Values=optional\"
\"Name=metadata-options.state\",\"Values=applied\" --query
\"Reservations[*].Instances[*].\"
``` "
  desc "fix",
       "From Console:
1. Login to AWS Management Console and open the Amazon EC2 console using
https://console.aws.amazon.com/ec2/
2. Under the Instances menu, select
Instances.
3. For each Instance, select the instance, then choose Actions > Modify
instance metadata options.
4. If the Instance metadata service is enabled, set IMDSv2 to
Required.

From Command Line:
```
aws ec2 modify-instance-metadata-options
--instance-id <instance_id> --http-tokens required
``` "
  impact 0.5
  ref "https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/:https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html"
  tag nist: %w(SI-10 SC-8)
  tag severity: "medium "

  describe "No Tests Defined Yet" do
    skip "No Tests have been written for this control yet"
  end
end
