control 'aws-foundations-cis-4.16' do
  title 'Ensure AWS Security Hub is enabled '
  desc "Security Hub collects security data from across AWS accounts, services, and supported
third-party partner products and helps you analyze your security trends and identify the
highest priority security issues. When you enable Security Hub, it begins to consume,
aggregate, organize, and prioritize findings from AWS services that you have enabled, such
as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations
with AWS partner security products. "
  desc 'rationale',
       "AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps
you check your environment against security industry standards and best practices -
enabling you to quickly assess the security posture across your AWS accounts. "
  desc 'check',
       "The process to evaluate AWS Security Hub configuration per region

**From
Console:**

1. Sign in to the AWS Management Console and open the AWS Security Hub console
at https://console.aws.amazon.com/securityhub/.
2. On the top right of the console,
select the target Region.
3. If presented with the Security Hub > Summary page then Security
Hub is set-up for the selected region.
4. If presented with Setup Security Hub or Get Started
With Security Hub - follow the online instructions.
5. Repeat steps 2 to 4 for each
region.

**From Command Line:**

Run the following to list the Securityhub
status:
```
aws securityhub describe-hub
```
This will list the Securityhub status
by region. Audit for the presence of a 'SubscribedAt' value

Example output:
```
{

\"HubArn\": \"<Securityhub ARN>\",
 \"SubscribedAt\": \"2022-08-19T17:06:42.398Z\",

\"AutoEnableControls\": true
}
```
An error will be returned if Securityhub is not
enabled.

Example error:
```
An error occurred (InvalidAccessException) when
calling the DescribeHub operation: Account <Account ID> is not subscribed to AWS Security
Hub
``` "
  desc 'fix',
       "To grant the permissions required to enable Security Hub, attach the Security Hub managed
policy AWSSecurityHubFullAccess to an IAM user, group, or role.

Enabling Security
Hub

**From Console:**

1. Use the credentials of the IAM identity to sign in to the
Security Hub console.
2. When you open the Security Hub console for the first time, choose
Enable AWS Security Hub.
3. On the welcome page, Security standards list the security
standards that Security Hub supports.
4. Choose Enable Security Hub.

**From Command
Line:**

1. Run the enable-security-hub command. To enable the default standards,
include `--enable-default-standards`.
```
aws securityhub enable-security-hub
--enable-default-standards
```

2. To enable the security hub without the default
standards, include `--no-enable-default-standards`.
```
aws securityhub
enable-security-hub --no-enable-default-standards
``` "
  desc 'impact',
       "It is recommended AWS Security Hub be enabled in all regions. AWS Security Hub requires AWS
Config to be enabled. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-get-started.html:https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html#securityhub-enable-api:https://awscli.amazonaws.com/v2/documentation/api/latest/reference/securityhub/enable-security-hub.html'
  tag nist: ['CM-6(1)']
  tag severity: 'medium '
  tag cis_controls: [{ '7' => ['11.3'] }]

  describe 'No Tests Defined Yet' do
    skip 'No Tests have been written for this control yet'
  end
end
