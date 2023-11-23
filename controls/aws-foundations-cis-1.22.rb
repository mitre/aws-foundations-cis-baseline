control 'aws-foundations-cis-1.22' do
  title 'Ensure access to AWSCloudShellFullAccess is restricted '
  desc "AWS CloudShell is a convenient way of running CLI commands against AWS services; a managed IAM
policy ('AWSCloudShellFullAccess') provides full access to CloudShell, which allows file
upload and download capability between a user's local system and the CloudShell
environment. Within the CloudShell environment a user has sudo permissions, and can access
the internet. So it is feasible to install file transfer software (for example) and move data
from CloudShell to external internet servers. "
  desc 'rationale',
       "Access to this policy should be restricted as it presents a potential channel for data
exfiltration by malicious cloud admins that are given full permissions to the service. AWS
documentation describes how to create a more restrictive IAM policy which denies file
transfer permissions. "
  desc 'check',
       "**From Console**
1. Open the IAM console at https://console.aws.amazon.com/iam/
2. In
the left pane, select Policies
3. Search for and select AWSCloudShellFullAccess
4. On
the Entities attached tab, ensure that there are no entities using this policy

**From
Command Line**
1. List IAM policies, filter for the 'AWSCloudShellFullAccess' managed
policy, and note the \"Arn\" element value:
```
aws iam list-policies --query
\"Policies[?PolicyName == 'AWSCloudShellFullAccess']\"
```
2. Check if the
'AWSCloudShellFullAccess' policy is attached to any role:
```
aws iam
list-entities-for-policy --policy-arn
arn:aws:iam::aws:policy/AWSCloudShellFullAccess
```
3. In Output, Ensure
PolicyRoles returns empty. 'Example: Example: PolicyRoles: [ ]'

If it does not return
empty refer to the remediation below.

Note: Keep in mind that other policies may grant
access. "
  desc 'fix',
       "**From Console**
1. Open the IAM console at https://console.aws.amazon.com/iam/
2. In
the left pane, select Policies
3. Search for and select AWSCloudShellFullAccess
4. On
the Entities attached tab, for each item, check the box and select Detach "
  impact 0.5
  ref 'https://docs.aws.amazon.com/cloudshell/latest/userguide/sec-auth-with-identities.html'
  tag nist: ['AC-6']
  tag severity: 'medium '

  describe aws_iam_policy(policy_name: 'AWSCloudShellFullAccess') do
    its('attached_roles') { should be_empty }
  end
end
