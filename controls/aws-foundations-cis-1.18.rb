control 'aws-foundations-cis-1.18' do
  title 'Ensure IAM instance roles are used for AWS resource access from instances '
  desc "AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls
or by assigning the instance to a role which has an appropriate permissions policy for the
required access. \"AWS Access\" means accessing the APIs of AWS in order to access AWS resources
or manage AWS account resources. "
  desc 'rationale', "AWS IAM roles reduce the risks associated with sharing and rotating credentials that can be
used outside of AWS itself. If credentials are compromised, they can be used from outside of
the AWS account they give access to. In contrast, in order to leverage role permissions an
attacker would need to gain and maintain access to a specific instance to use the privileges
associated with it.

Additionally, if credentials are encoded into compiled
applications or other hard to change mechanisms, then they are even more unlikely to be
properly rotated due to service disruption risks. As time goes on, credentials that cannot be
rotated are more likely to be known by an increasing number of individuals who no longer work
for the organization owning the credentials. "
  desc 'check', "**From Console:**

1. Sign in to the AWS Management Console and navigate to EC2 dashboard
at `https://console.aws.amazon.com/ec2/`.
2. In the left navigation panel, choose
`Instances`.
3. Select the EC2 instance you want to examine.
4. Select `Actions`.
5.
Select `View details`.
6. Select `Security` in the lower panel.
 - If the value for
**Instance profile arn** is an instance profile ARN, then an instance profile (that contains
an IAM role) is attached.
 - If the value for **IAM Role** is blank, no role is attached.
 - If
the value for **IAM Role** contains a role
 - If the value for **IAM Role** is \"No roles
attached to instance profile: <Instance-Profile-Name>\", then an instance profile is
attached to the instance, but it does not contain an IAM role.
7. Repeat steps 3 to 6 for each
EC2 instance in your AWS account.

**From Command Line:**

1. Run the
`describe-instances` command to list all EC2 instance IDs, available in the selected AWS
region. The command output will return each instance ID:
```
aws ec2 describe-instances
--region <region-name> --query 'Reservations[*].Instances[*].InstanceId'
```
2.
Run the `describe-instances` command again for each EC2 instance using the
`IamInstanceProfile` identifier in the query filter to check if an IAM role is
attached:
```
aws ec2 describe-instances --region <region-name> --instance-id
<Instance-ID> --query 'Reservations[*].Instances[*].IamInstanceProfile'
```
3.
If an IAM role is attached, the command output will show the IAM instance profile ARN and ID.

4. Repeat steps 1 to 3 for each EC2 instance in your AWS account. "
  desc 'fix', "**From Console:**

1. Sign in to the AWS Management Console and navigate to EC2 dashboard
at `https://console.aws.amazon.com/ec2/`.
2. In the left navigation panel, choose
`Instances`.
3. Select the EC2 instance you want to modify.
4. Click `Actions`.
5.
Click `Security`.
6. Click `Modify IAM role`.
7. Click `Create new IAM role` if a new IAM
role is required.
8. Select the IAM role you want to attach to your instance in the `IAM role`
dropdown.
9. Click `Update IAM role`.
10. Repeat steps 3 to 9 for each EC2 instance in your
AWS account that requires an IAM role to be attached.

**From Command Line:**

1. Run
the `describe-instances` command to list all EC2 instance IDs, available in the selected AWS
region:
```
aws ec2 describe-instances --region <region-name> --query
'Reservations[*].Instances[*].InstanceId'
```
2. Run the
`associate-iam-instance-profile` command to attach an instance profile (which is
attached to an IAM role) to the EC2 instance:
```
aws ec2
associate-iam-instance-profile --region <region-name> --instance-id <Instance-ID>
--iam-instance-profile Name=\"Instance-Profile-Name\"
```
3. Run the
`describe-instances` command again for the recently modified EC2 instance. The command
output should return the instance profile ARN and ID:
```
aws ec2 describe-instances
--region <region-name> --instance-id <Instance-ID> --query
'Reservations[*].Instances[*].IamInstanceProfile'
```
4. Repeat steps 1 to 3 for
each EC2 instance in your AWS account that requires an IAM role to be attached. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html:https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html'
  tag nist: ['AC-2']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['6.8'] },
  ]

  only_if('Not Applicable - No EC2s discovered', impact: 0.0) { aws_ec2_instances.exist? }

  ec2_instances_with_no_role = aws_ec2_instances.where { !iam_profile.present? }

  fail_message = "EC2 Instances with no role:\n\t- #{ec2_instances_with_no_role.instance_ids.join("\n\t- ")}"

  describe 'EC2 Instances' do
    it 'should all have an attached role' do
      expect(ec2_instances_with_no_role.entries).to be_empty, fail_message
    end
  end
end
