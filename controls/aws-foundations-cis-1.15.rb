control 'aws-foundations-cis-1.15' do
  title 'Ensure IAM Users Receive Permissions Only Through Groups '
  desc "IAM users are granted access to services, functions, and data through IAM policies. There are
four ways to define policies for a user: 1) Edit the user policy directly, aka an inline, or
user, policy; 2) attach a policy directly to a user; 3) add the user to an IAM group that has an
attached policy; 4) add the user to an IAM group that has an inline policy.

Only the third
implementation is recommended. "
  desc 'rationale', "Assigning IAM policy only through groups unifies permissions management to a single,
flexible layer consistent with organizational functional roles. By unifying permissions
management, the likelihood of excessive permissions is reduced. "
  desc 'check', "Perform the following to determine if an inline policy is set or a policy is directly attached
to users:

1. Run the following to get a list of IAM users:
```
 aws iam list-users
--query 'Users[*].UserName' --output text
```
2. For each user returned, run the
following command to determine if any policies are attached to them:
```
 aws iam
list-attached-user-policies --user-name <iam_user>
 aws iam list-user-policies
--user-name <iam_user>
```
3. If any policies are returned, the user has an inline policy
or direct policy attachment. "
  desc 'fix', "Perform the following to create an IAM group and assign a policy to it:

1. Sign in to the AWS
Management Console and open the IAM console at
[https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
2.
In the navigation pane, click `Groups` and then click `Create New Group` .
3. In the `Group
Name` box, type the name of the group and then click `Next Step` .
4. In the list of policies,
select the check box for each policy that you want to apply to all members of the group. Then
click `Next Step` .
5. Click `Create Group`

Perform the following to add a user to a given
group:

1. Sign in to the AWS Management Console and open the IAM console at
[https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
2.
In the navigation pane, click `Groups`
3. Select the group to add a user to
4. Click `Add
Users To Group`
5. Select the users to be added to the group
6. Click `Add Users`


Perform the following to remove a direct association between a user and policy:

1.
Sign in to the AWS Management Console and open the IAM console at
[https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
2.
In the left navigation pane, click on Users
3. For each user:
 - Select the user
 - Click on
the `Permissions` tab
 - Expand `Permissions policies`
 - Click `X` for each policy; then
click Detach or Remove (depending on policy type) "
  impact 0.5
  ref 'http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html:http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
  tag nist: ['AC-6']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['6.8'] },
  ]

  if aws_iam_users.entries.empty?
    describe 'Control skipped because no iam users were found' do
      skip 'This control is skipped since the aws_iam_users resource returned an empty user list'
    end
  else
    aws_iam_users.entries.each do |user|
      describe aws_iam_user(user_name: user.username) do
        its('inline_policy_names') { should be_empty }
        its('attached_policy_names') { should be_empty }
      end
    end
  end
end
