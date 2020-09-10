# encoding: UTF-8

control "aws-foundations-cis-1.16" do
  title "Ensure IAM policies are attached only to groups or roles"
  desc  "By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended that IAM policies be applied directly to groups and roles but not users."
  desc  "rationale", "Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity may in-turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges."
  desc  "check", "Perform the following to determine if policies are attached directly to users:

    1. Run the following to get a list of IAM users:
    ```
     aws iam list-users --query 'Users[*].UserName' --output text
    ```
    2. For each user returned, run the following command to determine if any policies are attached to them:
    ```
     aws iam list-attached-user-policies --user-name
     aws iam list-user-policies --user-name
    ```
    3. If any policies are returned, the user has a direct policy attachment."
  desc  "fix", "Perform the following to create an IAM group and assign a policy to it:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
    2. In the navigation pane, click `Groups` and then click `Create New Group`.
    3. In the `Group Name` box, type the name of the group and then click `Next Step` .
    4. In the list of policies, select the check box for each policy that you want to apply to all members of the group. Then click `Next Step` .
    5. Click `Create Group`

    Perform the following to add a user to a given group:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
    2. In the navigation pane, click `Groups`
    3. Select the group to add a user to
    4. Click `Add Users To Group`
    5. Select the users to be added to the group
    6. Click `Add Users`

    Perform the following to remove a direct association between a user and policy:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
    2. In the left navigation pane, click on Users
    3. For each user:
     1. Select the user
     2. Click on the `Permissions` tab
     3. Expand `Managed Policies`
     4. Click `Detach Policy` for each policy
     5. Expand `Inline Policies`
     6. Click `Remove Policy` for each policy"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-2']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Account Monitoring and Control CONTROL:16 DESCRIPTION:Account Monitoring and Control;"
  tag ref: "http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html:http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"


  if aws_iam_users.entries.empty?
    describe 'Control skipped because no iam users were found' do
      skip 'This control is skipped since the aws_iam_users resource returned an empty user list'
    end
  else
    aws_iam_users.entries.each do |user|
      describe aws_iam_user(user_name: user.username) do
        its ('inline_policy_names') { should be_empty }
        its ('attached_policy_names') { should be_empty }
      end
    end
  end
end
