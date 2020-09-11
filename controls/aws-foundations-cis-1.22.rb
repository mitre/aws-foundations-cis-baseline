# encoding: UTF-8

control "aws-foundations-cis-1.22" do
  title "Ensure IAM policies that allow full \"*:*\" administrative privileges are not created"
  desc  "IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant _least privilege_ that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform _only_ those tasks, instead of allowing full administrative privileges."
  desc  "rationale", "It's more secure to start with a minimum set of permissions and grant additional permissions as necessary, rather than starting with permissions that are too lenient and then trying to tighten them later.

    Providing full administrative privileges instead of restricting to the minimum set of permissions that the user is required to do exposes the resources to potentially unwanted actions.

    IAM policies that have a statement with \"Effect\": \"Allow\" with \"Action\": \"\\*\" over \"Resource\": \"\\*\" should be removed."
  desc  "check", "Perform the following to determine what policies are created:

    1. Run the following to get a list of IAM policies:
    ```
     aws iam list-policies --output text
    ```
    2. For each policy returned, run the following command to determine if any policies is allowing full administrative privileges on the account:
    ```
     aws iam get-policy-version --policy-arn
    \t --version-id
    ```
    3. In output ensure policy should not have any Statement block with `\"Effect\": \"Allow\"` and `Action` set to `\"*\"` and `Resource` set to `\"*\"`"
  desc  "fix", "Using the GUI, perform the following to detach the policy that has full administrative privileges:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
    2. In the navigation pane, click Policies and then search for the policy name found in the audit step.
    3. Select the policy that needs to be deleted.
    4. In the policy action menu, select first `Detach`
    5. Select all Users, Groups, Roles that have this policy attached
    6. Click `Detach Policy`
    7. In the policy action menu, select `Detach`

    Using the CLI, perform the following to detach the policy that has full administrative privileges as found in the audit step:

    1\\. Lists all IAM users, groups, and roles that the specified managed policy is attached to.
    ```
     aws iam list-entities-for-policy --policy-arn
    ```
    2\\. Detach the policy from all IAM Users:
    ```
     aws iam detach-user-policy --user-name  --policy-arn
    ```
    3\\. Detach the policy from all IAM Groups:
    ```
     aws iam detach-group-policy --group-name  --policy-arn
    ```
    4\\. Detach the policy from all IAM Roles:
    ```
     aws iam detach-role-policy --role-name  --policy-arn
    ```"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-6']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Controlled Use of Administrative Privileges CONTROL:4 DESCRIPTION:Controlled Use of Administrative Privileges;"
  tag ref: "http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html:http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html:http://docs.aws.amazon.com/cli/latest/reference/iam/index.html#cli-aws-iam"
  
  
  attached_policies = aws_iam_policies.where { attachment_count > 0 }.policy_names
  
  if attached_policies.empty? == true
    impact 0.0
    describe 'Control not applicable since no attached iam policies were detected' do
      skip 'Not applicable since no policies are detected as attached to anything within this account.'
    end
  else
    attached_policies.each do |policy|
      describe "Attached Policies #{policy} allows full '*:*' privileges?" do
        subject do
          aws_iam_policy(policy).document.where(Effect: 'Allow').actions.flatten.include?('*') &&
            aws_iam_policy(policy).document.where(Effect: 'Allow').resources.flatten.include?('*')
        end
        it { should be false }
      end
    end
  end
end