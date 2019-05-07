control 'cis-aws-foundations-1.24' do
  title "Ensure IAM policies that allow full '*:*' administrative privileges
are not created"
  desc  "IAM policies are the means by which privileges are granted to users,
groups, or roles. It is recommended and considered a standard security advice
to grant _least privilege_--that is, granting only the permissions required to
perform a task. Determine what users need to do and then craft policies for
them that let the users perform _only_ those tasks, instead of allowing full
administrative privileges."
  impact 0.3
  tag "rationale": "It's more secure to start with a minimum set of permissions
and grant additional permissions as necessary, rather than starting with
permissions that are too lenient and then trying to tighten them later.

'Providing full administrative privileges instead of restricting to the minimum
set of permissions that the user is required to do exposes the resources to
potentially unwanted actions.

'IAM policies that have a statement with 'Effect': 'Allow' with 'Action': '*'
over  'Resource': '*' should be removed."
  tag "cis_impact": ''
  tag "cis_rid": '1.24'
  tag "cis_level": 1
  tag "severity": 'low'
  tag "csc_control": ''
  tag "nist": ['AC-6', 'Rev_4']
  tag "cce_id": 'CCE-78912-3'
  tag "check": "Perform the following to determine what policies are created:

* Run the following to get a list of IAM policies:

'aws iam list-policies --output text

* For each policy returned, run the following command to determine if any
policies is allowing full administrative privileges on the account:

'aws iam get-policy-version --policy-arn _<policy_arn>_ --version
_<policy_version>_ --query 'PolicyVersion.Document.Statement[?Effect == 'Allow'
&& contains(Resource, '*') && contains (Action, '*')]'
* If the output of the command returns any policies, it's not compliant."
  tag "fix": "Using the GUI, perform the following to detach the policy that
has full administrative privileges:

 'Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/iam/ [https://console.aws.amazon.com/iam/].

 'In the navigation pane, click Policies and then search for the policy name
found in the audit step.

 'Select the policy that needs to be deleted.

 'In the policy action menu, select first Detach
* Select all Users, Groups, Roles that have this policy attached

 'Click Detach Policy

 'In the policy action menu, select Detach

'Using the CLI, perform the following to detach the policy that has full
administrative privileges as found in the audit step:

'1. Lists all IAM users, groups, and roles that the specified managed policy is
attached to.

 'aws iam list-entities-for-policy --policy-arn _<policy_arn>_


'2. Detach the policy from all IAM Users:

 'aws iam detach-user-policy --user-name _<iam_user>_ --policy-arn _<policy_arn>_

'3. Detach the policy from all IAM Groups:

 'aws iam detach-group-policy --group-name _<iam_group>_ --policy-arn
_<policy_arn>_


'4. Detach the policy from all IAM Roles:


 'aws iam detach-role-policy --role-name _<iam_role>_ --policy-arn _<policy_arn>_

'
"
  # the following implementation covers cases where 'Action' and 'Resource' param of the
  # policy json is defined as an array or string
  # if recoded please confirm that it tests both cases

  aws_iam_policies.where { attachment_count > 0 }.policy_names.each do |policy|
    describe "Attached Policies #{policy} allows full '*:*' privileges?" do
      subject do
        aws_iam_policy(policy).document.where(Effect: 'Allow').actions.flatten.include?('*') &&
          aws_iam_policy(policy).document.where(Effect: 'Allow').resources.flatten.include?('*')
      end
      it { should be false }
    end
  end

  if  aws_iam_policies.where { attachment_count > 0 }.policy_names.empty?
    describe 'Control skipped because no iam policies were found' do
      skip 'This control is skipped since the aws_iam_policies resource returned an empty policy list'
    end
  end
end
