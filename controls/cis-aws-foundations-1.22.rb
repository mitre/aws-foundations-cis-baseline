control 'cis-aws-foundations-1.22' do
  title "Ensure a support role has been created to manage incidents with AWS
Support"
  desc  "AWS provides a support center that can be used for incident
notification and response, as well as technical support and customer services.
Create an IAM Role to allow authorized users to manage incidents with AWS
Support."
  impact 0.3
  tag "rationale": "By implementing least privilege for access control, an IAM
Role will require an appropriate IAM Policy to allow Support Center Access in
order to manage Incidents with AWS Support."
  tag "cis_impact": "All AWS Support plans include an unlimited number of
account and billing support cases, with no long-term contracts.

Support billing calculations are performed on a per-account basis for all
plans. Enterprise Support plan customers have the option to include multiple
enabled accounts in an aggregated monthly billing calculation.

Monthly charges for the Business and Enterprise support plans are based on each
month's AWS usage charges, subject to a monthly minimum, billed in advance."
  tag "cis_rid": '1.22'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['IR-7', 'Rev_4']
  tag "cce_id": ''
  tag "check": "Using the Amazon unified command line interface:

* List IAM policies, filter for the 'AWSSupportAccess' managed policy, and note
the 'Arn' element value:

 'aws iam list-policies --query 'Policies[?PolicyName == 'AWSSupportAccess']'


* Check if the 'AWSSupportAccess' is attached to any IAM user, group or role:

 'aws iam list-entities-for-policy --policy-arn <iam_policy_arn>
"
  tag "fix": "Using the Amazon unified command line interface:

* Create an IAM role for managing incidents with AWS:

* Create a trust relationship policy document that allows <iam_user> to manage
AWS incidents, and save it locally as /tmp/TrustPolicy.json:

 '{
 'Version': '2012-10-17',
 'Statement': [
 {
 'Effect': 'Allow',
 'Principal': {
 'AWS': '<iam_user>'
 },
 'Action': 'sts:AssumeRole'
 }
 ]
}


 * Create the IAM role using the above trust policy:

 'aws iam create-role --role-name <_aws_support_iam_role_>
--assume-role-policy-document file:///tmp/TrustPolicy.json


 * Attach 'AWSSupportAccess' managed policy to the created IAM role:

 'aws iam attach-role-policy --policy-arn <iam_policy_arn> --role-name
<_aws_support_iam_role_>

"

  describe aws_iam_policy('AWSSupportAccess') do
    it { should be_attached }
  end
end
