# encoding: UTF-8

control "aws-foundations-cis-1.20" do
  title "Ensure a support role has been created to manage incidents with AWS Support"
  desc  "AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Create an IAM Role to allow authorized users to manage incidents with AWS Support."
  desc  "rationale", "By implementing least privilege for access control, an IAM Role will require an appropriate IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support."
  desc  "check", "Using the Amazon unified command line interface:

    - List IAM policies, filter for the 'AWSSupportAccess' managed policy, and note the \"Arn\" element value:
    ```
     aws iam list-policies --query \"Policies[?PolicyName == 'AWSSupportAccess']\"
    ```
    - Check if the 'AWSSupportAccess' is attached to any IAM user, group or role:
    ```
     aws iam list-entities-for-policy --policy-arn
    ```"
  desc  "fix", "Using the Amazon unified command line interface:

    - Create an IAM role for managing incidents with AWS:
    - Create a trust relationship policy document that allows  to manage AWS incidents, and save it locally as /tmp/TrustPolicy.json:
    ```
     {
     \"Version\": \"2012-10-17\",
     \"Statement\": [
     {
     \"Effect\": \"Allow\",
     \"Principal\": {
     \"AWS\": \"\"
     },
     \"Action\": \"sts:AssumeRole\"
     }
     ]
     }
    ```
    - - Create the IAM role using the above trust policy:
    ```
     aws iam create-role --role-name  --assume-role-policy-document file:///tmp/TrustPolicy.json
    ```
    - - Attach 'AWSSupportAccess' managed policy to the created IAM role:
    ```
     aws iam attach-role-policy --policy-arn  --role-name
    ```"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['IR-7']
  tag notes: "We also need two recommendations in Identity Section of this 3 tier web app to have an admin group and create a policy that can open support tickets and do other admin things that cost money. Valentin worked on these new recommendations."
  tag comment: "All AWS Support plans include an unlimited number of account and billing support cases, with no long-term contracts. Support billing calculations are performed on a per-account basis for all plans. Enterprise Support plan customers have the option to include multiple enabled accounts in an aggregated monthly billing calculation. Monthly charges for the Business and Enterprise support plans are based on each month's AWS usage charges, subject to a monthly minimum, billed in advance."
  tag ref: "http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html:https://aws.amazon.com/premiumsupport/pricing/:http://docs.aws.amazon.com/cli/latest/reference/iam/list-policies.html:http://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html:http://docs.aws.amazon.com/cli/latest/reference/iam/list-entities-for-policy.html"

  
  describe aws_iam_policy('AWSSupportAccess') do
    it { should be_attached }
  end
end