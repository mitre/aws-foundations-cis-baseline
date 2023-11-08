# encoding: UTF-8

control "aws-foundations-cis-1.17" do
  title "Ensure a support role has been created to manage incidents with AWS Support "
  desc "AWS provides a support center that can be used for incident notification and response, as well 
as technical support and customer services. Create an IAM Role, with the appropriate policy 
assigned, to allow authorized users to manage incidents with AWS Support. "
  desc "rationale", "By implementing least privilege for access control, an IAM Role will require an appropriate 
IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support. "
  desc "check", "**From Command Line:**

1. List IAM policies, filter for the 'AWSSupportAccess' managed 
policy, and note the \"Arn\" element value:
```
aws iam list-policies --query 
\"Policies[?PolicyName == 'AWSSupportAccess']\"
```
2. Check if the 
'AWSSupportAccess' policy is attached to any role:

```
aws iam 
list-entities-for-policy --policy-arn 
arn:aws:iam::aws:policy/AWSSupportAccess
```

3. In Output, Ensure `PolicyRoles` 
does not return empty. 'Example: Example: PolicyRoles: [ ]'

If it returns empty refer to 
the remediation below. "
  desc "fix", "**From Command Line:**

1. Create an IAM role for managing incidents with AWS:
 - Create a 
trust relationship policy document that allows <iam_user> to manage AWS incidents, and save 
it locally as /tmp/TrustPolicy.json:
```
 {
 \"Version\": \"2012-10-17\",
 
\"Statement\": [
 {
 \"Effect\": \"Allow\",
 \"Principal\": {
 \"AWS\": \"<iam_user>\"
 },
 
\"Action\": \"sts:AssumeRole\"
 }
 ]
 }
```
2. Create the IAM role using the above trust 
policy:
```
aws iam create-role --role-name <aws_support_iam_role> 
--assume-role-policy-document file:///tmp/TrustPolicy.json
```
3. Attach 
'AWSSupportAccess' managed policy to the created IAM role:
```
aws iam 
attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess 
--role-name <aws_support_iam_role>
``` "
  desc "additional_information", "AWSSupportAccess policy is a global AWS resource. It has same ARN as 
`arn:aws:iam::aws:policy/AWSSupportAccess` for every account. "
  desc "impact", "All AWS Support plans include an unlimited number of account and billing support cases, with 
no long-term contracts. Support billing calculations are performed on a per-account basis 
for all plans. Enterprise Support plan customers have the option to include multiple enabled 
accounts in an aggregated monthly billing calculation. Monthly charges for the Business and 
Enterprise support plans are based on each month's AWS usage charges, subject to a monthly 
minimum, billed in advance.

When assigning rights, keep in mind that other policies may 
grant access to Support as well. This may include AdministratorAccess and other policies 
including customer managed policies. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html:https://aws.amazon.com/premiumsupport/pricing/:https://docs.aws.amazon.com/cli/latest/reference/iam/list-policies.html:https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html:https://docs.aws.amazon.com/cli/latest/reference/iam/list-entities-for-policy.html'
  tag nist: []
  tag severity: "medium "
end