# encoding: UTF-8

control "1.20" do
  title "Ensure a support role has been created to manage incidents with AWS
Support"
  desc  "AWS provides a support center that can be used for incident
notification and response, as well as technical support and customer services.
Create an IAM Role to allow authorized users to manage incidents with AWS
Support."
  desc  "rationale", "By implementing least privilege for access control, an
IAM Role will require an appropriate IAM Policy to allow Support Center Access
in order to manage Incidents with AWS Support."
  desc  "check", "
    Using the Amazon unified command line interface:

    - List IAM policies, filter for the 'AWSSupportAccess' managed policy, and
note the \"Arn\" element value:
    ```
     aws iam list-policies --query \"Policies[?PolicyName ==
'AWSSupportAccess']\"
    ```
    - Check if the 'AWSSupportAccess' is attached to any IAM user, group or
role:
    ```
     aws iam list-entities-for-policy --policy-arn
    ```
  "
  desc  "fix", "
    Using the Amazon unified command line interface:

    - Create an IAM role for managing incidents with AWS:
     - Create a trust relationship policy document that allows  to manage AWS
incidents, and save it locally as /tmp/TrustPolicy.json:
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
     aws iam create-role --role-name  --assume-role-policy-document
file:///tmp/TrustPolicy.json
    ```
    - - Attach 'AWSSupportAccess' managed policy to the created IAM role:
    ```
     aws iam attach-role-policy --policy-arn  --role-name
    ```
  "
  impact 0.3
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag ref:
"http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html:https://aws.amazon.com/premiumsupport/pricing/:http://docs.aws.amazon.com/cli/latest/reference/iam/list-policies.html:http://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html:http://docs.aws.amazon.com/cli/latest/reference/iam/list-entities-for-policy.html"
end

