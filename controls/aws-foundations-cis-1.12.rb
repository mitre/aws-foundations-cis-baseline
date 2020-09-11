# encoding: UTF-8

control "aws-foundations-cis-1.12" do
  title "Ensure no root account access key exists"
  desc  "The root account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the root account be removed."
  desc  "rationale", "Removing access keys associated with the root account limits vectors by which the account can be compromised. Additionally, removing the root access keys encourages the creation and use of role based accounts that are least privileged."
  desc  "check", "Perform the following to determine if the root account has access keys:

    Via the AWS Console

    1. Login to the AWS Management Console
    2. Click `Services`
    3. Click `IAM`
    4. Click on `Credential Report`
    5. This will download an `.xls` file which contains credential usage for all IAM users within an AWS Account - open this file
    6. For the `` user, ensure the `access_key_1_active` and `access_key_2_active` fields are set to `FALSE` .

    Via CLI

    1. Run the following commands:
    ```
     aws iam generate-credential-report
     aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,9,14 | grep -B1 ''
    ```
    2. For the `` user, ensure the `access_key_1_active` and `access_key_2_active` fields are set to `FALSE` ."
  desc  "fix", "Perform the following to delete or disable active root access keys being

    Via the AWS Console

    1. Sign in to the AWS Management Console as Root and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
    2. Click on __ at the top right and select `Security Credentials` from the drop down list
    3. On the pop out screen Click on `Continue to Security Credentials`
    4. Click on `Access Keys` _(Access Key ID and Secret Access Key)_
    5. Under the `Status` column if there are any Keys which are Active
     1. Click on `Make Inactive` - (Temporarily disable Key - may be needed again)
     2. Click `Delete` - (Deleted keys cannot be recovered)"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-6(9)']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Ensure the Use of Dedicated Administrative Accounts CONTROL:4.3 DESCRIPTION:Ensure that all users with administrative account access use a dedicated or secondary account for elevated activities. This account should only be used for administrative activities and not internet browsing, email, or similar activities.;"
  tag ref: "http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html:http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html:http://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html:CIS CSC v6.0 #5.1"

  
  describe aws_iam_root_user do
    it { should_not have_access_key }
  end
end