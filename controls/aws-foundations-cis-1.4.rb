control 'aws-foundations-cis-1.4' do
  title "Ensure no 'root' user account access key exists "
  desc "The 'root' user account is the most privileged user in an AWS account. AWS Access Keys provide
programmatic access to a given AWS account. It is recommended that all access keys associated
with the 'root' user account be deleted. "
  desc 'rationale', "Deleting access keys associated with the 'root' user account limits vectors by which the
account can be compromised. Additionally, deleting the 'root' access keys encourages the
creation and use of role based accounts that are least privileged. "
  desc 'check', "Perform the following to determine if the 'root' user account has access keys:

**From
Console:**

1. Login to the AWS Management Console.
2. Click `Services`.
3. Click
`IAM`.
4. Click on `Credential Report`.
5. This will download a `.csv` file which
contains credential usage for all IAM users within an AWS Account - open this file.
6. For the
`<root_account>` user, ensure the `access_key_1_active` and `access_key_2_active`
fields are set to `FALSE`.

**From Command Line:**

Run the following
command:
```
aws iam get-account-summary | grep \"AccountAccessKeysPresent\"

```
If no 'root' access keys exist the output will show `\"AccountAccessKeysPresent\":
0,`.

If the output shows a \"1\", then 'root' keys exist and should be deleted. "
  desc 'fix', "Perform the following to delete active 'root' user access keys.

**From
Console:**

1. Sign in to the AWS Management Console as 'root' and open the IAM console at
[https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
2.
Click on `<root_account>` at the top right and select `My Security Credentials` from the drop
down list.
3. On the pop out screen Click on `Continue to Security Credentials`.
4. Click
on `Access Keys` (Access Key ID and Secret Access Key).
5. Under the `Status` column (if
there are any Keys which are active).
6. Click `Delete` (Note: Deleted keys cannot be
recovered).

Note: While a key can be made inactive, this inactive key will still show up in
the CLI command from the audit procedure, and may lead to a key being falsely flagged as being
non-compliant. "
  desc 'additional_information', "IAM User account \"root\" for us-gov cloud regions is not enabled by default. However, on
request to AWS support enables 'root' access only through access-keys (CLI, API methods) for
us-gov cloud region. "
  impact 0.5
  ref 'http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html:http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html:http://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html:https://aws.amazon.com/blogs/security/an-easier-way-to-determine-the-presence-of-aws-account-access-keys/'
  tag nist: ['AC-6']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['3.3'] },
  ]
  describe 'The root account should not have active access keys.' do
    subject { aws_iam_credential_report.where(user: '<root_account>').entries.first }
    its('access_key_1_active') { should eq false }
    its('access_key_2_active') { should eq false }
  end
end
