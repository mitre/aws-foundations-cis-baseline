control 'cis-aws-foundations-1.3' do
  title 'Ensure credentials unused for 90 days or greater are disabled'
  desc  "AWS IAM users can access AWS resources using different types of
credentials, such as passwords or access keys. It is recommended that all
credentials that have been unused in 90 or greater days be removed or
deactivated."
  impact 0.3
  tag "rationale": "Disabling or removing unnecessary credentials will reduce
the window of opportunity for credentials associated with a compromised or
abandoned account to be used."
  tag "cis_impact": ''
  tag "cis_rid": '1.3'
  tag "cis_level": 1
  tag "csc_control": [['16.6'], '6.0']
  tag "nist": ['IA-4', 'Rev_4']
  tag "cce_id": 'CCE-78900-8'
  tag "check": "Perform the following to determine if unused credentials exist:


* Login to the AWS Management Console
* Click Services
* Click IAM
* Click on Credential Report
* This will download an .xls file which contains credential usage for all users
within an AWS Account - open this file
* For each user having password_enabled set to TRUE, ensure password_last_used
is less than 90 days ago.
* For each user having access_key_1_active or access_key_2_active to TRUE,
ensure the corresponding access_key_n_last_used_date is less than 90 days ago.


'Via CLI

* Run the following commands:

'aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | cut
-d, -f1,9,10,11,14,15,16
* For each user having password_enabled set to TRUE, ensure
password_last_used_date is less than 90 days ago.
* For each user having an access_key_1_active or access_key_2_active to TRUE,
ensure the corresponding access_key_n_last_used_date is less than 90 days ago."
  tag "fix": "Perform the following to remove or deactivate credentials:

* Login to the AWS Management Console:
* Click Services
* Click IAM
* Click on Users
* Click on Security Credentials

* As an Administrator

* Click on Make Inactive for credentials that have not been used in 90 Days

* As an IAM User

* Click on Make Inactive or Delete for credentials which have not been used in
90 Days
"
  describe aws_iam_users.where(has_console_password?: true).where(password_never_used?: true) do
    it { should_not exist }
  end

  describe aws_iam_users.where(password_ever_used?: true).where { password_last_used_days_ago >= 90 } do
    it { should_not exist }
  end

  aws_iam_access_keys.where(active: true).entries.each do |key|
    describe key.username do
      context key do
        its('last_used_days_ago') { should cmp < 90 }
      end
    end
  end

  if aws_iam_access_keys.where(active: true).entries.empty?
    describe 'Control skipped because no active iam access keys were found' do
      skip 'This control is skipped since the aws_iam_access_keys resource returned an empty active access key list'
    end
  end
end
