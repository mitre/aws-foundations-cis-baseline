aws_key_age = attribute('aws_key_age')

control 'cis-aws-foundations-1.4' do
  title "Ensure access keys are rotated every #{aws_key_age} days or less"
  desc  "Access keys consist of an access key ID and secret access key, which
are used to sign programmatic requests that you make to AWS. AWS users need
their own access keys to make programmatic calls to AWS from the AWS Command
Line Interface (AWS CLI), Tools for Windows PowerShell, the AWS SDKs, or direct
HTTP calls using the APIs for individual AWS services. It is recommended that
all access keys be regularly rotated."
  impact 0.3
  tag "rationale": "Rotating access keys will reduce the window of opportunity
for an access key that is associated with a compromised or terminated account
to be used.

'Access keys should be rotated to ensure that data cannot be accessed with an
old key which might have been lost, cracked, or stolen."
  tag "cis_impact": ''
  tag "cis_rid": '1.4'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['IA-5(1)', 'Rev_4']
  tag "cce_id": 'CCE-78902-4'
  tag "check": "Perform the following to determine if access keys are rotated
as prescribed:

* Login to the AWS Management Console
* Click Services
* Click IAM
* Click on Credential Report
* This will download an .xls file which contains Access Key usage for all IAM
users within an AWS Account - open this file

* Focus on the following columns (where x = 1 or 2)

* access_key_X_active
* access_key_X_last_rotated
* access_key_X_last_used_date


* Ensure all active keys have been rotated within #{aws_key_age} days

* Ensure all active keys have been used since last rotation

* Keys not in-use since last rotation should be disabled/deleted

'Via CLI

'aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d"
  tag "fix": "Perform the following to rotate access keys:

* Login to the AWS Management Console:
* Click Services
* Click IAM
* Click on Users
* Click on Security Credentials

* As an Administrator

* Click on Make Inactive for keys that have not been rotated in #{aws_key_age} Days

* As an IAM User

* Click on Make Inactive or Delete for keys which have not been rotated or used
in the last #{aws_key_age} days


* Click on Create Access Key
* Update programmatic call with new Access Key credentials

'Via CLI

'aws iam update-access-key
aws iam create-access-key
aws iam delete-access-key"

  aws_iam_access_keys.where(active: true).entries.each do |key|
    describe key.username do
      context key do
        its('created_days_ago') { should cmp <= aws_key_age }
        its('ever_used') { should be true }
      end
    end
  end

  if aws_iam_access_keys.where(active: true).entries.empty?
    describe 'Control skipped because no active iam access keys were found' do
      skip 'This control is skipped since the aws_iam_access_keys resource returned an empty active access key list'
    end
  end
end
