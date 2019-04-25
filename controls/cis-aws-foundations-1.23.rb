control 'cis-aws-foundations-1.23' do
  title "Do not setup access keys during initial user setup for all IAM users
that have a console password"
  desc  "AWS console defaults the checkbox for creating access keys to enabled.
This results in many access keys being generated unnecessarily. In addition to
unnecessary credentials, it also generates unnecessary management work in
auditing and rotating these keys."
  impact 0.3
  tag "rationale": "Requiring that additional steps be taken by the user after
their profile has been created will give a stronger indication of intent that
access keys are [a] necessary for their work and [b] once the access key is
established on an account, that the keys may be in use somewhere in the
organization.

'NOTE: Even if it is known the user will need access keys, require them to
create the keys themselves or put in a support ticket to have the created as a
separate step from user creation."
  tag "cis_impact": ''
  tag "cis_rid": '1.23'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['AC-6', 'Rev_4']
  tag "cce_id": ''
  tag "check": "Perform the following to determine if access keys are rotated
as prescribed:

* Login to the AWS Management Console
* ClickServices
* ClickIAM
* Click onA User
* Compare the user creation date to the key 1 creation date.
* For any that match, the key was created during initial user setup.

 * Keys that were created at the same time as the user profile and do not have a
last used date should be deleted.

' Via the CLI


* Run the following command (OSX/Linux/UNIX) to generate a list of all IAM
users along with their access keys utilization:

'aws iam generate-credential-report

'aws iam get-credential-report --query 'Content' --output text | base64 -d |
cut -d, -f1,4,9,11,14,16

* The output of this command will produce a table similar to the following:

'user,password_enabled,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date

elise,false,true,2015-04-16T15:14:00+00:00,false,N/A
brandon,true,true,N/A,false,N/A
rakesh,false,false,N/A,false,N/A
helene,false,true,2015-11-18T17:47:00+00:00,false,N/A
paras,true,true,2016-08-28T12:04:00+00:00,true,2016-03-04T10:11:00+00:00
anitha,true,true,2016-06-08T11:43:00+00:00,true,N/A
* For any user having access_key_last_used_date set to N/A, ensure that access
key is deleted.


"
  tag "fix": "Perform the following to delete access keys that do not pass the
audit:

* Login to the AWS Management Console:
* Click Services
* Click IAM
* Click on Users
* Click on Security Credentials

* As an Administrator

* Click on Delete for keys that were created at the same time as the user
profile but have not been used.

* As an IAM User

* Click on Delete for keys that were created at the same time as the user
profile but have not been used.

'Via CLI

'aws iam delete-access-key"

  aws_iam_access_keys.entries.each do |key|
    describe key.username do
      context key do
        its('last_used_days_ago') { should_not be_nil }
      end
    end
  end

  if aws_iam_access_keys.entries.empty?
    describe 'Control skipped because no iam access keys were found' do
      skip 'This control is skipped since the aws_iam_access_keys resource returned an empty access key list'
    end
  end
end
