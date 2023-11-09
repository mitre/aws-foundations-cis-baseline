# encoding: UTF-8

control "aws-foundations-cis-1.14" do
  title "Ensure access keys are rotated every 90 days or less "
  desc "Access keys consist of an access key ID and secret access key, which are used to sign 
programmatic requests that you make to AWS. AWS users need their own access keys to make 
programmatic calls to AWS from the AWS Command Line Interface (AWS CLI), Tools for Windows 
PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services. It 
is recommended that all access keys be regularly rotated. "
  desc "rationale", "Rotating access keys will reduce the window of opportunity for an access key that is 
associated with a compromised or terminated account to be used.

Access keys should be 
rotated to ensure that data cannot be accessed with an old key which might have been lost, 
cracked, or stolen. "
  desc "check", "Perform the following to determine if access keys are rotated as prescribed:

**From 
Console:**

1. Go to Management Console (https://console.aws.amazon.com/iam)
2. 
Click on `Users`
3. Click `setting` icon
4. Select `Console last sign-in`
5. Click 
`Close`
6. Ensure that `Access key age` is less than 90 days ago. note) `None` in the `Access 
key age` means the user has not used the access key.

**From Command Line:**

```
aws 
iam generate-credential-report
aws iam get-credential-report --query 'Content' 
--output text | base64 -d
```
The `access_key_1_last_rotated` and the 
`access_key_2_last_rotated` fields in this file notes The date and time, in ISO 8601 
date-time format, when the user's access key was created or last changed. If the user does not 
have an active access key, the value in this field is N/A (not applicable). "
  desc "fix", "Perform the following to rotate access keys:

**From Console:**

1. Go to Management 
Console (https://console.aws.amazon.com/iam)
2. Click on `Users`
3. Click on 
`Security Credentials` 
4. As an Administrator 
 - Click on `Make Inactive` for keys that 
have not been rotated in `90` Days
5. As an IAM User
 - Click on `Make Inactive` or `Delete` 
for keys which have not been rotated or used in `90` Days
6. Click on `Create Access Key` 
7. 
Update programmatic call with new Access Key credentials

**From Command Line:**

1. 
While the first access key is still active, create a second access key, which is active by 
default. Run the following command:
```
aws iam create-access-key
```

At this 
point, the user has two active access keys.

2. Update all applications and tools to use the 
new access key.
3. Determine whether the first access key is still in use by using this 
command:
```
aws iam get-access-key-last-used
```
4. One approach is to wait 
several days and then check the old access key for any use before proceeding.

Even if step 
Step 3 indicates no use of the old key, it is recommended that you do not immediately delete the 
first access key. Instead, change the state of the first access key to Inactive using this 
command:
```
aws iam update-access-key
```
5. Use only the new access key to confirm 
that your applications are working. Any applications and tools that still use the original 
access key will stop working at this point because they no longer have access to AWS resources. 
If you find such an application or tool, you can switch its state back to Active to reenable the 
first access key. Then return to step Step 2 and update this application to use the new 
key.

6. After you wait some period of time to ensure that all applications and tools have 
been updated, you can delete the first access key with this command:
```
aws iam 
delete-access-key
``` "
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#rotate-credentials:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html:https://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'
  tag nist: ['AC-2']
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["5"]}
  ]

  aws_iam_credential_report.where(access_key_1_active: false).entries.each do |user|
    describe "Access key 1 disabled for user (#{user.user})" do
      skip "Test not applicable since user's (#{user.user}) access key 1 is disabled"
    end
  end

  aws_iam_credential_report.where(access_key_1_active: true).entries.each do |user|
    describe "The user (#{user.user})" do
      if user.access_key_1_last_used_date.is_a? DateTime
        subject { ((Time.current - user.access_key_1_last_used_date) / (24 * 60 * 60)).to_i }
        it 'must have used access key 1 within the last 90 days.' do
          expect(subject).to be < 90
        end
      elsif user.access_key_1_last_rotated.is_a? DateTime
        subject { ((Time.current - user.access_key_1_last_rotated) / (24 * 60 * 60)).to_i }
        it 'must have rotated access key 1 within the last 90 days if they have not used it within the last 90 days.' do
          expect(subject).to be < 90
        end
      else
        RSpec::Expectatations.fail_with('must have rotated access key 1 within the last 90 days if they have not used it within the last 90 days.')
      end
    end
  end

  aws_iam_credential_report.where(access_key_2_active: false).entries.each do |user|
    describe "Access key 2 disabled for user (#{user.user})" do
      skip "Test not applicable since user's (#{user.user}) access key 2 is disabled"
    end
  end

  aws_iam_credential_report.where(access_key_2_active: true).entries.each do |user|
    describe "The user (#{user.user})" do
      if user.access_key_2_last_used_date.is_a? DateTime
        subject { ((Time.current - user.access_key_2_last_used_date) / (24 * 60 * 60)).to_i }
        it 'must have used access key 2 within the last 90 days.' do
          expect(subject).to be < 90
        end
      elsif user.access_key_2_last_rotated.is_a? DateTime
        subject { ((Time.current - user.access_key_2_last_rotated) / (24 * 60 * 60)).to_i }
        it 'must have rotated access key 2 within the last 90 days if they have not used it within the last 90 days.' do
          expect(subject).to be < 90
        end
      else
        RSpec::Expectatations.fail_with('must have rotated access key 2 within the last 90 days if they have not used it within the last 90 days.')
      end
    end
  end
end
