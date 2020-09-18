# encoding: UTF-8

control "aws-foundations-cis-1.3" do
  title "Ensure credentials unused for 90 days or greater are disabled"
  desc  "AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in 90 or greater days be removed or deactivated."
  desc  "rationale", "Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used."
  desc  "check", "Perform the following to determine if unused credentials exist:

    **Download Credential Report:**

    Using Management Console:
    1. Login to the AWS Management Console
    2. Click `Services`
    3. Click `IAM`
    4. Click on `Credential Report`
    5. This will download an `.xls` file which contains credential usage for all users within an AWS Account - open this file

    Via CLI
    1. Run the following commands:
    ```
     aws iam generate-credential-report
     aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16
    ```
    **Ensure unused credentials does not exist:**
    2. For each user having `password_enabled` set to `TRUE` , ensure `password_last_used_date` is less than `90` days ago.
    - When `password_enabled` is set to `TRUE` and `password_last_used` is set to `No_Information` , ensure `password_last_changed` is less than 90 days ago.
    3. For each user having an `access_key_1_active` or `access_key_2_active` to `TRUE` , ensure the corresponding `access_key_n_last_used_date` is less than `90` days ago.
    - When a user having an `access_key_x_active` (where x is 1 or 2) to `TRUE` and corresponding access_key_x_last_used_date is set to `N/A', ensure `access_key_x_last_rotated` is less than 90 days ago."
  desc  "fix", "Perform the following to remove or deactivate credentials:

    1. Login to the AWS Management Console:
    2. Click `Services`
    3. Click `IAM`
    4. Click on `Users`
    5. Click on `Security Credentials`
    6. As an Administrator
     - Click on `Make Inactive` for credentials that have not been used in `90` Days
    7. As an IAM User
     - Click on `Make` `Inactive` or `Delete` for credentials which have not been used in `90` Days"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-2']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Disable Dormant Accounts CONTROL:16.9 DESCRIPTION:Automatically disable dormant accounts after a set period of inactivity.;"
  tag ref: "CIS CSC v6.0 #16.6"

  
  # For each user having `password_enabled` set to `TRUE` , ensure `password_last_used_date` is less than `90` days ago.
  aws_iam_users.where(has_console_password: true).where(password_ever_used?: true).entries.each do |user|
    describe user.username do
      subject { user }
      its('password_last_used_days_ago') { should cmp < 90 }
    end
  end

  # When `password_enabled` is set to `TRUE` and `password_last_used` is set to `No_Information` , ensure `password_last_changed` is less than 90 days ago.
  # 'password_last_changed' property not exposed in AWS Ruby SDK: https://github.com/aws/aws-sdk-ruby/issues/2375

  no_information_users = aws_iam_users.where(has_console_password: true).where(password_last_used_days_ago: -1).entries
  unless no_information_users.empty?
    no_information_users.each do |user|
      describe "Manually validate that the password has been changed less than 90 days ago for user: #{user.username}" do
        skip "Manually validate that the password has been changed less than 90 days ago for user: #{user.username}"
      end
    end
  end
  

  # For each user having an `access_key_1_active` or `access_key_2_active` to `TRUE` , ensure the corresponding `access_key_n_last_used_date` is less than `90` days ago.
  # When a user having an `access_key_x_active` (where x is 1 or 2) to `TRUE` and corresponding access_key_x_last_used_date is set to `N/A', ensure `access_key_x_last_rotated` is less than 90 days ago
      
  aws_iam_access_keys.where(active: true).entries.each do |key|
    describe key.username do
      if key.last_used_days_ago.nil?
        describe key.username do
          context key do
            its('created_days_ago') { should cmp < 90 }
          end
        end
      else
        context key do
          its('last_used_days_ago') { should cmp < 90 }
        end
      end
    end
  end

  if aws_iam_access_keys.where(active: true).entries.empty?
    describe 'Control skipped because no active iam access keys were found' do
      skip 'This control is skipped since the aws_iam_access_keys resource returned an empty active access key list'
    end
  end
end