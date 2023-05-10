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
  tag nist: ['AC-2']
  tag cis_controls: "TITLE:Disable Dormant Accounts CONTROL:16.9 DESCRIPTION:Automatically disable dormant accounts after a set period of inactivity.;"
  tag ref: "CIS CSC v6.0 #16.6"

  aws_iam_credential_report.where(password_enabled: false).entries.each do |user|
    describe "Password disabled for user (#{user.user})" do
      skip "Test not applicable since user's (#{user.user}) password is disabled"
    end
  end

  aws_iam_credential_report.where(password_enabled: true).entries.each do |user|
    describe "The user (#{user.user})" do
      if user.password_last_used.is_a? DateTime
       subject { ((Time.current - user.password_last_used) / (24*60*60)).to_i }
       it "must have used their password within the last 90 days." do
         expect(subject).to be < 90
       end
      elsif user.password_last_changed.is_a? DateTime
       subject { ((Time.current - user.password_last_changed) / (24*60*60)).to_i }
       it "must have changed their password within the last 90 days if they have not used it within the last 90 days." do
         expect(subject).to be < 90
       end
      else
        RSpec::Expectatations.fail_with("must have changed their password within the last 90 days if they have not used it within the last 90 days.")
      end
    end
  end

  aws_iam_credential_report.where(access_key_1_active: false).entries.each do |user|
    describe "Access key 1 disabled for user (#{user.user})" do
      skip "Test not applicable since user's (#{user.user}) access key 1 is disabled"
    end
  end

  aws_iam_credential_report.where(access_key_1_active: true).entries.each do |user|
    describe "The user (#{user.user})" do
      if user.access_key_1_last_used_date.is_a? DateTime
       subject { ((Time.current - user.access_key_1_last_used_date) / (24*60*60)).to_i }
       it "must have used access key 1 within the last 90 days." do
         expect(subject).to be < 90
       end
      elsif user.access_key_1_last_rotated.is_a? DateTime
       subject { ((Time.current - user.access_key_1_last_rotated) / (24*60*60)).to_i }
       it "must have rotated access key 1 within the last 90 days if they have not used it within the last 90 days." do
         expect(subject).to be < 90
       end
      else
        RSpec::Expectatations.fail_with("must have rotated access key 1 within the last 90 days if they have not used it within the last 90 days.")
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
       subject { ((Time.current - user.access_key_2_last_used_date) / (24*60*60)).to_i }
       it "must have used access key 2 within the last 90 days." do
         expect(subject).to be < 90
       end
      elsif user.access_key_2_last_rotated.is_a? DateTime
       subject { ((Time.current - user.access_key_2_last_rotated) / (24*60*60)).to_i }
       it "must have rotated access key 2 within the last 90 days if they have not used it within the last 90 days." do
         expect(subject).to be < 90
       end
      else
        RSpec::Expectatations.fail_with("must have rotated access key 2 within the last 90 days if they have not used it within the last 90 days.")
      end
    end
  end
end
