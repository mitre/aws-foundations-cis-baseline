# encoding: UTF-8

control "aws-foundations-cis-1.9" do
  title "Ensure IAM password policy requires minimum length of 14 or greater"
  desc  "Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure password are at least a given length. It is recommended that the password policy require a minimum password length 14."
  desc  "rationale", "Setting a password complexity policy increases account resiliency against brute force login attempts."
  desc  "check", "Perform the following to ensure the password policy is configured as prescribed:

    Via AWS Console

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Ensure \"Minimum password length\" is set to 14 or greater.

    Via CLI
    ```
    aws iam get-account-password-policy
    ```
    Ensure the output of the above command includes \"MinimumPasswordLength\": 14 (or higher)"
  desc  "fix", "Perform the following to set the password policy as prescribed:

    Via AWS Console

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Set \"Minimum password length\" to `14` or greater.
    5. Click \"Apply password policy\"

     Via CLI
    ```
     aws iam update-account-password-policy --minimum-password-length 14
    ```
    Note: All commands starting with \"aws iam update-account-password-policy\" can be combined into a single command."
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
  tag cis_controls: "TITLE:Account Monitoring and Control CONTROL:16 DESCRIPTION:Account Monitoring and Control;"
  tag ref: "CIS CSC v6.0 #5.7, #16.12"


  describe aws_iam_password_policy do
    it { should exist }
    its('minimum_password_length') { should cmp >= input("pwd_length") }
  end
end