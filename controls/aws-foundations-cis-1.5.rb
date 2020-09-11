# encoding: UTF-8

control "aws-foundations-cis-1.5" do
  title "Ensure IAM password policy requires at least one uppercase letter"
  desc  "Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure password are comprised of different character sets. It is recommended that the password policy require at least one uppercase letter."
  desc  "rationale", "Setting a password complexity policy increases account resiliency against brute force login attempts."
  desc  "check", "Perform the following to ensure the password policy is configured as prescribed:

    Via AWS Console
    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Ensure \"Requires at least one uppercase letter\" is checked under \"Password Policy\"

    Via CLI
    ```
    aws iam get-account-password-policy
    ```
    Ensure the output of the above command includes \"RequireUppercaseCharacters\": true"
  desc  "fix", "Perform the following to set the password policy as prescribed:

    Via AWS Console
    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Check \"Requires at least one uppercase letter\"
    5. Click \"Apply password policy\"

    Via CLI
    ```
     aws iam update-account-password-policy --require-uppercase-characters
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


  describe aws_iam_password_policy do
    it { should exist }
    it { should require_uppercase_characters }
  end
end