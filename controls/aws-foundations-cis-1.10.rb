# encoding: UTF-8

control "aws-foundations-cis-1.10" do
  title "Ensure IAM password policy prevents password reuse"
  desc  "IAM password policies can prevent the reuse of a given password by the same user. It is recommended that the password policy prevent the reuse of passwords."
  desc  "rationale", "Preventing password reuse increases account resiliency against brute force login attempts."
  desc  "check", "Perform the following to ensure the password policy is configured as prescribed:

    Via AWS Console

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Ensure \"Prevent password reuse\" is checked
    5. Ensure \"Number of passwords to remember\" is set to 24

    Via CLI
    ```
    aws iam get-account-password-policy
    ```
    Ensure the output of the above command includes \"PasswordReusePrevention\": 24"
  desc  "fix", "Perform the following to set the password policy as prescribed:

    Via AWS Console

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Check \"Prevent password reuse\"
    5. Set \"Number of passwords to remember\" is set to `24`

     Via CLI
    ```
     aws iam update-account-password-policy --password-reuse-prevention 24
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
  tag nist: ['IA-5(1)']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Use Unique Passwords CONTROL:4.4 DESCRIPTION:Where multi-factor authentication is not supported (such as local administrator, root, or service accounts), accounts will use passwords that are unique to that system.;"


  describe aws_iam_password_policy do
    it { should exist }
    it { should prevent_password_reuse }
    its('number_of_passwords_to_remember') { should cmp == 24 }
  end
end