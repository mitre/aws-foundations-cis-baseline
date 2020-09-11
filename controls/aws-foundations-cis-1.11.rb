# encoding: UTF-8

control "aws-foundations-cis-1.11" do
  title "Ensure IAM password policy expires passwords within 90 days or less"
  desc  "IAM password policies can require passwords to be rotated or expired after a given number of days. It is recommended that the password policy expire passwords after 90 days or less."
  desc  "rationale", "Reducing the password lifetime increases account resiliency against brute force login attempts. Additionally, requiring regular password changes help in the following scenarios:

    - Passwords can be stolen or compromised sometimes without your knowledge. This can happen via a system compromise, software vulnerability, or internal threat.
    - Certain corporate and government web filters or proxy servers have the ability to intercept and record traffic even if it's encrypted.
    - Many people use the same password for many systems such as work, email, and personal.
    - Compromised end user workstations might have a keystroke logger."
  desc  "check", "Perform the following to ensure the password policy is configured as prescribed:

    Via AWS Console:

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Ensure \"Enable password expiration\" is checked
    5. Ensure \"Password expiration period (in days):\" is set to 90 or less

    Via CLI
    ```
    aws iam get-account-password-policy
    ```
    Ensure the output of the above command includes \"MaxPasswordAge\": 90 or less"
  desc  "fix", "Perform the following to set the password policy as prescribed:

    Via AWS Console:

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service on the AWS Console
    3. Click on Account Settings on the Left Pane
    4. Check \"Enable password expiration\"
    5. Set \"Password expiration period (in days):\" to 90 or less

     Via CLI
    ```
     aws iam update-account-password-policy --max-password-age 90
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
    it { should expire_passwords }
    its('max_password_age_in_days') { should cmp <= input("aws_cred_age") }
  end
end