control "aws-foundations-cis-1.8" do
  title "Ensure IAM password policy requires minimum length of 14 or greater "
  desc "Password policies are, in part, used to enforce password complexity requirements. IAM
password policies can be used to ensure password are at least a given length. It is recommended
that the password policy require a minimum password length 14. "
  desc "rationale", "Setting a password complexity policy increases account resiliency against brute force
login attempts. "
  desc "check", "Perform the following to ensure the password policy is configured as prescribed:

**From
Console:**

1. Login to AWS Console (with appropriate permissions to View Identity
Access Management Account Settings)
2. Go to IAM Service on the AWS Console
3. Click on
Account Settings on the Left Pane
4. Ensure \"Minimum password length\" is set to 14 or
greater.

**From Command Line:**
```
aws iam
get-account-password-policy
```
Ensure the output of the above command includes
\"MinimumPasswordLength\": 14 (or higher) "
  desc "fix", "Perform the following to set the password policy as prescribed:

**From
Console:**

1. Login to AWS Console (with appropriate permissions to View Identity
Access Management Account Settings)
2. Go to IAM Service on the AWS Console
3. Click on
Account Settings on the Left Pane
4. Set \"Minimum password length\" to `14` or greater.
5.
Click \"Apply password policy\"

**From Command Line:**
```
 aws iam
update-account-password-policy --minimum-password-length 14
```
Note: All
commands starting with \"aws iam update-account-password-policy\" can be combined into a
single command. "
  impact 0.5
  ref "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy"
  tag nist: ["IA-5(1)"]
  tag severity: "medium "
  tag cis_controls: [
    { "8" => ["5"] },
  ]

  describe aws_iam_password_policy do
    it { should exist }
    its("minimum_password_length") { should cmp >= input("pwd_length") }
  end
end
