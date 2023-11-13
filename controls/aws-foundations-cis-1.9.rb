control 'aws-foundations-cis-1.9' do
  title 'Ensure IAM password policy prevents password reuse '
  desc "IAM password policies can prevent the reuse of a given password by the same user. It is
recommended that the password policy prevent the reuse of passwords. "
  desc 'rationale', "Preventing password reuse increases account resiliency against brute force login
attempts. "
  desc 'check', "Perform the following to ensure the password policy is configured as prescribed:

**From
Console:**

1. Login to AWS Console (with appropriate permissions to View Identity
Access Management Account Settings)
2. Go to IAM Service on the AWS Console
3. Click on
Account Settings on the Left Pane
4. Ensure \"Prevent password reuse\" is checked
5. Ensure
\"Number of passwords to remember\" is set to 24

**From Command Line:**
```
aws iam
get-account-password-policy
```
Ensure the output of the above command includes
\"PasswordReusePrevention\": 24 "
  desc 'fix', "Perform the following to set the password policy as prescribed:

**From
Console:**

1. Login to AWS Console (with appropriate permissions to View Identity
Access Management Account Settings)
2. Go to IAM Service on the AWS Console
3. Click on
Account Settings on the Left Pane
4. Check \"Prevent password reuse\"
5. Set \"Number of
passwords to remember\" is set to `24`

**From Command Line:**
```
 aws iam
update-account-password-policy --password-reuse-prevention 24
```
Note: All
commands starting with \"aws iam update-account-password-policy\" can be combined into a
single command. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy'
  tag nist: ['IA-5(1)']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['5.2'] },
  ]

  describe aws_iam_password_policy do
    it { should exist }
    it { should prevent_password_reuse }
    its('number_of_passwords_to_remember') { should cmp == 24 }
  end
end
