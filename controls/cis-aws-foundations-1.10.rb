control 'cis-aws-foundations-1.10' do
  title 'Ensure IAM password policy prevents password reuse'
  desc  "IAM password policies can prevent the reuse of a given password by the
same user. It is recommended that the password policy prevent the reuse of
passwords."
  impact 0.3
  tag "rationale": "Preventing password reuse increases account resiliency
against brute force login attempts."
  tag "cis_impact": ''
  tag "cis_rid": '1.10'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['IA-5(1)', 'Rev_4']
  tag "cce_id": 'CCE-78908-1'
  tag "check": "Perform the following to ensure the password policy is
configured as prescribed:

'Via AWS Console

* Login to AWS Console (with appropriate permissions to View Identity Access
Management Account Settings)
* Go to IAM Service on the AWS Console
* Click on Account Settings on the Left Pane
* Ensure 'Prevent password reuse' is checked
* Ensure 'Number of passwords to remember' is set to 24

'Via CLI

'aws iam get-account-password-policy

Ensure the output of the above command includes 'PasswordReusePrevention': 24"
  tag "fix": "Perform the following to set the password policy as prescribed:

'Via AWS Console

* Login to AWS Console (with appropriate permissions to View Identity Access
Management Account Settings)
* Go to IAM Service on the AWS Console
* Click on Account Settings on the Left Pane
* Check 'Prevent password reuse'
* Set 'Number of passwords to remember' is set to 24

' Via CLI

' aws iam update-account-password-policy --password-reuse-prevention 24

'Note: All commands starting with 'aws iam update-account-password-policy' can
be combined into a single command."

  describe aws_iam_password_policy do
    it { should exist }
  end

  describe aws_iam_password_policy do
    its('prevent_password_reuse?') { should be true }
    its('number_of_passwords_to_remember') { should cmp <= 24 }
  end if aws_iam_password_policy.exists?
end
