aws_cred_age = attribute('aws_cred_age')

control 'cis-aws-foundations-1.11' do
  title "Ensure IAM password policy expires passwords within #{aws_cred_age} days or less"
  desc  "IAM password policies can require passwords to be rotated or expired
after a given number of days. It is recommended that the password policy expire
passwords after #{aws_cred_age} days or less."
  impact 0.3
  tag "rationale": "Reducing the password lifetime increases account resiliency
against brute force login attempts. Additionally, requiring regular password
changes help in the following scenarios:

* Passwords can be stolen or compromised sometimes without your knowledge. This
can happen via a system compromise, software vulnerability, or internal threat.


* Certain corporate and government web filters or proxy servers have the
ability to intercept and record traffic even if it's encrypted.
* Many people use the same password for many systems such as work, email, and
personal.
* Compromised end user workstations might have a keystroke logger."
  tag "cis_impact": ''
  tag "cis_rid": '1.11'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['IA-5(1)', 'Rev_4']
  tag "cce_id": 'CCE-78909-9'
  tag "check": "Perform the following to ensure the password policy is
configured as prescribed:

'Via AWS Console:

* Login to AWS Console (with appropriate permissions to View Identity Access
Management Account Settings)
* Go to IAM Service on the AWS Console
* Click on Account Settings on the Left Pane
* Ensure 'Enable password expiration' is checked
* Ensure 'Password expiration period (in days):' is set to #{aws_cred_age} or less

'Via CLI

'aws iam get-account-password-policy

Ensure the output of the above command includes 'MaxPasswordAge': #{aws_cred_age} or less"
  tag "fix": "Perform the following to set the password policy as prescribed:

'Via AWS Console:

* Login to AWS Console (with appropriate permissions to View Identity Access
Management Account Settings)
* Go to IAM Service on the AWS Console
* Click on Account Settings on the Left Pane
* Check 'Enable password expiration'
* Set 'Password expiration period (in days):' to #{aws_cred_age} or less

' Via CLI

' aws iam update-account-password-policy --max-password-age #{aws_cred_age}

'Note: All commands starting with 'aws iam update-account-password-policy' can
be combined into a single command."

  describe aws_iam_password_policy do
    it { should exist }
  end

  describe aws_iam_password_policy do
    its('expire_passwords?') { should be true }
    its('max_password_age_in_days') { should cmp <= aws_cred_age }
  end if aws_iam_password_policy.exists?
end
