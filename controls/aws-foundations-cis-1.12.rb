control 'aws-foundations-cis-1.12' do
  title 'Ensure credentials unused for 45 days or greater are disabled '
  desc "AWS IAM users can access AWS resources using different types of credentials, such as
passwords or access keys. It is recommended that all credentials that have been unused in 45 or
greater days be deactivated or removed. "
  desc 'rationale', "Disabling or removing unnecessary credentials will reduce the window of opportunity for
credentials associated with a compromised or abandoned account to be used. "
  desc 'check', "Perform the following to determine if unused credentials exist:

**From
Console:**

1. Login to the AWS Management Console
2. Click `Services`
3. Click
`IAM`
4. Click on `Users`
5. Click the `Settings` (gear) icon.
6. Select `Console last
sign-in`, `Access key last used`, and `Access Key Id`
7. Click on `Close`
8. Check and
ensure that `Console last sign-in` is less than 45 days ago.

**Note** - `Never` means the
user has never logged in.

9. Check and ensure that `Access key age` is less than 45 days and
that `Access key last used` does not say `None`

If the user hasn't signed into the Console
in the last 45 days or Access keys are over 45 days old refer to the remediation.

**From
Command Line:**

**Download Credential Report:**

1. Run the following
commands:
```
 aws iam generate-credential-report

 aws iam get-credential-report
--query 'Content' --output text | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16 | grep -v
'^<root_account>'
```

**Ensure unused credentials do not exist:**

2. For each
user having `password_enabled` set to `TRUE` , ensure `password_last_used_date` is less
than `45` days ago.

- When `password_enabled` is set to `TRUE` and `password_last_used`
is set to `No_Information` , ensure `password_last_changed` is less than 45 days ago.

3.
For each user having an `access_key_1_active` or `access_key_2_active` to `TRUE` , ensure
the corresponding `access_key_n_last_used_date` is less than `45` days ago.

- When a
user having an `access_key_x_active` (where x is 1 or 2) to `TRUE` and corresponding
access_key_x_last_used_date is set to `N/A', ensure `access_key_x_last_rotated` is less
than 45 days ago. "
  desc 'fix', "**From Console:**

Perform the following to manage Unused Password (IAM user console
access)

1. Login to the AWS Management Console:
2. Click `Services`
3. Click `IAM`

4. Click on `Users`
5. Click on `Security Credentials`
6. Select user whose `Console
last sign-in` is greater than 45 days
7. Click `Security credentials`
8. In section
`Sign-in credentials`, `Console password` click `Manage`
9. Under Console Access select
`Disable`
10.Click `Apply`

Perform the following to deactivate Access Keys:

1.
Login to the AWS Management Console:
2. Click `Services`
3. Click `IAM`
4. Click on
`Users`
5. Click on `Security Credentials`
6. Select any access keys that are over 45 days
old and that have been used and
 - Click on `Make Inactive`
7. Select any access keys that are
over 45 days old and that have not been used and
 - Click the X to `Delete` "
  desc 'additional_information', "<root_account> is excluded in the audit since the root account should not be used for day to day
business and would likely be unused for more than 45 days. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#remove-credentials:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'
  tag nist: ['AC-2(3)']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['5.3'] },
  ]

  only_if('The IAM Credential report takes a long time to generate.') do
    !input('disable_slow_controls')
  end

  aws_iam_credential_report.where(password_enabled: false).entries.each do |user|
    describe "Password disabled for user (#{user.user})" do
      skip "Test not applicable since user's (#{user.user}) password is disabled"
    end
  end

  aws_iam_credential_report.where(password_enabled: true).entries.each do |user|
    describe "The user (#{user.user})" do
      if user.password_last_used.is_a? DateTime
        subject { ((Time.current - user.password_last_used) / (24 * 60 * 60)).to_i }
        it 'must have used their password within the last 45 days.' do
          expect(subject).to be < 45
        end
      elsif user.password_last_changed.is_a? DateTime
        subject { ((Time.current - user.password_last_changed) / (24 * 60 * 60)).to_i }
        it 'must have changed their password within the last 45 days if they have not used it within the last 45 days.' do
          expect(subject).to be < 45
        end
      else
        RSpec::Expectatations.fail_with('must have changed their password within the last 45 days if they have not used it within the last 45 days.')
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
        subject { ((Time.current - user.access_key_1_last_used_date) / (24 * 60 * 60)).to_i }
        it 'must have used access key 1 within the last 45 days.' do
          expect(subject).to be < 45
        end
      elsif user.access_key_1_last_rotated.is_a? DateTime
        subject { ((Time.current - user.access_key_1_last_rotated) / (24 * 60 * 60)).to_i }
        it 'must have rotated access key 1 within the last 45 days if they have not used it within the last 45 days.' do
          expect(subject).to be < 45
        end
      else
        RSpec::Expectatations.fail_with('must have rotated access key 1 within the last 45 days if they have not used it within the last 45 days.')
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
        subject { ((Time.current - user.access_key_2_last_used_date) / (24 * 60 * 60)).to_i }
        it 'must have used access key 2 within the last 45 days.' do
          expect(subject).to be < 45
        end
      elsif user.access_key_2_last_rotated.is_a? DateTime
        subject { ((Time.current - user.access_key_2_last_rotated) / (24 * 60 * 60)).to_i }
        it 'must have rotated access key 2 within the last 45 days if they have not used it within the last 45 days.' do
          expect(subject).to be < 45
        end
      else
        RSpec::Expectatations.fail_with('must have rotated access key 2 within the last 45 days if they have not used it within the last 45 days.')
      end
    end
  end
end
