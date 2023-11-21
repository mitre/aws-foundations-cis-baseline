control "aws-foundations-cis-1.7" do
  title "Eliminate use of the 'root' user for administrative and daily tasks "
  desc "With the creation of an AWS account, a 'root user' is created that cannot be disabled or
deleted. That user has unrestricted access to and control over all resources in the AWS
account. It is highly recommended that the use of this account be avoided for everyday tasks. "
  desc "rationale",
       "The 'root user' has unrestricted access to and control over all account resources. Use of it is
inconsistent with the principles of least privilege and separation of duties, and can lead to
unnecessary harm due to error or account compromise. "
  desc "check",
       "**From Console:**

1. Login to the AWS Management Console at
`https://console.aws.amazon.com/iam/`
2. In the left pane, click `Credential
Report`
3. Click on `Download Report`
4. Open of Save the file locally
5. Locate the
`<root account>` under the user column
6. Review `password_last_used,
access_key_1_last_used_date, access_key_2_last_used_date` to determine when the 'root
user' was last used.

**From Command Line:**

Run the following CLI commands to
provide a credential report for determining the last time the 'root user' was
used:
```
aws iam generate-credential-report
```
```
aws iam
get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 |
grep -B1 '<root_account>'
```

Review `password_last_used`,
`access_key_1_last_used_date`, `access_key_2_last_used_date` to determine when the
_root user_ was last used.

**Note:** There are a few conditions under which the use of the
'root' user account is required. Please see the reference links for all of the tasks that
require use of the 'root' user. "
  desc "fix",
       "If you find that the 'root' user account is being used for daily activity to include
administrative tasks that do not require the 'root' user:

1. Change the 'root' user
password.
2. Deactivate or delete any access keys associate with the 'root'
user.

**Remember, anyone who has 'root' user credentials for your AWS account has
unrestricted access to and control of all the resources in your account, including billing
information. "
  desc "additional_information",
       "The 'root' user for us-gov cloud regions is not enabled by default. However, on request to AWS
support, they can enable the 'root' user and grant access only through access-keys (CLI, API
methods) for us-gov cloud region. If the 'root' user for us-gov cloud regions is enabled, this
recommendation is applicable.

Monitoring usage of the 'root' user can be accomplished
by implementing recommendation 3.3 Ensure a log metric filter and alarm exist for usage of the
'root' user. "
  impact 0.5
  ref "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html:https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html"
  tag nist: %w[AC-6(2) AC-6(5)]
  tag severity: "medium "
  tag cis_controls: [{ "8" => ["5.4"] }]

  
  credential_report = aws_iam_credential_report.where( user: '<root_account>' )

  if !input('last_root_login_date').zero?
    last_root_login_date = DateTime.strptime(input('last_root_login_date').to_s, '%Y%m%d')
    describe "The root user" do
      it "should not have logged in via password since #{last_root_login_date.strftime('%Y%m%d')}" do
        expect(credential_report.password_last_used.first).to eq("N/A").or be <= last_root_login_date
      end
      it "should not have logged in via an access key (key 1) since #{last_root_login_date.strftime('%Y%m%d')}" do
        expect(credential_report.access_key_1_last_used_date.first).to eq("N/A").or be <= last_root_login_date
      end
      it "should not have logged in via an access key (key 2) since #{last_root_login_date.strftime('%Y%m%d')}" do
        expect(credential_report.access_key_2_last_used_date.first).to eq("N/A").or be <= last_root_login_date
      end
    end
  else
    describe "Manual review required" do
      skip "Last use date of root password:\t'#{credential_report.password_last_used.first}'\nLast use date of root access key 1:\t'#{credential_report.access_key_1_last_used_date.first}'\nLast use date of root access key 2:\t'#{credential_report.access_key_2_last_used_date.first}'\n\nReview to ensure this usage meets security requirements for your organization."
    end
  end
end
