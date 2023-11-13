control "aws-foundations-cis-1.13" do
  title "Ensure there is only one active access key available for any single IAM user "
  desc "Access keys are long-term credentials for an IAM user or the AWS account 'root' user. You can
use access keys to sign programmatic requests to the AWS CLI or AWS API (directly or using the
AWS SDK) "
  desc "rationale",
       "Access keys are long-term credentials for an IAM user or the AWS account 'root' user. You can
use access keys to sign programmatic requests to the AWS CLI or AWS API. One of the best ways to
protect your account is to not allow users to have multiple access keys. "
  desc "check",
       "**From Console:**

1. Sign in to the AWS Management Console and navigate to IAM dashboard
at `https://console.aws.amazon.com/iam/`.
2. In the left navigation panel, choose
`Users`.
3. Click on the IAM user name that you want to examine.
4. On the IAM user
configuration page, select `Security Credentials` tab.
5. Under `Access Keys` section,
in the Status column, check the current status for each access key associated with the IAM
user. If the selected IAM user has more than one access key activated then the users access
configuration does not adhere to security best practices and the risk of accidental
exposures increases.
- Repeat steps no. 3 – 5 for each IAM user in your AWS
account.

**From Command Line:**

1. Run `list-users` command to list all IAM users
within your account:
```
aws iam list-users --query \"Users[*].UserName\"
```
The
command output should return an array that contains all your IAM user names.

2. Run
`list-access-keys` command using the IAM user name list to return the current status of each
access key associated with the selected IAM user:
```
aws iam list-access-keys
--user-name <user-name>
```
The command output should expose the metadata
`(\"Username\", \"AccessKeyId\", \"Status\", \"CreateDate\")` for each access key on that user
account.

3. Check the `Status` property value for each key returned to determine each
keys current state. If the `Status` property value for more than one IAM access key is set to
`Active`, the user access configuration does not adhere to this recommendation, refer to the
remediation below.

- Repeat steps no. 2 and 3 for each IAM user in your AWS account. "
  desc "fix",
       "**From Console:**

1. Sign in to the AWS Management Console and navigate to IAM dashboard
at `https://console.aws.amazon.com/iam/`.
2. In the left navigation panel, choose
`Users`.
3. Click on the IAM user name that you want to examine.
4. On the IAM user
configuration page, select `Security Credentials` tab.
5. In `Access Keys` section,
choose one access key that is less than 90 days old. This should be the only active key used by
this IAM user to access AWS resources programmatically. Test your application(s) to make
sure that the chosen access key is working.
6. In the same `Access Keys` section, identify
your non-operational access keys (other than the chosen one) and deactivate it by clicking
the `Make Inactive` link.
7. If you receive the `Change Key Status` confirmation box, click
`Deactivate` to switch off the selected key.
8. Repeat steps no. 3 – 7 for each IAM user in your
AWS account.

**From Command Line:**

1. Using the IAM user and access key information
provided in the `Audit CLI`, choose one access key that is less than 90 days old. This should be
the only active key used by this IAM user to access AWS resources programmatically. Test your
application(s) to make sure that the chosen access key is working.

2. Run the
`update-access-key` command below using the IAM user name and the non-operational access
key IDs to deactivate the unnecessary key(s). Refer to the Audit section to identify the
unnecessary access key ID for the selected IAM user

**Note** - the command does not return
any output:
```
aws iam update-access-key --access-key-id <access-key-id> --status
Inactive --user-name <user-name>
```
3. To confirm that the selected access key pair has
been successfully `deactivated` run the `list-access-keys` audit command again for that
IAM User:
```
aws iam list-access-keys --user-name <user-name>
```
- The command
output should expose the metadata for each access key associated with the IAM user. If the
non-operational key pair(s) `Status` is set to `Inactive`, the key has been successfully
deactivated and the IAM user access configuration adheres now to this
recommendation.

4. Repeat steps no. 1 – 3 for each IAM user in your AWS account. "
  impact 0.5
  ref "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
  tag nist: ["AC-2"]
  tag severity: "medium "
  tag cis_controls: [{ "8" => ["5"] }]
  describe "No Tests Defined Yet" do
    skip "No Tests have been written for this control yet"
  end
end
