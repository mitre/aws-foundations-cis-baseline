control "aws-foundations-cis-1.10" do
  title "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console
password "
  desc "Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond
traditional credentials. With MFA enabled, when a user signs in to the AWS Console, they will
be prompted for their user name and password as well as for an authentication code from their
physical or virtual MFA token. It is recommended that MFA be enabled for all accounts that have
a console password. "
  desc "rationale",
       "Enabling MFA provides increased security for console access as it requires the
authenticating principal to possess a device that displays a time-sensitive key and have
knowledge of a credential. "
  desc "check",
       "Perform the following to determine if a MFA device is enabled for all IAM users having a console
password:

**From Console:**

1. Open the IAM console at
[https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
2.
In the left pane, select `Users`
3. If the `MFA` or `Password age` columns are not visible in
the table, click the gear icon at the upper right corner of the table and ensure a checkmark is
next to both, then click `Close`.
4. Ensure that for each user where the `Password age`
column shows a password age, the `MFA` column shows `Virtual`, `U2F Security Key`, or
`Hardware`.

**From Command Line:**

1. Run the following command (OSX/Linux/UNIX)
to generate a list of all IAM users along with their password and MFA status:
```
 aws iam
generate-credential-report
```
```
 aws iam get-credential-report --query
'Content' --output text | base64 -d | cut -d, -f1,4,8
```
2. The output of this command will
produce a table similar to the following:
```
 user,password_enabled,mfa_active

elise,false,false
 brandon,true,true
 rakesh,false,false
 helene,false,false

paras,true,true
 anitha,false,false
```
3. For any column having
`password_enabled` set to `true` , ensure `mfa_active` is also set to `true.` "
  desc "fix",
       "Perform the following to enable MFA:

**From Console:**

1. Sign in to the AWS
Management Console and open the IAM console at
'https://console.aws.amazon.com/iam/'
2. In the left pane, select `Users`.
3. In the
`User Name` list, choose the name of the intended MFA user.
4. Choose the `Security
Credentials` tab, and then choose `Manage MFA Device`.
5. In the `Manage MFA Device
wizard`, choose `Virtual MFA` device, and then choose `Continue`.

 IAM generates and
displays configuration information for the virtual MFA device, including a QR code graphic.
The graphic is a representation of the 'secret configuration key' that is available for
manual entry on devices that do not support QR codes.

6. Open your virtual MFA
application. (For a list of apps that you can use for hosting virtual MFA devices, see Virtual
MFA Applications at
https://aws.amazon.com/iam/details/mfa/#Virtual_MFA_Applications). If the virtual
MFA application supports multiple accounts (multiple virtual MFA devices), choose the
option to create a new account (a new virtual MFA device).
7. Determine whether the MFA app
supports QR codes, and then do one of the following:

 - Use the app to scan the QR code. For
example, you might choose the camera icon or choose an option similar to Scan code, and then use
the device's camera to scan the code.
 - In the Manage MFA Device wizard, choose Show secret
key for manual configuration, and then type the secret configuration key into your MFA
application.

 When you are finished, the virtual MFA device starts generating one-time
passwords.

8. In the `Manage MFA Device wizard`, in the `MFA Code 1 box`, type the
`one-time password` that currently appears in the virtual MFA device. Wait up to 30 seconds
for the device to generate a new one-time password. Then type the second `one-time password`
into the `MFA Code 2 box`.

9. Click `Assign MFA`. "
  desc "additional_information",
       "**Forced IAM User Self-Service Remediation**

Amazon has published a pattern that
forces users to self-service setup MFA before they have access to their complete permissions
set. Until they complete this step, they cannot access their full permissions. This pattern
can be used on new AWS accounts. It can also be used on existing accounts - it is recommended
users are given instructions and a grace period to accomplish MFA enrollment before active
enforcement on existing AWS accounts. "
  desc "impact",
       "AWS will soon end support for SMS multi-factor authentication (MFA). New customers are not
allowed to use this feature. We recommend that existing customers switch to one of the
following alternative methods of MFA. "
  impact 0.5
  ref "https://tools.ietf.org/html/rfc6238:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#enable-mfa-for-privileged-users:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html:https://blogs.aws.amazon.com/security/post/Tx2SJJYE082KBUK/How-to-Delegate-Management-of-Multi-Factor-Authentication-to-AWS-IAM-Users"
  tag nist: ["IA-2(1)"]
  tag severity: "medium "
  tag cis_controls: [{ "8" => ["6.5"] }]

  service_account_mfa_exceptions = input("service_account_mfa_exceptions")

  users_without_mfa =
    aws_iam_users
      .where(has_console_password: true)
      .where(has_mfa_enabled: false)
      .usernames

  if service_account_mfa_exceptions.compact.empty?
    describe "The active IAM users that do not have MFA enabled", :sensitive do
      subject { users_without_mfa }
      it { should be_empty }
    end
  else
    describe "The active IAM users that do not have MFA enabled
    (except for the documented service accounts: #{service_account_mfa_exceptions})",
             :sensitive do
      subject { users_without_mfa - service_account_mfa_exceptions }
      it { should be_empty }
    end
  end
end
