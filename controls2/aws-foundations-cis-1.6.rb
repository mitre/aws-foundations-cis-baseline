# encoding: UTF-8

control "aws-foundations-cis-1.6" do
  title "Ensure hardware MFA is enabled for the 'root' user account "
  desc "The 'root' user account is the most privileged user in an AWS account. MFA adds an extra layer of 
protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS 
website, they will be prompted for their user name and password as well as for an 
authentication code from their AWS MFA device. For Level 2, it is recommended that the 'root' 
user account be protected with a hardware MFA. "
  desc "rationale", "A hardware MFA has a smaller attack surface than a virtual MFA. For example, a hardware MFA does 
not suffer the attack surface introduced by the mobile smartphone on which a virtual MFA 
resides.

**Note**: Using hardware MFA for many, many AWS accounts may create a 
logistical device management issue. If this is the case, consider implementing this Level 2 
recommendation selectively to the highest security AWS accounts and the Level 1 
recommendation applied to the remaining accounts. "
  desc "check", "Perform the following to determine if the 'root' user account has a hardware MFA setup:

1. 
Run the following command to determine if the 'root' account has MFA setup:
```
 aws iam 
get-account-summary | grep \"AccountMFAEnabled\"
```

The `AccountMFAEnabled` 
property is set to `1` will ensure that the 'root' user account has MFA (Virtual or Hardware) 
Enabled.
If `AccountMFAEnabled` property is set to `0` the account is not compliant with 
this recommendation.

2. If `AccountMFAEnabled` property is set to `1`, determine 
'root' account has Hardware MFA enabled.
Run the following command to list all virtual MFA 
devices:
```
 aws iam list-virtual-mfa-devices 
```
If the output contains one MFA 
with the following Serial Number, it means the MFA is virtual, not hardware and the account is 
not compliant with this recommendation:

 `\"SerialNumber\": 
\"arn:aws:iam::_<aws_account_number>_:mfa/root-account-mfa-device\"` "
  desc "fix", "Perform the following to establish a hardware MFA for the 'root' user account:

1. Sign in 
to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).
Note: 
to manage MFA devices for the AWS 'root' user account, you must use your 'root' account 
credentials to sign in to AWS. You cannot manage MFA devices for the 'root' account using other 
credentials.
2. Choose `Dashboard` , and under `Security Status` , expand `Activate MFA` 
on your root account.
3. Choose `Activate MFA` 
4. In the wizard, choose `A hardware MFA` 
device and then choose `Next Step` .
5. In the `Serial Number` box, enter the serial number 
that is found on the back of the MFA device.
6. In the `Authentication Code 1` box, enter the 
six-digit number displayed by the MFA device. You might need to press the button on the front of 
the device to display the number.
7. Wait 30 seconds while the device refreshes the code, and 
then enter the next six-digit number into the `Authentication Code 2` box. You might need to 
press the button on the front of the device again to display the second number.
8. Choose 
`Next Step` . The MFA device is now associated with the AWS account. The next time you use your 
AWS account credentials to sign in, you must type a code from the hardware MFA 
device.

Remediation for this recommendation is not available through AWS CLI. "
  desc "additional_information", "IAM User account 'root' for us-gov cloud regions does not have console access. This control is 
not applicable for us-gov cloud regions. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html#enable-hw-mfa-for-root'
  tag nist: []
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["6.5"]}
  ]
end