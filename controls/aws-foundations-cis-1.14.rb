# encoding: UTF-8

control "aws-foundations-cis-1.14" do
  title "Ensure hardware MFA is enabled for the \"root\" account"
  desc  "The root account is the most privileged user in an AWS account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they will be prompted for their user name and password as well as for an authentication code from their AWS MFA device. For Level 2, it is recommended that the root account be protected with a hardware MFA."
  desc  "rationale", "A hardware MFA has a smaller attack surface than a virtual MFA. For example, a hardware MFA does not suffer the attack surface introduced by the mobile smartphone on which a virtual MFA resides.

    **Note**: Using hardware MFA for many, many AWS accounts may create a logistical device management issue. If this is the case, consider implementing this Level 2 recommendation selectively to the highest security AWS accounts and the Level 1 recommendation applied to the remaining accounts.

    Link to order AWS compatible hardware MFA device: [http://onlinenoram.gemalto.com/](http://onlinenoram.gemalto.com/)"
  desc  "check", "
    Perform the following to determine if the root account has a hardware MFA setup:

    1. Run the following command to determine if the root account has MFA setup:
    ```
     aws iam get-account-summary | grep \"AccountMFAEnabled\"
    ```

    The `AccountMFAEnabled` property is set to `1` will ensure that root account has MFA (Virtual or Hardware) Enabled.
    If `AccountMFAEnabled` property is set to `0` the account is not compliant with this recommendation.

    2. If `AccountMFAEnabled` property is set to `1`, determine root account has Hardware MFA enabled.
    Run the following command to list all virtual MFA devices:
    ```
     aws iam list-virtual-mfa-devices
    ```
    If the output contains one MFA with the following Serial Number, it means the MFA is virtual, not hardware and the account is not compliant with this recommendation:

     `\"SerialNumber\": \"arn:aws:iam::__:mfa/root-account-mfa-device\"`"
  desc  "fix", "Perform the following to establish a hardware MFA for the root account:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/).

     Note: to manage MFA devices for the root AWS account, you must use your root account credentials to sign in to AWS. You cannot manage MFA devices for the root account using other credentials.
    2. Choose `Dashboard` , and under `Security Status` , expand `Activate MFA` on your root account.
    3. Choose `Activate MFA`
    4. In the wizard, choose `A hardware MFA` device and then choose `Next Step` .
    5. In the `Serial Number` box, enter the serial number that is found on the back of the MFA device.
    6. In the `Authentication Code 1` box, enter the six-digit number displayed by the MFA device. You might need to press the button on the front of the device to display the number.
    7. Wait 30 seconds while the device refreshes the code, and then enter the next six-digit number into the `Authentication Code 2` box. You might need to press the button on the front of the device again to display the second number.
    8. Choose `Next Step` . The MFA device is now associated with the AWS account. The next time you use your AWS account credentials to sign in, you must type a code from the hardware MFA device."
  impact 0.5
  tag severity: "Medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['IA-2(1)']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Use Multifactor Authentication For All Administrative Access CONTROL:4.5 DESCRIPTION:Use multi-factor authentication and encrypted channels for all administrative account access.;"
  tag ref: "CIS CSC v6.0 #5.6, #11.4, #12.6, #16.11:Order Hardware MFA: http://onlinenoram.gemalto.com/:http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html:http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html#enable-hw-mfa-for-root"

  
  describe aws_iam_root_user do
    it { should have_hardware_mfa_enabled }
  end
end