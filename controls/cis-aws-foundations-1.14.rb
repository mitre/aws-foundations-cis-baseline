control 'cis-aws-foundations-1.14' do
  title "Ensure hardware MFA is enabled for the 'root' account"
  desc  "The root account is the most privileged user in an AWS account. MFA
adds an extra layer of protection on top of a user name and password. With MFA
enabled, when a user signs in to an AWS website, they will be prompted for
their user name and password as well as for an authentication code from their
AWS MFA device. For Level 2, it is recommended that the root account be
protected with a hardware MFA."
  impact 0.7
  tag "rationale": "A hardware MFA has a smaller attack surface than a virtual
MFA. For example, a hardware MFA does not suffer the attack surface introduced
by the mobile smartphone on which a virtual MFA resides.

'NOTE: Using hardware MFA for many, many AWS accounts may create a logistical
device management issue. If this is the case, consider implementing this Level
2 recommendation selectively to the highest security AWS accounts and the Level
1 recommendation applied to the remaining accounts.

'Link to order AWS compatible hardware MFA device:
http://onlinenoram.gemalto.com/ [http://onlinenoram.gemalto.com/]"
  tag "cis_impact": ''
  tag "cis_rid": '1.14'
  tag "cis_level": 2
  tag "csc_control": [['5.6', '11.4', '12.6', '16.11'], '6.0']
  tag "nist": ['IA-2(1)', 'SC-23', 'Rev_4']
  tag "cce_id": 'CCE-78911-5'
  tag "check": "Perform the following to determine if the root account has a
hardware MFA setup:


* Run the following command to list all virtual MFA devices:

'aws iam list-virtual-mfa-devices
* If the output contains one MFA with the following Serial Number, it means the
MFA is virtual, not hardware and the account is not compliant with this
recommendation:

' 'SerialNumber':
'arn:aws:iam::_<aws_account_number>_:mfa/root-account-mfa-device'
"
  tag "fix": "Perform the following to establish a hardware MFA for the root
account:


 'Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/iam/ [https://console.aws.amazon.com/iam/].<div
class='aws-note'>

'Note: to manage MFA devices for the root AWS account, you must use your root
account credentials to sign in to AWS. You cannot manage MFA devices for the
root account using other credentials.


 'Choose Dashboard, and under Security Status, expand Activate MFA on your root
account.

 'Choose Activate MFA

 'In the wizard, choose A hardware MFA device and then choose Next Step.

 'In the Serial Number box, enter the serial number that is found on the back of
the MFA device.

 'In the Authentication Code 1 box, enter the six-digit number displayed by the
MFA device. You might need to press the button on the front of the device to
display the number.

 'Wait 30 seconds while the device refreshes the code, and then enter the next
six-digit number into the Authentication Code 2 box. You might need to press
the button on the front of the device again to display the second number.

 'Choose Next Step. The MFA device is now associated with the AWS account. The
next time you use your AWS account credentials to sign in, you must type a code
from the hardware MFA device.
"

  describe aws_iam_root_user do
    it { should have_mfa_enabled }
    it { should_not have_virtual_mfa_enabled }
  end
end
