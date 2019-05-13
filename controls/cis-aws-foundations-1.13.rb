control 'cis-aws-foundations-1.13' do
  title "Ensure MFA is enabled for the 'root' account"
  desc  "The root account is the most privileged user in an AWS account. MFA
adds an extra layer of protection on top of a user name and password. With MFA
enabled, when a user signs in to an AWS website, they will be prompted for
their user name and password as well as for an authentication code from their
AWS MFA device.

'NOTE: When virtual MFA is used for root accounts, it is recommended that the
device used is NOT a personal device, but rather a dedicated mobile device
(tablet or phone) that is managed to be kept charged and secured independent of
any individual personal devices. ('non-personal virtual MFA') This lessens the
risks of losing access to the MFA due to device loss, device trade-in or if the
individual owning the device is no longer employed at the company."
  impact 0.3
  tag "rationale": "Enabling MFA provides increased security for console access
as it requires the authenticating principal to possess a device that emits a
time-sensitive key and have knowledge of a credential."
  tag "cis_impact": ''
  tag "cis_rid": '1.13'
  tag "cis_level": 1
  tag "csc_control": [['5.6', '11.4', '12.6', '16.11'], '6.0']
  tag "nist": ['IA-2(1)', 'SC-23', 'Rev_4']
  tag "cce_id": 'CCE-78911-5'
  tag "check": "Perform the following to determine if the root account has MFA
setup:


* Run the following command:

'aws iam get-account-summary | grep 'AccountMFAEnabled'
* Ensure the AccountMFAEnabled property is set to 1


"
  tag "fix": "Perform the following to establish MFA for the root account:


 'Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/iam/ [https://console.aws.amazon.com/iam/].<div
class='aws-note'>

'Note: to manage MFA devices for the root AWS account, you must use your root
account credentials to sign in to AWS. You cannot manage MFA devices for the
root account using other credentials.


 'Choose Dashboard, and under Security Status, expand Activate MFA on your root
account.

 'Choose Activate MFA

 'In the wizard, choose A virtual MFA device and then choose Next Step.

 'IAM generates and displays configuration information for the virtual MFA
device, including a QR code graphic. The graphic is a representation of the
'secret configuration key' that is available for manual entry on devices that
do not support QR codes.

 'Open your virtual MFA application. (For a list of apps that you can use for
hosting virtual MFA devices, see Virtual MFA Applications
[http://aws.amazon.com/iam/details/mfa/#Virtual_MFA_Applications].) If the
virtual MFA application supports multiple accounts (multiple virtual MFA
devices), choose the option to create a new account (a new virtual MFA device).

 'Determine whether the MFA app supports QR codes, and then do one of the
following:

 'Use the app to scan the QR code. For example, you might choose the camera icon
or choose an option similar to Scan code, and then use the device's camera to
scan the code.

 'In the Manage MFA Device wizard, choose Show secret key for manual
configuration, and then type the secret configuration key into your MFA
application.


'When you are finished, the virtual MFA device starts generating one-time
passwords.

 'In the Manage MFA Device wizard, in the Authentication Code 1 box, type the
one-time password that currently appears in the virtual MFA device. Wait up to
30 seconds for the device to generate a new one-time password. Then type the
second one-time password into the Authentication Code 2 box. Choose Active
Virtual MFA.
"
  describe aws_iam_root_user do
    it { should have_mfa_enabled }
  end
end
