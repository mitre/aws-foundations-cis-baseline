control 'cis-aws-foundations-2.7' do
  title 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs'
  desc  "AWS CloudTrail is a web service that records AWS API calls for an
account and makes those logs available to users and resources in accordance
with IAM policies. AWS Key Management Service (KMS) is a managed service that
helps create and control the encryption keys used to encrypt account data, and
uses Hardware Security Modules (HSMs) to protect the security of encryption
keys. CloudTrail logs can be configured to leverage server side encryption
(SSE) and KMS customer created master keys (CMK) to further protect CloudTrail
logs. It is recommended that CloudTrail be configured to use SSE-KMS."
  impact 0.7
  tag "rationale": "Configuring CloudTrail to use SSE-KMS provides additional
confidentiality controls on log data as a given user must have S3 read
permission on the corresponding log bucket and must be granted decrypt
permission by the CMK policy."
  tag "cis_impact": "Customer created keys incur an additional cost. See
https://aws.amazon.com/kms/pricing/ for more information."
  tag "cis_rid": '2.7'
  tag "cis_level": 2
  tag "csc_control": [['13.1'], '6.0']
  tag "nist": ['AU-9', 'Rev_4']
  tag "cce_id": 'CCE-78919-8'
  tag "check": "Perform the following to determine if CloudTrail is configured
to use SSE-KMS:

'Via the Management Console

 'Sign in to the AWS Management Console and open the CloudTrail console at
https://console.aws.amazon.com/cloudtrail
[https://console.aws.amazon.com/cloudtrail]
* In the left navigation pane, choose Trails.
* Select a Trail
* Under the S3 section, ensure Encrypt log files is set to Yes and a KMS key ID
is specified in the KSM Key Id field.

'Via CLI

* Run the following command:

'aws cloudtrail describe-trails
* For each trail listed, SSE-KMS is enabled if the trail has a KmsKeyId
property defined."
  tag "fix": "Perform the following to configure CloudTrail to use SSE-KMS:

'Via the Management Console

 'Sign in to the AWS Management Console and open the CloudTrail console at
https://console.aws.amazon.com/cloudtrail
[https://console.aws.amazon.com/cloudtrail]
* In the left navigation pane, choose Trails.
* Click on a Trail
* Under the S3 section click on the edit button (pencil icon)
* Click Advanced

* Select an existing CMK from the KMS key Id drop-down menu

* Note: Ensure the CMK is located in the same region as the S3 bucket
* Note: You will need to apply a KMS Key policy on the selected CMK in order
for CloudTrail as a service to encrypt and decrypt log files using the CMK
provided. Steps are provided here
[https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html]
for editing the selected CMK Key policy


* Click Save
* You will see a notification message stating that you need to have decrypt
permissions on the specified KMS key to decrypt log files.
* Click Yes

'Via CLI

'aws cloudtrail update-trail --name <_trail_name_> --kms-id
<_cloudtrail_kms_key_>
aws kms put-key-policy --key-id <_cloudtrail_kms_key_> --policy
<_cloudtrail_kms_key_policy_>"

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      its('kms_key_id') { should_not be_nil }
    end
  end
end
