# encoding: UTF-8

control "aws-foundations-cis-3.7" do
  title "Ensure CloudTrail logs are encrypted at rest using KMS CMKs "
  desc "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs 
available to users and resources in accordance with IAM policies. AWS Key Management Service 
(KMS) is a managed service that helps create and control the encryption keys used to encrypt 
account data, and uses Hardware Security Modules (HSMs) to protect the security of 
encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) 
and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is 
recommended that CloudTrail be configured to use SSE-KMS. "
  desc "rationale", "Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log 
data as a given user must have S3 read permission on the corresponding log bucket and must be 
granted decrypt permission by the CMK policy. "
  desc "check", "Perform the following to determine if CloudTrail is configured to use SSE-KMS:

**From 
Console:**

1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
2. 
In the left navigation pane, choose `Trails` .
3. Select a Trail
4. Under the `S3` section, 
ensure `Encrypt log files` is set to `Yes` and a KMS key ID is specified in the `KSM Key Id` 
field.

**From Command Line:**

1. Run the following command:
```
 aws cloudtrail 
describe-trails 
```
2. For each trail listed, SSE-KMS is enabled if the trail has a 
`KmsKeyId` property defined. "
  desc "fix", "Perform the following to configure CloudTrail to use SSE-KMS:

**From Console:**

1. 
Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
2. 
In the left navigation pane, choose `Trails` .
3. Click on a Trail
4. Under the `S3` section 
click on the edit button (pencil icon)
5. Click `Advanced` 
6. Select an existing CMK from 
the `KMS key Id` drop-down menu
 - Note: Ensure the CMK is located in the same region as the S3 
bucket
 - Note: You will need to apply a KMS Key policy on the selected CMK in order for 
CloudTrail as a service to encrypt and decrypt log files using the CMK provided. Steps are 
provided [here](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html) 
for editing the selected CMK Key policy
7. Click `Save` 
8. You will see a notification 
message stating that you need to have decrypt permissions on the specified KMS key to decrypt 
log files.
9. Click `Yes` 

**From Command Line:**
```
aws cloudtrail update-trail 
--name <trail_name> --kms-id <cloudtrail_kms_key>
aws kms put-key-policy --key-id 
<cloudtrail_kms_key> --policy <cloudtrail_kms_key_policy>
``` "
  desc "additional_information", "3 statements which need to be added to the CMK policy:

1\\. Enable Cloudtrail to describe 
CMK properties
```
<pre class=\"programlisting\" style=\"font-style: normal;\">{
 
\"Sid\": \"Allow CloudTrail access\",
 \"Effect\": \"Allow\",
 \"Principal\": {
 \"Service\": 
\"cloudtrail.amazonaws.com\"
 },
 \"Action\": \"kms:DescribeKey\",
 \"Resource\": 
\"*\"
}
```
2\\. Granting encrypt permissions
```
<pre class=\"programlisting\" 
style=\"font-style: normal;\">{
 \"Sid\": \"Allow CloudTrail to encrypt logs\",
 \"Effect\": 
\"Allow\",
 \"Principal\": {
 \"Service\": \"cloudtrail.amazonaws.com\"
 },
 \"Action\": 
\"kms:GenerateDataKey*\",
 \"Resource\": \"*\",
 \"Condition\": {
 \"StringLike\": {
 
\"kms:EncryptionContext:aws:cloudtrail:arn\": [
 
\"arn:aws:cloudtrail:*:aws-account-id:trail/*\"
 ]
 }
 }
}
```
3\\. Granting 
decrypt permissions
```
<pre class=\"programlisting\" style=\"font-style: 
normal;\">{
 \"Sid\": \"Enable CloudTrail log decrypt permissions\",
 \"Effect\": \"Allow\",
 
\"Principal\": {
 \"AWS\": \"arn:aws:iam::aws-account-id:user/username\"
 },
 \"Action\": 
\"kms:Decrypt\",
 \"Resource\": \"*\",
 \"Condition\": {
 \"Null\": {
 
\"kms:EncryptionContext:aws:cloudtrail:arn\": \"false\"
 }
 }
}
``` "
  desc "impact", "Customer created keys incur an additional cost. See https://aws.amazon.com/kms/pricing/ 
for more information. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html:https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html'
  tag nist: []
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["3.11"]}
  ]
end