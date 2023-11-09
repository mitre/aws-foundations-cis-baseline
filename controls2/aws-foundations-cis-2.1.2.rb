# encoding: UTF-8

control "aws-foundations-cis-2.1.2" do
  title "Ensure MFA Delete is enabled on S3 buckets "
  desc "Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to 
have two forms of authentication. "
  desc "rationale", "Adding MFA delete to an S3 bucket, requires additional authentication when you change the 
version state of your bucket or you delete and object version adding another layer of security 
in the event your security credentials are compromised or unauthorized access is granted. "
  desc "check", "Perform the steps below to confirm MFA delete is configured on an S3 Bucket

**From 
Console:**

1. Login to the S3 console at `https://console.aws.amazon.com/s3/`

2. 
Click the `Check` box next to the Bucket name you want to confirm

3. In the window under 
`Properties`

4. Confirm that Versioning is `Enabled`

5. Confirm that MFA Delete is 
`Enabled`

**From Command Line:**

1. Run the `get-bucket-versioning`
```
aws 
s3api get-bucket-versioning --bucket my-bucket
```

Output 
example:
```
<VersioningConfiguration 
xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"> 
 <Status>Enabled</Status>
 
<MfaDelete>Enabled</MfaDelete> 
</VersioningConfiguration>
```

If the Console 
or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation 
below. "
  desc "fix", "Perform the steps below to enable MFA delete on an S3 bucket.

Note:
-You cannot enable 
MFA Delete using the AWS Management Console. You must use the AWS CLI or API.
-You must use 
your 'root' account to enable MFA Delete on S3 buckets.

**From Command line:**

1. Run 
the s3api put-bucket-versioning command

```
aws s3api put-bucket-versioning 
--profile my-root-profile --bucket Bucket_Name --versioning-configuration 
Status=Enabled,MFADelete=Enabled --mfa 
“arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”
``` "
  desc "impact", "Enabling MFA delete on an S3 bucket could required additional administrator oversight. 
Enabling MFA delete may impact other services that automate the creation and/or deletion of 
S3 buckets. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html'
  tag nist: []
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["3.3"]}
  ]
end