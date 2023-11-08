# encoding: UTF-8

control "aws-foundations-cis-2.1.1" do
  title "Ensure S3 Bucket Policy is set to deny HTTP requests "
  desc "At the Amazon S3 bucket level, you can configure permissions through a bucket policy making 
the objects accessible only through HTTPS. "
  desc "rationale", "By default, Amazon S3 allows both HTTP and HTTPS requests. To achieve only allowing access to 
Amazon S3 objects through HTTPS you also have to explicitly deny access to HTTP requests. 
Bucket policies that allow HTTPS requests without explicitly denying HTTP requests will not 
comply with this recommendation. "
  desc "check", "To allow access to HTTPS you can use a condition that checks for the key 
`\"aws:SecureTransport: true\"`. This means that the request is sent through HTTPS but that 
HTTP can still be used. So to make sure you do not allow HTTP access confirm that there is a bucket 
policy that explicitly denies access for HTTP requests and that it contains the key 
\"aws:SecureTransport\": \"false\".

**From Console:**

1. Login to AWS Management 
Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
2. 
Select the Check box next to the Bucket.
3. Click on 'Permissions', then Click on `Bucket 
Policy`.
4. Ensure that a policy is listed that matches:
```
'{
 \"Sid\": <optional>,
 
\"Effect\": \"Deny\",
 \"Principal\": \"*\",
 \"Action\": \"s3:*\",
 \"Resource\": 
\"arn:aws:s3:::<bucket_name>/*\",
 \"Condition\": {
 \"Bool\": {
 
\"aws:SecureTransport\": \"false\"
 }'
```
`<optional>` and `<bucket_name>` will be 
specific to your account

5. Repeat for all the buckets in your AWS account.

**From 
Command Line:**

1. List all of the S3 Buckets 
```
aws s3 ls
```
2. Using the list of 
buckets run this command on each of them:
```
aws s3api get-bucket-policy --bucket 
<bucket_name> | grep aws:SecureTransport
```
3. Confirm that `aws:SecureTransport` 
is set to false `aws:SecureTransport:false`
4. Confirm that the policy line has Effect set 
to Deny 'Effect:Deny' "
  desc "fix", "**From Console:**

1. Login to AWS Management Console and open the Amazon S3 console using 
https://console.aws.amazon.com/s3/
2. Select the Check box next to the Bucket.
3. 
Click on 'Permissions'.
4. Click 'Bucket Policy'
5. Add this to the existing policy 
filling in the required information
```
{
 \"Sid\": <optional>\",
 \"Effect\": \"Deny\",
 
\"Principal\": \"*\",
 \"Action\": \"s3:*\",
 \"Resource\": 
\"arn:aws:s3:::<bucket_name>/*\",
 \"Condition\": {
 \"Bool\": {
 
\"aws:SecureTransport\": \"false\"
 }
 }
 }
```
6. Save
7. Repeat for all the buckets in 
your AWS account that contain sensitive data.

**From Console** 

using AWS Policy 
Generator:

1. Repeat steps 1-4 above.
2. Click on `Policy Generator` at the bottom of 
the Bucket Policy Editor
3. Select Policy Type
`S3 Bucket Policy`
4. Add Statements
- 
`Effect` = Deny
- `Principal` = *
- `AWS Service` = Amazon S3
- `Actions` = *
- `Amazon 
Resource Name` = <ARN of the S3 Bucket>
5. Generate Policy
6. Copy the text and add it to the 
Bucket Policy.

**From Command Line:**

1. Export the bucket policy to a json 
file.
```
aws s3api get-bucket-policy --bucket <bucket_name> --query Policy --output 
text > policy.json
```

2. Modify the policy.json file by adding in this 
statement:
```
{
 \"Sid\": <optional>\",
 \"Effect\": \"Deny\",
 \"Principal\": \"*\",
 
\"Action\": \"s3:*\",
 \"Resource\": \"arn:aws:s3:::<bucket_name>/*\",
 \"Condition\": {
 
\"Bool\": {
 \"aws:SecureTransport\": \"false\"
 }
 }
 }
```
3. Apply this modified 
policy back to the S3 bucket:
```
aws s3api put-bucket-policy --bucket <bucket_name> 
--policy file://policy.json
``` "
  impact 0.5
  ref 'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/:https://aws.amazon.com/blogs/security/how-to-use-bucket-policies-and-apply-defense-in-depth-to-help-secure-your-amazon-s3-data/:https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/get-bucket-policy.html'
  tag nist: []
  tag severity: "medium "
end