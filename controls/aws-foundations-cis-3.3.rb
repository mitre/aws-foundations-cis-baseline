control 'aws-foundations-cis-3.3' do
  title 'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible '
  desc "CloudTrail logs a record of every API call made in your AWS account. These logs file are stored
in an S3 bucket. It is recommended that the bucket policy or access control list (ACL) applied
to the S3 bucket that CloudTrail logs to prevent public access to the CloudTrail logs. "
  desc 'rationale',
       "Allowing public access to CloudTrail log content may aid an adversary in identifying
weaknesses in the affected account's use or configuration. "
  desc 'check',
       "Perform the following to determine if any public access is granted to an S3 bucket via an ACL or
S3 bucket policy:

**From Console:**

1. Go to the Amazon CloudTrail console at [https://console.aws.amazon.com/cloudtrail/home](https://console.aws.amazon.com/cloudtrail/home).
2.
In the `API activity history` pane on the left, click `Trails`.
3. In the `Trails` pane, note
the bucket names in the `S3 bucket` column
4. Go to Amazon S3 console at [https://console.aws.amazon.com/s3/home](https://console.aws.amazon.com/s3/home).
5.
For each bucket noted in step 3, right-click on the bucket and click `Properties`.
6. In the
`Properties` pane, click the `Permissions` tab.
7. The tab shows a list of grants, one row
per grant, in the bucket ACL. Each row identifies the grantee and the permissions
granted.
8. Ensure no rows exists that have the `Grantee` set to `Everyone` or the `Grantee`
set to `Any Authenticated User.`
9. If the `Edit bucket policy` button is present, click it
to review the bucket policy.
10. Ensure the policy does not contain a `Statement` having an
`Effect` set to `Allow` and a `Principal` set to \"\\*\" or {\"AWS\": \"\\*\"}, or if it does, ensure
that it has a condition in place to restrict access, such as
`aws:PrincipalOrgID`.

**From Command Line:**

1. Get the name of the S3 bucket that
CloudTrail is logging to:
```
 aws cloudtrail describe-trails --query
'trailList[*].S3BucketName'
```
2. Ensure the `AllUsers` principal is not granted
privileges to that `<bucket>` :
```
 aws s3api get-bucket-acl --bucket
<s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI==
`https://acs.amazonaws.com/groups/global/AllUsers` ]'
```
3. Ensure the
`AuthenticatedUsers` principal is not granted privileges to that `<bucket>`:
```
 aws
s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query
'Grants[?Grantee.URI== `https://acs.amazonaws.com/groups/global/Authenticated
Users`]'
```
4. Get the S3 Bucket Policy
```
 aws s3api get-bucket-policy --bucket
<s3_bucket_for_cloudtrail>
```
5. Ensure the policy does not contain a `Statement`
having an `Effect` set to `Allow` and a `Principal` set to \"\\*\" or {\"AWS\": \"\\*\"}.
Additionally, check to see whether a condition has been added to the bucket policy covering
`aws:PrincipalOrgID`, as having this (in the StringEquals or StringEqualsIgnoreCase)
would restrict access to only the named Org ID.

**Note:** Principal set to \"\\*\" or {\"AWS\":
\"\\*\"}, without any conditions, allows anonymous access. "
  desc 'fix',
       "Perform the following to remove any public access that has been granted to the bucket via an ACL
or S3 bucket policy:

1. Go to Amazon S3 console at [https://console.aws.amazon.com/s3/home](https://console.aws.amazon.com/s3/home).
2.
Right-click on the bucket and click Properties
3. In the `Properties` pane, click the
`Permissions` tab.
4. The tab shows a list of grants, one row per grant, in the bucket ACL.
Each row identifies the grantee and the permissions granted.
5. Select the row that grants
permission to `Everyone` or `Any Authenticated User`.
6. Uncheck all the permissions
granted to `Everyone` or `Any Authenticated User` (click `x` to delete the row).
7. Click
`Save` to save the ACL.
8. If the `Edit bucket policy` button is present, click it.
9.
Remove any `Statement` having an `Effect` set to `Allow` and a `Principal` set to \"\\*\" or
{\"AWS\": \"\\*\"}, that doesn't also have a condition to restrict access, such as
`aws:PrincipalOrgID`. "
  desc 'default_value', 'By default, S3 buckets are not publicly accessible. '
  impact 0.5
  ref 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html'
  tag nist: ['AC-3']
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['3.3'] }]

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  if aws_cloudtrail_trails.exist?
    aws_cloudtrail_trails.trail_arns.each do |trail|
      bucket_name = aws_cloudtrail_trail(trail).s3_bucket_name
      if input('exempt_buckets').include?(bucket_name)
        describe 'Bucket not inspected because it is defined as an exception' do
          skip "Bucket: #{bucket_name} not inspected because it is defined in exempt_buckets."
        end
      else
        describe aws_s3_bucket(bucket_name) do
          it { should_not be_public }
        end
      end
    end
  end
end
