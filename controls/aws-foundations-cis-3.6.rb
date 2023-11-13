control 'aws-foundations-cis-3.6' do
  title 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket '
  desc "S3 Bucket Access Logging generates a log that contains access records for each request made to
your S3 bucket. An access log record contains details about the request, such as the request
type, the resources specified in the request worked, and the time and date the request was
processed. It is recommended that bucket access logging be enabled on the CloudTrail S3
bucket. "
  desc 'rationale', "By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which
may affect objects within any target buckets. Configuring logs to be placed in a separate
bucket allows access to log information which can be useful in security and incident response
workflows. "
  desc 'check', "Perform the following ensure the CloudTrail S3 bucket has access logging is
enabled:

**From Console:**

1. Go to the Amazon CloudTrail console at [https://console.aws.amazon.com/cloudtrail/home](https://console.aws.amazon.com/cloudtrail/home)
2.
In the API activity history pane on the left, click Trails
3. In the Trails pane, note the
bucket names in the S3 bucket column
4. Sign in to the AWS Management Console and open the S3
console at
[https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
5.
Under `All Buckets` click on a target S3 bucket
6. Click on `Properties` in the top right of
the console
7. Under `Bucket:` _ `<bucket_name>` _ click on `Logging`
8. Ensure
`Enabled` is checked.

**From Command Line:**

1. Get the name of the S3 bucket that
CloudTrail is logging to:
```
aws cloudtrail describe-trails --query
'trailList[*].S3BucketName'
```
2. Ensure Bucket Logging is enabled:
```
aws
s3api get-bucket-logging --bucket <s3_bucket_for_cloudtrail>
```
Ensure command
does not returns empty output.

Sample Output for a bucket with logging
enabled:

```
{
 \"LoggingEnabled\": {
 \"TargetPrefix\": \"<Prefix_Test>\",

\"TargetBucket\": \"<Bucket_name_for_Storing_Logs>\"
 }
}
``` "
  desc 'fix', "Perform the following to enable S3 bucket logging:

**From Console:**

1. Sign in to
the AWS Management Console and open the S3 console at
[https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
2.
Under `All Buckets` click on the target S3 bucket
3. Click on `Properties` in the top right of
the console
4. Under `Bucket:` <s3\\_bucket\\_for\\_cloudtrail> click on `Logging`
5.
Configure bucket logging
 - Click on the `Enabled` checkbox
 - Select Target Bucket from
list
 - Enter a Target Prefix
6. Click `Save`.

**From Command Line:**

1. Get the
name of the S3 bucket that CloudTrail is logging to:
```
aws cloudtrail describe-trails
--region <region-name> --query trailList[*].S3BucketName
```
2. Copy and add target
bucket name at `<Logging_BucketName>`, Prefix for logfile at `<LogFilePrefix>` and
optionally add an email address in the following template and save it as
`<FileName.Json>`:
```
{
 \"LoggingEnabled\": {
 \"TargetBucket\":
\"<Logging_BucketName>\",
 \"TargetPrefix\": \"<LogFilePrefix>\",
 \"TargetGrants\": [

{
 \"Grantee\": {
 \"Type\": \"AmazonCustomerByEmail\",
 \"EmailAddress\": \"<EmailID>\"

},
 \"Permission\": \"FULL_CONTROL\"
 }
 ]
 }
}
```
3. Run the `put-bucket-logging`
command with bucket name and `<FileName.Json>` as input, for more information refer at [put-bucket-logging](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-logging.html):
```
aws
s3api put-bucket-logging --bucket <BucketName> --bucket-logging-status
file://<FileName.Json>
``` "
  desc 'default_value', 'Logging is disabled. '
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html'
  tag nist: %w(AU-12 AU-2)
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['3.14'] },
  ]

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    bucket_name = aws_cloudtrail_trail(trail).s3_bucket_name
    if input('exception_bucket_list').include?(bucket_name)
      describe 'Bucket not inspected because it is defined as an exception' do
        skip "Bucket: #{bucket_name} not inspected because it is defined in exception_bucket_list."
      end
    else
      describe aws_s3_bucket(bucket_name) do
        it { should have_access_logging_enabled }
      end
    end
  end

  # Use this after skeletal aws_cloudtrail_trails is enhanced to expose s3_bucket_name
  # aws_cloudtrail_trails.s3_bucket_name.uniq.each do |bucket|
  #   describe aws_s3_bucket( bucket ) do
  #     it{ should be_logging_enabled }
  #   end
  # end
end
