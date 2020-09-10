# encoding: UTF-8

control "aws-foundations-cis-2.6" do
  title "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
  desc  "S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket."
  desc  "rationale", "By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within an target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows."
  desc  "check", "Perform the following ensure the CloudTrail S3 bucket has access logging is enabled:

    Via the management Console
    1. Go to the Amazon CloudTrail console at [https://console.aws.amazon.com/cloudtrail/home](https://console.aws.amazon.com/cloudtrail/home)
    2. In the API activity history pane on the left, click Trails
    3. In the Trails pane, note the bucket names in the S3 bucket column
    4. Sign in to the AWS Management Console and open the S3 console at [https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
    5. Under `All Buckets` click on a target S3 bucket
    6. Click on `Properties` in the top right of the console
    7. Under `Bucket:` _ `` _ click on `Logging`
    8. Ensure `Enabled` is checked.

    Via CLI
    1. Get the name of the S3 bucket that CloudTrail is logging to:
    ```
    aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'
    ```
    2. Ensure Bucket Logging is enabled:
    ```
    aws s3api get-bucket-logging --bucket
    ```
    Ensure command does not returns empty output.
    Sample Output for a bucket with logging enabled:
    ```
    {
     \"LoggingEnabled\": {
     \"TargetPrefix\": \"\t\",
     \"TargetBucket\": \"\"
     }
    }
    ```"
  desc  "fix", "Perform the following to enable S3 bucket logging:

    Via the Management Console
    1. Sign in to the AWS Management Console and open the S3 console at [https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
    2. Under `All Buckets` click on the target S3 bucket
    3. Click on `Properties` in the top right of the console
    4. Under `Bucket:`  click on `Logging`
    5. Configure bucket logging
     1. Click on `Enabled` checkbox
     2. Select Target Bucket from list
     3. Enter a Target Prefix
    6. Click `Save`"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-12', 'AU-2']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Activate audit logging CONTROL:6.2 DESCRIPTION:Ensure that local logging has been enabled on all systems and networking devices.;TITLE:Enforce Detail Logging for Access or Changes to Sensitive Data CONTROL:14.9 DESCRIPTION:Enforce detailed audit logging for access to sensitive data or changes to sensitive data (utilizing tools such as File Integrity Monitoring or Security Information and Event Monitoring).;"
  tag ref: "CIS CSC v6.0 #14.6"

  
  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    bucket_name = aws_cloudtrail_trail(trail).s3_bucket_name
    if input("exception_bucket_list").include?(bucket_name)
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