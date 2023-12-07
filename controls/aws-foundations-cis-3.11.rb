control 'aws-foundations-cis-3.11' do
  title 'Ensure that Object-level logging for read events is enabled for S3 bucket '
  desc "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called
data events. By default, CloudTrail trails don't log data events and so it is recommended to
enable Object-level logging for S3 buckets. "
  desc 'rationale',
       "Enabling object-level logging will help you meet data compliance requirements within your
organization, perform comprehensive security analysis, monitor specific patterns of user
behavior in your AWS account or take immediate actions on any object-level API activity using
Amazon CloudWatch Events. "
  desc 'check',
       "**From Console:**

1. Login to the AWS Management Console and navigate to S3 dashboard at
`https://console.aws.amazon.com/s3/`
2. In the left navigation panel, click `buckets`
and then click on the S3 Bucket Name that you want to examine.
3. Click `Properties` tab to see
in detail bucket configuration.
4. If the current status for `Object-level` logging is set
to `Disabled`, then object-level logging of read events for the selected s3 bucket is not
set.
5. If the current status for `Object-level` logging is set to `Enabled`, but the Read
event check-box is unchecked, then object-level logging of read events for the selected s3
bucket is not set.
6. Repeat steps 2 to 5 to verify `object-level` logging for `read` events
of your other S3 buckets.

**From Command Line:**
1. Run `describe-trails` command to
list the names of all Amazon CloudTrail trails currently available in the selected AWS
region:
```
aws cloudtrail describe-trails --region <region-name> --output table
--query trailList[*].Name
```
2. The command output will be table of the requested trail
names.
3. Run `get-event-selectors` command using the name of the trail returned at the
previous step and custom query filters to determine if Data events logging feature is enabled
within the selected CloudTrail trail configuration for s3 bucket resources:
```
aws
cloudtrail get-event-selectors --region <region-name> --trail-name <trail-name>
--query EventSelectors[*].DataResources[]
```
4. The command output should be an
array that contains the configuration of the AWS resource(S3 bucket) defined for the Data
events selector.
5. If the `get-event-selectors` command returns an empty array, the Data
events are not included into the selected AWS Cloudtrail trail logging configuration,
therefore the S3 object-level API operations performed within your AWS account are not
recorded.
6. Repeat steps 1 to 5 for auditing each s3 bucket to identify other trails that are
missing the capability to log Data events.
7. Change the AWS region by updating the
`--region` command parameter and perform the audit process for other regions. "
  desc 'fix',
       "**From Console:**

1. Login to the AWS Management Console and navigate to S3 dashboard at
`https://console.aws.amazon.com/s3/`
2. In the left navigation panel, click `buckets`
and then click on the S3 Bucket Name that you want to examine.
3. Click `Properties` tab to see
in detail bucket configuration.
4. Click on the `Object-level` logging setting, enter the
CloudTrail name for the recording activity. You can choose an existing Cloudtrail or create a
new one by navigating to the Cloudtrail console link
`https://console.aws.amazon.com/cloudtrail/`
5. Once the Cloudtrail is selected,
check the Read event checkbox, so that `object-level` logging for `Read` events is
enabled.
6. Repeat steps 2 to 5 to enable `object-level` logging of read events for other S3
buckets.

**From Command Line:**
1. To enable `object-level` data events logging for
S3 buckets within your AWS account, run `put-event-selectors` command using the name of the
trail that you want to reconfigure as identifier:
```
aws cloudtrail
put-event-selectors --region <region-name> --trail-name <trail-name>
--event-selectors '[{ \"ReadWriteType\": \"ReadOnly\", \"IncludeManagementEvents\":true,
\"DataResources\": [{ \"Type\": \"AWS::S3::Object\", \"Values\":
[\"arn:aws:s3:::<s3-bucket-name>/\"] }] }]'
```
2. The command output will be
`object-level` event trail configuration.
3. If you want to enable it for all buckets at
once then change Values parameter to `[\"arn:aws:s3\"]` in command given above.
4. Repeat
step 1 for each s3 bucket to update `object-level` logging of read events.
5. Change the AWS
region by updating the `--region` command parameter and perform the process for other
regions. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html'
  tag nist: %w{AU-3 AU-3(1) AU-12}
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['8.5'] }]

  if input('single_trail').present?
    describe aws_cloudtrail_trail(input('single_trail')) do
      it { should be_multi_region_trail }
      it { should be monitoring_read('AWS::S3::Object') }
    end
  else
    trails_monitoring_all_s3 = aws_cloudtrail_trails.trail_arns.select { |trail_arn|
      aws_cloudtrail_trail(trail_arn).is_multi_region_trail &&
        aws_cloudtrail_trail(trail_arn).monitoring_read?('AWS::S3::Object')
    }
    describe 'CloudTrail trails' do
      it 'should include at least one multi-region trail monitoring all S3 reads' do
        expect(trails_monitoring_all_s3).to_not be_empty, 'No multi-region trails monitoring all S3 bucket reads were discovered'
      end
    end
  end
end
