control 'cis-aws-foundations-2.2' do
  title 'Ensure CloudTrail log file validation is enabled'
  desc  "CloudTrail log file validation creates a digitally signed digest file
containing a hash of each log that CloudTrail writes to S3. These digest files
can be used to determine whether a log file was changed, deleted, or unchanged
after CloudTrail delivered the log. It is recommended that file validation be
enabled on all CloudTrails."
  impact 0.7
  tag "rationale": "Enabling log file validation will provide additional
integrity checking of CloudTrail logs."
  tag "cis_impact": ''
  tag "cis_rid": '2.2'
  tag "cis_level": 2
  tag "csc_control": [['6.3'], '6.0']
  tag "nist": ['AU-4', 'Rev_4']
  tag "cce_id": 'CCE-78914-9'
  tag "check": "Perform the following on each trail to determine if log file
validation is enabled:

'Via the management Console

* Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/cloudtrail
[https://console.aws.amazon.com/cloudtrail]

* Click on Trails on the left navigation pane

* You will be presented with a list of trails across all regions


* Ensure at least one Trail has All specified in the Region column
* Click on a trail via the link in the _Name_ column
* Under the S3 section, ensure Enable log file validation is set to Yes

'Via CLI

'aws cloudtrail describe-trails

'Ensure LogFileValidationEnabled is set to true for each trail."
  tag "fix": "Perform the following to enable log file validation on a given
trail:

'Via the management Console

* Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/cloudtrail
[https://console.aws.amazon.com/cloudtrail]
* Click on Trails on the left navigation pane
* Click on target trail
* Within the S3 section click on the edit icon (pencil)
* Click Advanced
* Click on the Yes radio button in section Enable log file validation
* Click Save

'Via CLI

'aws cloudtrail update-trail --name _<trail_name>_ --enable-log-file-validation


'Note that periodic validation of logs using these digests can be performed by
running the following command:

'aws cloudtrail validate-logs --trail-arn _<trail_arn>_ --start-time
_<start_time>_ --end-time _<end_time>_"

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      it { should be_log_file_validation_enabled }
    end
  end
end
