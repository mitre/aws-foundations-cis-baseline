# encoding: UTF-8

control "aws-foundations-cis-2.2" do
  title "Ensure CloudTrail log file validation is enabled"
  desc  "CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails."
  desc  "rationale", "Enabling log file validation will provide additional integrity checking of CloudTrail logs."
  desc  "check", "Perform the following on each trail to determine if log file validation is enabled:

    Via the management Console
    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
    2. Click on `Trails` on the left navigation pane
    3. For Every Trail:
    - Click on a trail via the link in the _Name_ column
    - Under the `S3` section, ensure `Enable log file validation` is set to `Yes`

    Via CLI
    ```
    aws cloudtrail describe-trails
    ```
    Ensure `LogFileValidationEnabled` is set to `true` for each trail"
  desc  "fix", "Perform the following to enable log file validation on a given trail:

    Via the management Console
    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
    2. Click on `Trails` on the left navigation pane
    3. Click on target trail
    4. Within the `S3` section click on the edit icon (pencil)
    5. Click `Advanced`
    6. Click on the `Yes` radio button in section `Enable log file validation`
    7. Click `Save`

    Via CLI
    ```
    aws cloudtrail update-trail --name
     --enable-log-file-validation
    ```
    Note that periodic validation of logs using these digests can be performed by running the following command:
    ```
    aws cloudtrail validate-logs --trail-arn
     --start-time  --end-time
    ```"
  impact 0.5
  tag severity: "Medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-6']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Maintenance, Monitoring and Analysis of Audit Logs CONTROL:6 DESCRIPTION:Maintenance, Monitoring and Analysis of Audit Logs;"
  tag ref: "http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html:CIS CSC v6.0 #6.3"

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      it { should be_log_file_validation_enabled }
    end
  end
end