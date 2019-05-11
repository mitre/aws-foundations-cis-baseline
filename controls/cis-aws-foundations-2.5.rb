config_delivery_channels = attribute('config_delivery_channels')

control 'cis-aws-foundations-2.5' do
  title 'Ensure AWS Config is enabled in all regions'
  desc  "AWS Config is a web service that performs configuration management of
supported AWS resources within your account and delivers log files to you. The
recorded information includes the configuration item (AWS resource),
relationships between configuration items (AWS resources), any configuration
changes between resources. It is recommended to enable AWS Config be enabled in
all regions."
  impact 0.3
  tag "rationale": "The AWS configuration item history captured by AWS Config
enables security analysis, resource change tracking, and compliance auditing."
  tag "cis_impact": ''
  tag "cis_rid": '2.5'
  tag "cis_level": 1
  tag "csc_control": [['1.1', '1.3', '1.4', '5.2', '11.1', '11.3', '14.6'], '6.0']
  tag "nist": ['CM-8(3)', 'CM-8(2)', 'CM-8', 'AC-6(7)', 'CM-6(1)', 'CM-6(2)', 'AU-2', 'Rev_4']
  tag "cce_id": 'CCE-78917-2'
  tag "check": "Process to evaluate AWS Config configuration per region

'Via AWS Management Console

 'Sign in to the AWS Management Console and open the AWS Config console at
https://console.aws.amazon.com/config/ [https://console.aws.amazon.com/config/].
* On the top right of the console select target Region.
* If presented with Setup AWS Config - follow remediation procedure:

 'On the Resource inventory page, Click on edit (the gear icon). The Set Up AWS
Config page appears.

* Ensure 1 or both check-boxes under 'All Resources' is checked.

* Include global resources related to IAM resources - which needs to be enabled
in 1 region only


* Ensure the correct S3 bucket has been defined.
* Ensure the correct SNS topic has been defined.
* Repeat steps 2 to 7 for each region."
  tag "fix": "Perform the following in the AWS Management Console:

* Select the region you want to focus on in the top right of the console
* Click Services
* Click Config
* Define which resources you want to record in the selected region
* Choose to include global resources (IAM resources)
* Specify an S3 bucket in the same account or in another managed AWS account
* Create an SNS Topic from the same AWS account or another managed AWS account


'API Call:

'aws configservice start-configuration-recorder"

  region = ENV['AWS_REGION']

  describe aws_config_recorder do
    it { should exist }
    it { should be_recording }
    it { should be_recording_all_resource_types }
    it { should be_recording_all_global_types }
  end

  describe aws_config_delivery_channel do
    it { should exist }
  end

  if aws_config_delivery_channel.exists?
    describe aws_config_delivery_channel do
      its('s3_bucket_name') { should cmp config_delivery_channels[region]['s3_bucket_name'] } 
      its('sns_topic_arn') { should cmp config_delivery_channels[region]['sns_topic_arn'] } 
    end
  end
end
