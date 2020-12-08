# encoding: UTF-8

control "aws-foundations-cis-2.5" do
  title "Ensure AWS Config is enabled in all regions"
  desc  "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended to enable AWS Config be enabled in all regions."
  desc  "rationale", "The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing."
  desc  "check", "Process to evaluate AWS Config configuration per region

    Via AWS Management Console:
    1. Sign in to the AWS Management Console and open the AWS Config console at [https://console.aws.amazon.com/config/](https://console.aws.amazon.com/config/).
    2. On the top right of the console select target Region.
    3. If presented with Setup AWS Config - follow remediation procedure:
    4. On the Resource inventory page, Click on edit (the gear icon). The Set Up AWS Config page appears.
    5. Ensure 1 or both check-boxes under \"All Resources\" is checked.
     - Include global resources related to IAM resources - which needs to be enabled in 1 region only
    6. Ensure the correct S3 bucket has been defined.
    7. Ensure the correct SNS topic has been defined.
    8. Repeat steps 2 to 7 for each region.

    Via AWS Command Line Interface:
    1. Run this command to show all AWS Config recorders and their properties:
    ```
    aws configservice describe-configuration-recorders
    ```
    2. Evaluate the output to ensure that there's at least one recorder for which `recordingGroup` object includes `\"allSupported\": true` AND `\"includeGlobalResourceTypes\": true`
    Note: There is one more parameter \"ResourceTypes\" in recordingGroup object. We don't need to check the same as whenever we set \"allSupported\": true, AWS enforces resource types to be empty (\"ResourceTypes\":[])
    Sample Output:
    ```
    {
     \"ConfigurationRecorders\": [
     {
     \"recordingGroup\": {
     \"allSupported\": true,
     \"resourceTypes\": [],
     \"includeGlobalResourceTypes\": true
     },
     \"roleARN\": \"arn:aws:iam:::role/service-role/\",
     \"name\": \"default\"
     }
     ]
    }
    ```
    3. Run this command to show the status for all AWS Config recorders:
    ```
    aws configservice describe-configuration-recorder-status
    ```
    4. In the output, find recorders with `name` key matching the recorders that met criteria in step 2. Ensure that at least one of them includes `\"recording\": true` and `\"lastStatus\": \"SUCCESS\"`"
  desc  "fix", "To implement AWS Config configuration:

    Via AWS Management Console:
    1. Select the region you want to focus on in the top right of the console
    2. Click `Services`
    3. Click `Config`
    4. Define which resources you want to record in the selected region
    5. Choose to include global resources (IAM resources)
    6. Specify an S3 bucket in the same account or in another managed AWS account
    7. Create an SNS Topic from the same AWS account or another managed AWS account

    Via AWS Command Line Interface:
    1. Ensure there is an appropriate S3 bucket, SNS topic, and IAM role per the [AWS Config Service prerequisites](http://docs.aws.amazon.com/config/latest/developerguide/gs-cli-prereq.html).
    2. Run this command to set up the configuration recorder
    ```
    aws configservice subscribe --s3-bucket my-config-bucket --sns-topic arn:aws:sns:us-east-1:012345678912:my-config-notice --iam-role arn:aws:iam::012345678912:role/myConfigRole
    ```
    3. Run this command to start the configuration recorder:
    ```
    start-configuration-recorder --configuration-recorder-name
    ```"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['CM-8(2)', 'CM-8(6)', 'CM-8']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Maintain Detailed Asset Inventory CONTROL:1.4 DESCRIPTION:Maintain an accurate and up-to-date inventory of all technology assets with the potential to store or process information. This inventory shall include all hardware assets, whether connected to the organization's network or not.;TITLE:Document Traffic Configuration Rules CONTROL:11.2 DESCRIPTION:All configuration rules that allow traffic to flow through network devices should be documented in a configuration management system with a specific business reason for each rule, a specific individual\'s name responsible for that business need, and an expected duration of the need.;TITLE:Maintain an Inventory of Authentication Systems CONTROL:16.1 DESCRIPTION:Maintain an inventory of each of the organization's authentication systems, including those located onsite or at a remote service provider.;"
  tag ref: "CIS CSC v6.0 #1.1, #1.3, #1.4, #5.2, #11.1 - #11.3, #14.6:http://docs.aws.amazon.com/cli/latest/reference/configservice/describe-configuration-recorder-status.html"


  config_delivery_channels = input('config_delivery_channels')

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
      its('s3_bucket_name') { should cmp config_delivery_channels[:"#{input('default_aws_region')}"][:'s3_bucket_name'] }
      its('sns_topic_arn') { should cmp config_delivery_channels[:"#{input('default_aws_region')}"][:'sns_topic_arn'] }
    end
  end
end