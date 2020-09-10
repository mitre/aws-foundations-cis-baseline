# encoding: UTF-8

control "aws-foundations-cis-2.1" do
  title "Ensure CloudTrail is enabled in all regions"
  desc  "AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the Management Console, SDKs, command line tools, and higher-level AWS services (such as CloudFormation)."
  desc  "rationale", "The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally,
    - ensuring that a multi-regions trail exists will ensure that unexpected activity occurring in otherwise unused regions is detected
    - ensuring that a multi-regions trail exists will ensure that `Global Service Logging` is enabled for a trail by default to capture recording of events generated on
    AWS global services
    - for a multi-regions trail, ensuring that management events configured for all type of Read/Writes ensures recording of management operations that are performed on all resources in an AWS account"
  desc  "check", "Perform the following to determine if CloudTrail is enabled for all regions:

    Via the management Console
    1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
    2. Click on `Trails` on the left navigation pane
     - You will be presented with a list of trails across all regions
    3. Ensure at least one Trail has `All` specified in the `Region` column
    4. Click on a trail via the link in the _Name_ column
    5. Ensure `Logging` is set to `ON`
    6. Ensure `Apply trail to all regions` is set to `Yes`
    7. In section `Management Events` ensure `Read/Write Events` set to `ALL`

    Via CLI
    ```
     aws cloudtrail describe-trails
    ```
    Ensure `IsMultiRegionTrail` is set to `true`
    ```
    aws cloudtrail get-trail-status --name
    ```
    Ensure `IsLogging` is set to `true`
    ```
    aws cloudtrail get-event-selectors --trail-name
    ```
    Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`"
  desc  "fix", "Perform the following to enable global (Multi-region) CloudTrail logging:

    Via the management Console
    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
    2. Click on _Trails_ on the left navigation pane
    3. Click `Get Started Now` , if presented
     - Click `Add new trail`
     - Enter a trail name in the `Trail name` box
     - Set the `Apply trail to all regions` option to `Yes`
     - Specify an S3 bucket name in the `S3 bucket` box
     - Click `Create`
    4. If 1 or more trails already exist, select the target trail to enable for global logging
    5. Click the edit icon (pencil) next to `Apply trail to all regions` , Click `Yes` and Click `Save`.
    6. Click the edit icon (pencil) next to `Management Events` click `All` for setting `Read/Write Events` and Click `Save`.

    Via CLI
    ```
    aws cloudtrail create-trail --name
     --bucket-name  --is-multi-region-trail
    aws cloudtrail update-trail --name
     --is-multi-region-trail
    ```

    Note: Creating CloudTrail via CLI without providing any overriding options configures `Management Events` to set `All` type of `Read/Writes` by default."
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-12']
  tag notes: nil
  tag comment: "S3 lifecycle features can be used to manage the accumulation and management of logs over time. See the following AWS resource for more information on these features:
  1. http://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html"
  tag cis_controls: "TITLE:Activate audit logging CONTROL:6.2 DESCRIPTION:Ensure that local logging has been enabled on all systems and networking devices.;"
  tag ref: "CIS CSC v6.0 #14.6:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-management-events:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html?icmpid=docs_cloudtrail_console#logging-management-events:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-services.html#cloud-trail-supported-services-data-events"

  
  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.names.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      it { should be_multi_region_trail }
      it { should be_logging }
      it { should have_event_selector_mgmt_events_rw_type_all }
    end
  end
end