control 'cis-aws-foundations-2.1' do
  title 'Ensure CloudTrail is enabled in all regions'
  desc  "AWS CloudTrail is a web service that records AWS API calls for your
account and delivers log files to you. The recorded information includes the
identity of the API caller, the time of the API call, the source IP address of
the API caller, the request parameters, and the response elements returned by
the AWS service. CloudTrail provides a history of AWS API calls for an account,
including API calls made via the Management Console, SDKs, command line tools,
and higher-level AWS services (such as CloudFormation)."
  impact 0.3
  tag "rationale": "The AWS API call history produced by CloudTrail enables
security analysis, resource change tracking, and compliance auditing.
Additionally, ensuring that a multi-regions trail exists will ensure that
unexpected activity occurring in otherwise unused regions is detected."
  tag "cis_impact": "S3 lifecycle features can be used to manage the
accumulation and management of logs over time. See the following AWS resource
for more information on these features:

* http://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html"
  tag "cis_rid": '2.1'
  tag "cis_level": 1
  tag "csc_control": [['14.6'], '6.0']
  tag "nist": ['AU-2', 'Rev_4']
  tag "cce_id": 'CCE-78913-1'
  tag "check": "Perform the following to determine if CloudTrail is enabled for
all regions:

'Via the management Console

* Sign in to the AWS Management Console and open the CloudTrail console at
https://console.aws.amazon.com/cloudtrail
[https://console.aws.amazon.com/cloudtrail]

* Click on Trails_ _on the left navigation pane

* You will be presented with a list of trails across all regions


* Ensure at least one Trail has All specified in the Region column
* Click on a trail via the link in the _Name_ column
* Ensure Logging is set to ON

* Ensure Apply trail to all regions is set to Yes

'Via CLI

' aws cloudtrail describe-trails

'Ensure IsMultiRegionTrail is set to true"
  tag "fix": "Perform the following to enable global CloudTrail logging:

'Via the management Console

* Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/cloudtrail
[https://console.aws.amazon.com/cloudtrail]
* Click on _Trails_ on the left navigation pane

* Click Get Started Now, if presented

* Click Add new trail
* Enter a trail name in the Trail name box
* Set the Apply trail to all regions option to Yes
* Specify an S3 bucket name in the S3 bucket box
* Click Create


* If 1 or more trails already exist, select the target trail to enable for
global logging

* Click the edit icon (pencil) next to Apply trail to all regions
* Click Yes
* Click Save
`
'Via CLI

'aws cloudtrail create-trail --name _<trail_name>_ --bucket-name
_<s3_bucket_for_cloudtrail>_ --is-multi-region-trail
aws cloudtrail update-trail --name _<trail_name>_ --is-multi-region-trail"

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      it { should be_multi_region_trail }
      its('status.is_logging') { should be true }
    end
  end
end
