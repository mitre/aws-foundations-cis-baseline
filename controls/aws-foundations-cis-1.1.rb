# encoding: UTF-8

control "aws-foundations-cis-1.1" do
  title "Avoid the use of the \"root\" account"
  desc  "The \"root\" account has unrestricted access to all resources in the AWS account. It is highly recommended that the use of this account be avoided."
  desc  "rationale", "The \"root\" account is the most privileged AWS account. Minimizing the use of this account and adopting the principle of least privilege for access management will reduce the risk of accidental changes and unintended disclosure of highly privileged credentials."
  desc  "check", "Implement the `Ensure a log metric filter and alarm exist for usage of \"root\" account` recommendation in the `Monitoring` section of this benchmark to receive notifications of root account usage. Additionally, executing the following commands will provide ad-hoc means for determining the last time the root account was used:
    ```
    aws iam generate-credential-report
    ```
    ```
    aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 ''
    ```
    Note: there are a few conditions under which the use of the root account is required, such as requesting a penetration test or creating a CloudFront private key."
  desc  "fix", "Follow the remediation instructions of the `Ensure IAM policies are attached only to groups or roles` recommendation"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-6(9)']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Ensure the Use of Dedicated Administrative Accounts CONTROL:4.3 DESCRIPTION:Ensure that all users with administrative account access use a dedicated or secondary account for elevated activities. This account should only be used for administrative activities and not internet browsing, email, or similar activities.;"
  tag ref: "http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html:CIS CSC v6.0 #5.1"


  pattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

  describe aws_cloudwatch_log_metric_filter(pattern: pattern) do
    it { should exist }
  end

  # Find the log_group_name associated with the aws_cloudwatch_log_metric_filter that has the pattern
  log_group_name = aws_cloudwatch_log_metric_filter(pattern: pattern).log_group_name

  # Find cloudtrails associated with with `log_group_name` parsed above
  associated_trails = aws_cloudtrail_trails.names.select{ |x| aws_cloudtrail_trail(x).cloud_watch_logs_log_group_arn =~ /log-group:#{log_group_name}:/ }

  # Ensure log_group is associated atleast one cloudtrail
  describe "Cloudtrails associated with log-group: #{log_group_name}" do
    subject { associated_trails }
    it { should_not be_empty }
  end

  # Ensure atleast one of the associated cloudtrail meet the requirements.
  describe.one do
    associated_trails.each do |trail|
      describe aws_cloudtrail_trail(trail) do
        it { should be_multi_region_trail }
        it { should have_event_selector_mgmt_events_rw_type_all }
        it { should be_logging }
      end
    end
  end

  # Parse out `metric_name` and `metric_namespace` for the specified pattern.
  associated_metric_filter = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: log_group_name)
  metric_name = associated_metric_filter.metric_name
  metric_namespace = associated_metric_filter.metric_namespace

  # Ensure aws_cloudwatch_alarm for the specified pattern meets requirements.
  if associated_metric_filter.exists?
    describe aws_cloudwatch_alarm(metric_name: metric_name, metric_namespace: metric_namespace) do
      it { should exist }
      its ('alarm_actions') { should_not be_empty }
    end

    aws_cloudwatch_alarm(metric_name: metric_name, metric_namespace: metric_namespace).alarm_actions.each do |sns|
      describe aws_sns_topic(sns) do
        it { should exist }
        its('confirmed_subscription_count') { should cmp >= 1 }
      end
    end
  end
end
