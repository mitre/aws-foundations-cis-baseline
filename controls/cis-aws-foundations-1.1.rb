# encoding: UTF-8

control "1.1" do
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
  impact 0.3
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Ensure the Use of Dedicated Administrative Accounts CONTROL:4.3 DESCRIPTION:Ensure that all users with administrative account access use a dedicated or secondary account for elevated activities. This account should only be used for administrative activities and not internet browsing, email, or similar activities.;"
  tag ref: "http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html:CIS CSC v6.0 #5.1"

  unless ENV['AWS_REGION'].eql?(attribute('default_aws_region'))
    impact 0.0
    desc  "Currently inspected region #{ENV['AWS_REGION']} is not the primary AWS region"
  end

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

