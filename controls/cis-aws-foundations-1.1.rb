control 'cis-aws-foundations-1.1' do
  title "Avoid the use of the 'root' account"
  desc  "The 'root' account has unrestricted access to all resources in the AWS
account. It is highly recommended that the use of this account be avoided."
  impact 0.3
  tag "rationale": "The 'root' account is the most privileged AWS account.
Minimizing the use of this account and adopting the principle of least
privilege for access management will reduce the risk of accidental changes and
unintended disclosure of highly privileged credentials."
  tag "cis_impact": ''
  tag "cis_rid": '1.1'
  tag "cis_level": 1
  tag "csc_control": [['5.1'], '6.0']
  tag "nist": ['AC-6 (9)', 'Rev_4']
  tag "cce_id": ''

  tag "check": "Implement the Ensure a log metric filter and alarm exist for
usage of 'root' account recommendation in the Monitoring section of this
benchmark to receive notifications of root account usage. Additionally,
executing the following commands will provide ad-hoc means for determining the
last time the root account was used:
'aws iam generate-credential-report
'aws iam get-credential-report --query 'Content' --output text | base64 -d |
cut -d, -f1,5,11,16 | grep -B1 '<root_account>'
'Note: there are a few conditions under which the use of the root account is
required, such as requesting a penetration test or creating a CloudFront
private key."
  tag "fix": "Follow the remediation instructions of the Ensure IAM policies
are attached only to groups or roles recommendation"

  unless ENV['AWS_REGION'].eql?(attribute('default_aws_region'))
    impact 0.0
    desc  "Currently inspected region #{ENV['AWS_REGION']} is not the primary AWS region"
  end

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|
      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

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
