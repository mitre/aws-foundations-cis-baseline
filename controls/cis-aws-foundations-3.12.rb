control 'cis-aws-foundations-3.12' do
  title "Ensure a log metric filter and alarm exist for changes to network
gateways"
  desc  "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms. Network gateways are required to send/receive traffic to a
destination outside of a VPC. It is recommended that a metric filter and alarm
be established for changes to network gateways."
  impact 0.3
  tag "rationale": "Monitoring changes to network gateways will help ensure
that all ingress/egress traffic traverses the VPC border via a controlled path."
  tag "cis_impact": ''
  tag "cis_rid": '3.12'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['SI-4(5)', 'Rev_4']
  tag "cce_id": 'CCE-79197-0'
  tag "check": "Perform the following to determine if the account is configured
as prescribed: 1. Identify the log group name configured for use with
CloudTrail:


'aws cloudtrail describe-trails
2. Note the <cloudtrail_log_group_name> value associated with
CloudWatchLogsLogGroupArn:


''arn:aws:logs:eu-west-1:<aws_account_number>:log-group:<cloudtrail_log_group_name>:*'

3. Get a list of all associated metric filters for this
<cloudtrail_log_group_name>:


'aws logs describe-metric-filters --log-group-name
'<cloudtrail_log_group_name>'4. Ensure the output from the above command
contains the following:


''filterPattern': '{ ($.eventName = CreateCustomerGateway) || ($.eventName =
DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName
= CreateInternetGateway) || ($.eventName = DeleteInternetGateway) ||
($.eventName = DetachInternetGateway) }'
5. Note the _<network_gw_changes_metric>_ value associated with the
filterPattern found in step 4.
6. Get a list of CloudWatch alarms and filter on the
_<network_gw_changes_metric>_ captured in step 5.


'aws cloudwatch describe-alarms --query
'MetricAlarms[?MetricName==`_<network_gw_changes_metric>_`]'
7. Note the AlarmActions value - this will provide the SNS topic ARN value.
8. Ensure there is at least one subscriber to the SNS topic


'aws sns list-subscriptions-by-topic --topic-arn _<sns_topic_arn> _

"
  tag "fix": "Perform the following to setup the metric filter, alarm, SNS
topic, and subscription:1. Create a metric filter based on filter pattern
provided which checks for network gateways changes and the
<cloudtrail_log_group_name> taken from audit step 2.


'aws logs put-metric-filter --log-group-name <cloudtrail_log_group_name>
--filter-name _<network_gw_changes_metric>_ --metric-transformations
metricName=_<network_gw_changes_metric>_,metricNamespace='CISBenchmark',metricValue=1
--filter-pattern '{ ($.eventName = CreateCustomerGateway) || ($.eventName =
DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName
= CreateInternetGateway) || ($.eventName = DeleteInternetGateway) ||
($.eventName = DetachInternetGateway) }'
NOTE: You can choose your own metricName and metricNamespace strings. Using the
same metricNamespace for all Foundations Benchmark metrics will group them
together.
2. Create an SNS topic that the alarm will notify


'aws sns create-topic --name _<sns_topic_name>_
NOTE: you can execute this command once and then re-use the same topic for all
monitoring alarms.
3. Create an SNS subscription to the topic created in step 2


'aws sns subscribe --topic-arn <sns_topic_arn> --protocol _<protocol_for_sns>_
--notification-endpoint _<sns_subscription_endpoints>_
NOTE: you can execute this command once and then re-use the SNS subscription
for all monitoring alarms.
4. Create an alarm that is associated with the CloudWatch Logs Metric Filter
created in step 1 and an SNS topic created in step 2


'aws cloudwatch put-metric-alarm --alarm-name _<network_gw_changes_alarm>_
--metric-name _<network_gw_changes_metric>_ --statistic Sum --period 300
--threshold 1 --comparison-operator GreaterThanOrEqualToThreshold
--evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions
<sns_topic_arn>
"

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

      pattern = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'

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
