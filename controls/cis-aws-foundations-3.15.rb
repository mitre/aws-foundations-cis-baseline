control "cis-aws-foundations-3.15" do
  title "Ensure appropriate subscribers to each SNS topic"
  desc  "AWS Simple Notification Service (SNS) is a web service that can
publish messages from an application and immediately deliver them to
subscribers or other applications. Subscribers are clients interested in
receiving notifications from topics of interest; they can subscribe to a topic
or be subscribed by the topic owner. When publishers have information or
updates to notify their subscribers about, they can publish a message to the
topic - which immediately triggers Amazon SNS to deliver the message to all
applicable subscribers. It is recommended that the list of subscribers to given
topics be periodically reviewed for appropriateness."
  impact 0.3
  tag "rationale": "Reviewing subscriber topics will help ensure that only
expected recipients receive information published to SNS topics."
  tag "cis_impact": ""
  tag "cis_rid": "3.15"
  tag "cis_level": 1
  tag "csc_control": ""
  tag "nist": ["AC-6", "Rev_4"]
  tag "cce_id": ""
  tag "check": "Perform the following to ensure appropriate subscribers:

'Via the AWS Management console:

 'Sign in to the AWS Management Console and open the SNS console at
https://console.aws.amazon.com/sns/ [https://console.aws.amazon.com/sns/]
* Click on Topics in the left navigation pane

* Evaluate Topics by clicking on the value within the ARN column

* Within a selected Topic evaluate:

* Topic owner
* Region

* Within the Subscriptions_ _section evaluate:

* _Subscription ID_
* _Protocol_
* _Endpoint_
* _Subscriber_ (Account ID)

'Via CLI:

'aws sns list-topics
aws sns list-subscriptions-by-topic --topic-arn _<topic_arn>_"
  tag "fix": "Perform the following to remove undesired subscriptions:

'Via Management Console

 'Sign in to the AWS Management Console and open the SNS console at
https://console.aws.amazon.com/sns/ [https://console.aws.amazon.com/sns/]
* Click on Subscriptions in the left navigation pane
* For any undesired subscription, select the corresponding checkboxes
* Click Actions
* Click Delete Subscriptions"

  SNS_TOPICS = attribute('sns_topics')
  SNS_SUBSCRIPTIONS = attribute('sns_subscriptions')

  attribute('aws_regions').each do |region|
    ENV['AWS_REGION'] = region

    aws_sns_topics.topic_arns.each do |topic|
      describe aws_sns_topic(topic) do
        its('owner') { should cmp SNS_TOPICS[topic]['owner'] } #verify with attributes
        its('region') { should cmp SNS_TOPICS[topic]['region'] } #verify with attributes
      end
      aws_sns_topic(topic).subscriptions.each do |subscription|
        describe aws_sns_subscription(subscription) do
          its('arn') { should_not eq 'PendingConfirmation' }
        end
        describe aws_sns_subscription(subscription) do
          its('endpoint') { should cmp SNS_SUBSCRIPTIONS[subscription]['endpoint'] } #verify with attributes
          its('protocol') { should cmp SNS_SUBSCRIPTIONS[subscription]['protocol'] } #verify with attributes
          its('owner') { should cmp SNS_SUBSCRIPTIONS[subscription]['owner'] } #verify with attributes
        end unless aws_sns_subscription(subscription).arn.eql?("PendingConfirmation")
      end
      describe "SNS Subscriptions where not found for the Topic" do
        skip "No SNS Subscriptions where found for the SNS Topic #{topic}"
      end if aws_sns_topic(topic).subscriptions.empty?
    end
    describe "SNS Topics where not found in this region" do
      skip "No SNS Topics where found for the region #{region}"
    end if aws_sns_topics.topic_arns.empty?
  end
  # reset to default region
  ENV['AWS_REGION'] = attribute('default_aws_region')
end
