#!/usr/bin/ruby
require 'yaml'
require 'json'

aws_regions = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2'
]

attributes_file = {}

config_delivery_channels = {}
aws_regions.each do |region|
  channels = JSON.parse(`aws configservice describe-delivery-channels --region #{region}`)
  channels['DeliveryChannels'].each do |channel|
    config_delivery_channels[region] =
      {
        's3_bucket_name' => channel['s3BucketName'],
        'sns_topic_arn' => channel['snsTopicARN']

      }
  end
end

sns_topics = {}
aws_regions.each do |region|
  topics = JSON.parse(`aws sns list-topics --region #{region}`)
  topics['Topics'].each do |topic|
    attrs = JSON.parse(`aws sns get-topic-attributes --topic-arn #{topic['TopicArn']} --region #{topic['TopicArn'].scan(/^arn:aws:sns:([\w\-]+):\d{12}:[\S]+$/).last.first}`)
    sns_topics[topic['TopicArn']] =
      {
        'owner' => attrs['Attributes']['Owner'],
        'region' => topic['TopicArn'].scan(/^arn:aws:sns:([\w\-]+):\d{12}:[\S]+$/).last.first
      }
  end
end

sns_subscriptions = {}
aws_regions.each do |region|
  subscriptions = JSON.parse(`aws sns list-subscriptions --region #{region}`)
  subscriptions['Subscriptions'].each do |subscription|
    sns_subscriptions[subscription['SubscriptionArn']] =
      {
        'endpoint' => subscription['Endpoint'],
        'owner' => subscription['Owner'],
        'protocol' => subscription['Protocol']
      }
  end
end

attributes_file['config_delivery_channels'] = config_delivery_channels
attributes_file['sns_topics'] = sns_topics
attributes_file['sns_subscriptions'] = sns_subscriptions

puts attributes_file.to_yaml
