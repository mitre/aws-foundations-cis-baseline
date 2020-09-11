#!/usr/bin/ruby
require 'yaml'
require 'json'

aws_regions = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2'
]

inputs_file = {}

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

inputs_file['config_delivery_channels'] = config_delivery_channels

puts inputs_file.to_yaml
