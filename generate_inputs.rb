#!/usr/bin/ruby

require 'yaml'
require 'json'
require 'pry'

aws_regions = JSON.parse(
  `aws ec2 describe-regions --filters "Name=region-name,Values=*us*" --query "Regions[].{Name:RegionName}" --output json`,
).map { |x| x['Name'] }

# aws_regions = %w{us-east-1 us-east-2 us-west-1 us-west-2}

inputs_file = {}

config_delivery_channels = {}

aws_regions.each do |region|
  channels =
    JSON.parse(
      `aws configservice describe-delivery-channels --region #{region}`,
    )
  channels['DeliveryChannels'].each do |channel|
    puts "channel: #{channel}"
    config_delivery_channels[region] = {
      's3_bucket_name' => channel['s3BucketName'],
      'sns_topic_arn' => channel['snsTopicARN'],
    }
  end
end

inputs_file['config_delivery_channels'] = config_delivery_channels

puts YAML.dump(inputs_file)
