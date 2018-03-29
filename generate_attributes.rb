# #!/usr/bin/ruby
require 'yaml'
require 'rubygems'; require 'json';

attributes_file = YAML.load_file(ARGF.argv[0])

aws_regions = attributes_file['aws_regions']

config_delivery_channels = {}
aws_regions.each do |region|
  channel = JSON.parse(%x[ aws configservice describe-delivery-channels --region #{region} ])
  
  config_delivery_channels[region] = 
  {   
    's3_bucket_name' => channel["DeliveryChannels"].first["s3BucketName"],
    'sns_topic_arn' => channel["DeliveryChannels"].first["snsTopicARN"]

  }
end

sns_topics = {}
aws_regions.each do |region|
  topics = JSON.parse(%x[ aws sns list-topics --region #{region} ])
  topics['Topics'].each do |topic|
    attrs = JSON.parse(%x[ aws sns get-topic-attributes --topic-arn #{topic["TopicArn"]} --region #{topic["TopicArn"].scan(/^arn:aws:sns:([\w\-]+):\d{12}:[\S]+$/).last.first} ])
    sns_topics[topic["TopicArn"]] = 
    {
      'owner' => attrs["Attributes"]["Owner"],
      'region' => topic["TopicArn"].scan(/^arn:aws:sns:([\w\-]+):\d{12}:[\S]+$/).last.first
    }
  end
end

sns_subscriptions = {}
aws_regions.each do |region|
  subscriptions = JSON.parse(%x[ aws sns list-subscriptions --region #{region} ])
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

File.write(ARGF.argv[0], attributes_file.to_yaml)