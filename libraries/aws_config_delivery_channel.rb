require '_aws'

class AwsConfigurationDeliveryChannel < Inspec.resource(1)
  name 'aws_config_delivery_channel'
  desc 'Verifies settings for AWS Configuration Delivery Channel'
  example "
    describe aws_config_delivery_channel do
      it { should exist }
      it { should be_default }
      its('s3_bucket_name') { should_not be_nil }
      its('sns_topic_arn') { should_not be_nil }
    end
  "

  include AwsResourceMixin
  attr_reader :channel_name , :s3_bucket_name, :s3_key_prefix, :sns_topic_arn

  def to_s
    "Configuration_Delivery_Channel: #{@channel_name}"
  end

  def default?
    @channel_name.eql?('default')
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:channel_name],
      allowed_scalar_name: :channel_name,
      allowed_scalar_type: String,
    )

    validated_params
  end

  def fetch_from_aws
    backend = AwsConfigurationDeliveryChannel::BackendFactory.create

    if @recorder_name.nil?
      query = { delivery_channel_names: ['default'] }
    else
      query = { delivery_channel_names: [@channel_name] }
    end

    @resp = backend.describe_delivery_channels(query)
    @exists = !@resp.empty?
    return unless @exists

    @channel = @resp.delivery_channels.first.to_h
    @channel_name = @channel[:name]
    @s3_bucket_name = @channel[:s3_bucket_name]
    @s3_key_prefix = @channel[:s3_key_prefix]
    @sns_topic_arn = @channel[:sns_topic_arn]
  end

  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def describe_delivery_channels(query)
        AWSConnection.new.configservice_client.describe_delivery_channels(query)
      rescue Aws::ConfigService::Errors::NoSuchDeliveryChannelException
        return {}
      end

    end
  end
end
