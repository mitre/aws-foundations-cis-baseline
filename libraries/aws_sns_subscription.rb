require '_aws'

class AwsSnsSubscription < Inspec.resource(1)
  name 'aws_sns_subscription'
  desc 'Verifies settings for an SNS Subscription'
  example "
    describe aws_sns_subscription('arn:aws:sns:us-east-1::test-topic-01:b214aff5-a2c7-438f-a753-8494493f2ff6') do
      it { should_not have_raw_message_delivery }
      it { should be_confirmation_authenticated }
      its('owner') { should cmp '12345678' }
      its('topic_arn') { should cmp 'arn:aws:sns:us-east-1::test-topic-01' }
      its('endpoint') { should cmp 'arn:aws:sqs:us-east-1::test-queue-01' }
      its('protocol') { should cmp 'sqs' }
    end
  "

  include AwsResourceMixin
  attr_reader :arn, :owner, :raw_message_delivery, :topic_arn, :endpoint, :protocol, :confirmation_was_authenticated, :aws_response

  alias confirmation_authenticated? confirmation_was_authenticated
  alias raw_message_delivery? raw_message_delivery

  def has_raw_message_delivery?
    raw_message_delivery
  end

  def to_s
    'SNS Subscription'
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:arn],
      allowed_scalar_name: :arn,
      allowed_scalar_type: String,
    )
    # Validate the ARN
    # unless validated_params[:arn] =~ /^arn:aws:sns:[\w\-]+:\d{12}:[\S]+$/
    #   raise ArgumentError, 'Malformed ARN for SNS Subscriptions.  Expected an ARN of the form ' \
    #                        "'arn:aws:sns:REGION:ACCOUNT-ID:TOPIC-NAME'"
    # end
    validated_params
  end

  def fetch_from_aws
    @aws_response = AwsSnsSubscription::BackendFactory.create.get_subscription_attributes(subscription_arn: @arn).attributes
    @exists = true
    @owner = @aws_response['Owner']
    @raw_message_delivery = @aws_response['RawMessageDelivery'].eql?('true')
    @topic_arn = @aws_response['TopicArn']
    @endpoint = @aws_response['Endpoint']
    @protocol = @aws_response['Protocol']
    @confirmation_was_authenticated = @aws_response['ConfirmationWasAuthenticated'].eql?('true')

  rescue Aws::SNS::Errors::NotFound
    @exists = false
  end

  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def get_subscription_attributes(criteria)
        AWSConnection.new.sns_client.get_subscription_attributes(criteria)
      end

      def list_subscriptions_by_topic(criteria)
        AWSConnection.new.sns_client.list_subscriptions_by_topic(criteria)
      end
    end
  end
end
