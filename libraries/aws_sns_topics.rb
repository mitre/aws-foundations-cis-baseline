require '_aws'

class AwsSnsTopics < Inspec.resource(1)
  name 'aws_sns_topics'
  desc 'Verifies settings for AWS VPCs in bulk'
  example '
    describe aws_sns_topics do
      it { should exist }
    end
  '

  # Underlying FilterTable implementation.
  filter = FilterTable.create
  filter.add_accessor(:entries)
        .add(:exists?) { |x| !x.entries.empty? }
        .add(:topic_arns, field: :topic_arn)
  filter.connect(self, :sns_topics)

  def sns_topics
    @table
  end

  def to_s
    'SNS Topics'
  end

  def initialize
    backend = AwsSnsTopics::BackendFactory.create
    @table = backend.list_topics.to_h[:topics]
  end

  class BackendFactory
    extend AwsBackendFactoryMixin
  end

  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def list_topics(query = {})
        AWSConnection.new.sns_client.list_topics(query)
      end
    end
  end
end
