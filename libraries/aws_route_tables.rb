class AwsRouteTables < Inspec.resource(1)
  name 'aws_route_tables'
  desc 'Verifies settings for AWS Route Tables in bulk'
  example '
    describe aws_route_tables do
      it { should exist }
    end
  '

  # Underlying FilterTable implementation.
  filter = FilterTable.create
  filter.add_accessor(:entries)
        .add(:exists?) { |x| !x.entries.empty? }
        .add(:vpc_ids, field: :vpc_id)
        .add(:route_table_ids, field: :route_table_id)
  filter.connect(self, :routes_data)

  def routes_data
    @table
  end

  def to_s
    'Route Tables'
  end

  def initialize
    backend = AwsRouteTables::BackendFactory.create
    @table = backend.describe_route_tables({}).to_h[:route_tables] # max value for limit is 1000
  end

  class BackendFactory
    extend AwsBackendFactoryMixin
  end

  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def describe_route_tables(query = {})
        AWSConnection.new.ec2_client.describe_route_tables(query)
      end
    end
  end
end
