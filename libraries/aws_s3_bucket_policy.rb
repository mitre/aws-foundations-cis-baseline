# author: Matthew Dromazos
class AwsS3BucketPolicy < Inspec.resource(1)
  name 'aws_s3_bucket_policy'
  desc 'Verifies settings for a s3 bucket'
  example "
    describe aws_s3_bucket_policy(name: 'test_bucket') do
      it { should_not have_statement_allow_all }
    end
  "

  include AwsResourceMixin
  attr_reader :name, :policy, :has_statement_allow_all
  alias have_statement_allow_all? has_statement_allow_all
  alias has_statement_allow_all? has_statement_allow_all

  def to_s
    "S3 Bucket #{@name}"
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:name],
      allowed_scalar_name: :name,
      allowed_scalar_type: String,
    )
    if validated_params.empty?
      raise ArgumentError, 'You must provide a role_name to aws_iam_role.'
    end

    validated_params
  end

  def fetch_from_aws
    # Transform into filter format expected by AWS
    filters = []
    [
      :name,
      :policy,
      :has_statement_allow_all,
    ].each do |criterion_name|
      val = instance_variable_get("@#{criterion_name}".to_sym)
      next if val.nil?
      filters.push(
        {
          name: criterion_name.to_s.tr('_', '-'),
          values: [val],
        },
      )
    end

    begin
      fetch_policy
    rescue Aws::IAM::Errors::NoSuchEntity
      @exists = false
      return
    end
    @exists = true
  end

  def fetch_policy
    @has_statement_allow_all = false
    @policy = JSON.parse(AwsS3BucketPolicy::BackendFactory.create.get_bucket_policy(bucket: name).policy.read)
    @policy['Statement'].each do |statement|
      if statement['Effect'] == 'Allow' and statement['Principal'] == '*'
        @has_statement_allow_all = true
      end
    end
  end

  # Uses the SDK API to really talk to AWS
  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def get_bucket_policy(query)
        AWSConnection.new.s3_client.get_bucket_policy(query)
      end
    end
  end
end
