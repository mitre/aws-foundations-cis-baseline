class AwsKmsKey < Inspec.resource(1)
  name 'aws_kms_key'
  desc 'Verifies settings for an individual AWS KMS Key'
  example "
    describe aws_kms_key('arn:aws:kms:us-east-1::key/key-id') do
      it { should exist }
    end
  "

  include AwsResourceMixin

  attr_reader :key_id, :arn, :creation_date, :key_usage, :key_state, :description,
              :deletion_date, :valid_to, :origin, :expiration_model, :key_manager

  def to_s
    "KMS Key #{@key_arn}"
  end

  def enabled?
    @enabled
  end

  def rotation_enabled?
    @rotation_enabled
  end

  def created_days_ago
    ((Time.now - creation_date)/(24*60*60)).to_i unless creation_date.nil?
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:key_arn],
      allowed_scalar_name: :key_arn,
      allowed_scalar_type: String,
    )

    if validated_params.empty?
      raise ArgumentError, "You must provide the parameter 'key_id' to aws_kms_key."
    end

    validated_params
  end

  def fetch_from_aws
    backend = AwsKmsKey::BackendFactory.create

    query = { key_id: @key_arn }
    resp = backend.describe_key(query)

    @exists = !resp.empty?
    return unless @exists

    @key = resp.key_metadata.to_h
    @key_id = @key[:key_id]
    @arn = @key[:arn]
    @creation_date = @key[:creation_date]
    @enabled = @key[:enabled]
    @description = @key[:description]
    @key_usage = @key[:key_usage]
    @key_state = @key[:key_state]
    @deletion_date = @key[:deletion_date]
    @valid_to = @key[:valid_to]
    @origin = @key[:origin]
    @expiration_model = @key[:expiration_model]
    @key_manager = @key[:key_manager]

    resp = backend.get_key_rotation_status(query)
    @rotation_enabled = resp.key_rotation_enabled unless resp.empty?
  end

  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def describe_key(query)
        AWSConnection.new.kms_client.describe_key(query)
      rescue Aws::KMS::Errors::NotFoundException
        return {}
      end

      def get_key_rotation_status(query)
        AWSConnection.new.kms_client.get_key_rotation_status(query)
      rescue Aws::KMS::Errors::NotFoundException
        return {}
      end
    end
  end
end
