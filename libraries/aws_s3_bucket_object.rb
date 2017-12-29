class AwsS3BucketObject < Inspec.resource(1)
  name 'aws_s3_bucket_object'
  desc 'Verifies settings for a s3 bucket object'
  example "
    describe aws_s3_bucket_object(name: 'bucket_name', key: 'file_name') do
      it { should exist }
      its('permissions.authUsers') { should be_in [] }
      its('permissions.owner') { should be_in ['FULL_CONTROL'] }
      its('permissions.everyone') { should be_in [] }
    end
  "

  include AwsResourceMixin
  attr_reader :name, :key, :id, :public, :permissions
  alias public? public

  def to_s
    "S3 Bucket Object #{@key} (#{@name})"
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:name, :key, :id],
      allowed_scalar_name: [:name, :key],
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
      :key,
      :id,
      :public,
      :permissions,
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
      fetch_permissions
    rescue Aws::IAM::Errors::NoSuchEntity
      @exists = false
      return
    end
    @exists = true
  end

  # get the permissions of an objectg
  def fetch_permissions
    # Use a Mash to make it easier to access hash elements in "its('permissions') {should ...}"
    @permissions = Hashie::Mash.new({})
    # Make sure standard extensions exist so we don't get nil for nil:NilClass
    # when the user tests for extensions which aren't present
    %w{
      owner authUsers everyone
    }.each { |perm| @permissions[perm] ||= [] }

    @public = false
    AwsS3BucketObject::BackendFactory.create.get_object_acl(bucket: name, key: key).each do |grant|
      permission = grant[:permission]
      type = grant.grantee[:type]
      if type == 'Group'
        @public = true
        @permissions[:everyone].push(permission)
      elsif type == 'AmazonCustomerByEmail'
        @permissions[:authUsers].push(permission)
      elsif type == 'CanonicalUser'
        @permissions[:owner].push(permission)
      end
    end
  end

  # Uses the SDK API to really talk to AWS
  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)
      def get_object_acl(query)
        AWSConnection.new.s3_client.get_object_acl(query).grants
      end
    end
  end
end
