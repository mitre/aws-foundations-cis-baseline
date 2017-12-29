class AwsS3Bucket < Inspec.resource(1)
  name 'aws_s3_bucket'
  desc 'Verifies settings for a s3 bucket'
  example "
    describe aws_s3_bucket(name: 'test_bucket') do
      it { should exist }
      it { should_not have_public_files }
      its('permissions.owner') { should be_in ['FULL_CONTROL'] }
    end
  "

  include AwsResourceMixin
  attr_reader :name, :permissions, :has_public_files, :region
  alias have_public_files? has_public_files
  alias has_public_files? has_public_files

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
      :permissions,
      :region,
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
      compute_has_public_files
      fetch_permissions
      fetch_region
    rescue Aws::IAM::Errors::NoSuchEntity
      @exists = false
      return
    end
    @exists = true
  end

  def compute_has_public_files
    @has_public_files = false
    bucket_objects = AwsS3Bucket::BackendFactory.create.list_objects(bucket: name)
    bucket_objects.contents.each do |object|
      grants = AwsS3Bucket::BackendFactory.create.get_object_acl(bucket: name, key: object.key)
      grants.each do |grant|
        if grant.grantee[:type] == 'Group' and grant.grantee[:uri] =~ /AllUsers/ and grant[:permission] != ''
          @has_public_files = true
        end
      end
    end
  end

  def fetch_permissions
    # Use a Mash to make it easier to access hash elements in "its('permissions') {should ...}"
    @permissions = Hashie::Mash.new({})
    # Make sure standard extensions exist so we don't get nil for nil:NilClass
    # when the user tests for extensions which aren't present
    %w{
      owner logGroup authUsers everyone
    }.each { |perm| @permissions[perm] ||= [] }

    AwsS3Bucket::BackendFactory.create.get_bucket_acl(bucket: name).each do |grant|
      type = grant.grantee[:type]
      permission = grant[:permission]
      uri = grant.grantee[:uri]
      if type == 'CanonicalUser'
        @permissions[:owner].push(permission)
      elsif type == 'AmazonCustomerByEmail'
        @permissions[:authUsers].push(permission)
      elsif type == 'Group' and uri =~ /AllUsers/
        @permissions[:everyone].push(permission)
      elsif type == 'Group' and uri =~ /LogDelivery/
        @permissions[:logGroup].push(permission)
      end
    end
  end

  def fetch_region
    @region = AwsS3Bucket::BackendFactory.create.get_bucket_location(bucket: name)
  end

  # Uses the SDK API to really talk to AWS
  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def list_objects(query)
        AWSConnection.new.s3_client.list_objects(query)
      end

      def get_bucket_acl(query)
        AWSConnection.new.s3_client.get_bucket_acl(query).grants
      end

      def get_object_acl(query)
        AWSConnection.new.s3_client.get_object_acl(query).grants
      end

      def get_bucket_location(query)
        AWSConnection.new.s3_client.get_bucket_location(query).location_constraint
      end
    end
  end
end
