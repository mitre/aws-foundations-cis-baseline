class AwsS3Buckets < Inspec.resource(1)
  name 'aws_s3_buckets'
  desc 'Verifies settings for AWS S3 Buckets in bulk'
  example '
    describe aws_s3_buckets do
      it { should exist }
    end
  '
  include AwsResourceMixin
  attr_reader :table, :buckets, :has_public_buckets
  alias have_public_buckets? has_public_buckets
  alias has_public_buckets? has_public_buckets

  # Underlying FilterTable implementation.
  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:exists?) { |x| !x.entries.empty? }
        .add(:names, field: :name)
  filter.connect(self, :table)

  def to_s
    'S3 Buckets'
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [],
      allowed_scalar_name: nil,
      allowed_scalar_type: String,
    )
    validated_params
  end

  def fetch_from_aws
    # Transform into filter format expected by AWS
    filters = []
    [
      :table,
      :buckets,
      :has_public_buckets,
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
    @table   = []
    @buckets = []
    backend  = AwsS3Buckets::BackendFactory.create
    # Note: should we ever implement server-side filtering
    # (and this is a very good resource for that),
    # we will need to reformat the criteria we are sending to AWS.
    results = backend.list_buckets
    results.buckets.each do |b_info|
      @table.push({
                    name: b_info.name,
                    creation_date: b_info.creation_date,
                    owner: {
                      display_name: results.owner.display_name,
                      id: results.owner.id,
                    },
                  })
      @buckets.push(b_info.name)
    end
    fetch_public_buckets
  end

  def fetch_public_buckets
    @has_public_buckets = false
    @buckets.each do |bucket|
      AwsS3Buckets::BackendFactory.create.get_bucket_acl(bucket: bucket).each do |grant|
        type = grant.grantee[:type]
        if type == 'Group' and grant.grantee[:uri] =~ /AllUsers/
          @has_public_buckets = true
        end
      end
    end
  end

  class Backend
    class AwsClientApi < Backend
      AwsS3Buckets::BackendFactory.set_default_backend self

      def list_buckets
        AWSConnection.new.s3_client.list_buckets
      end

      def get_bucket_acl(query)
        AWSConnection.new.s3_client.get_bucket_acl(query).grants
      end
    end
  end
end
