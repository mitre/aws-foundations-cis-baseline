require '_aws'

class AwsIamGroup < Inspec.resource(1)
  name 'aws_iam_group'
  desc 'Verifies settings for AWS IAM Group'
  example "
    describe aws_iam_group('mygroup') do
      it { should exist }
    end
  "

  include AwsResourceMixin
  attr_reader :group_name, :users

  def to_s
    "IAM Group #{group_name}"
  end

  def inline_policies
    return [] unless @exists
    AwsIamGroup::BackendFactory.create.list_group_policies(group_name: group_name).policy_names
  end

  def attached_policies
    return [] unless @exists
    AwsIamGroup::BackendFactory.create.list_attached_group_policies(group_name: group_name).attached_policies.map(&:policy_name)
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:group_name],
      allowed_scalar_name: :group_name,
      allowed_scalar_type: String,
    )

    if validated_params.empty?
      raise ArgumentError, 'You must provide a group_name to aws_iam_group.'
    end

    validated_params
  end

  def fetch_from_aws
    backend = AwsIamGroup::BackendFactory.create

    begin
      resp = backend.get_group(group_name: group_name)
      @exists = true
      @aws_group_struct = resp[:group]
      @users = resp[:users].map(&:user_name)
    rescue Aws::IAM::Errors::NoSuchEntity
      @exists = false
    end
  end

  class Backend
    BackendFactory.set_default_backend(self)

    def get_group(query)
      AWSConnection.new.iam_client.get_group(query)
    end

    def list_group_policies(query)
      AWSConnection.new.iam_client.list_group_policies(query)
    end

    def list_attached_group_policies(query)
      AWSConnection.new.iam_client.list_attached_group_policies(query)
    end
  end
end
