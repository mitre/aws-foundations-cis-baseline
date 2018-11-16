require '_aws'

class AwsIamRole < Inspec.resource(1)
  name 'aws_iam_role'
  desc 'Verifies settings for an IAM Role'
  example "
    describe aws_iam_role('my-role') do
      it { should exist }
    end
  "

  include AwsResourceMixin
  attr_reader :role_name, :description,

  def inline_policies
    return [] unless @exists
    AwsIamRole::BackendFactory.create.list_role_policies(role_name: role_name).policy_names
  end

  def attached_policies
    return [] unless @exists
    AwsIamRole::BackendFactory.create.list_attached_role_policies(role_name: role_name).attached_policies.map(&:policy_name)
  end


  def assume_role_policy_document
    return AssumePolicyDocumentFilter.new({}) unless @exists

    policy_data = CGI.unescape(@assume_role_policy_document) #CGI.unescape(AwsIamPolicy::BackendFactory.create.get_policy_version(
    #   {
    #     policy_arn: @arn,
    #     version_id: @default_version_id,
    #   },
    # ).policy_version.document)

    document = JSON.parse(policy_data, symbolize_names: true)[:Statement]

    AssumePolicyDocumentFilter.new(document)
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:role_name],
      allowed_scalar_name: :role_name,
      allowed_scalar_type: String,
    )
    if validated_params.empty?
      raise ArgumentError, 'You must provide a role_name to aws_iam_role.'
    end
    validated_params
  end

  def fetch_from_aws
    role_info = nil
    begin
      role_info = AwsIamRole::BackendFactory.create.get_role(role_name: role_name)
    rescue Aws::IAM::Errors::NoSuchEntity
      @exists = false
      return
    end
    @exists = true
    @description = role_info.role.description
    @assume_role_policy_document = role_info.role.assume_role_policy_document
  end

  # Uses the SDK API to really talk to AWS
  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)
      def get_role(query)
        AWSConnection.new.iam_client.get_role(query)
      end

      def list_role_policies(query)
        AWSConnection.new.iam_client.list_role_policies(query)
      end

      def list_attached_role_policies(query)
        AWSConnection.new.iam_client.list_attached_role_policies(query)
      end
    end
  end
end

class AssumePolicyDocumentFilter
  filter = FilterTable.create
  filter.add_accessor(:entries)
        .add_accessor(:where)
        .add(:exists?) { |x| !x.entries.empty? }
        .add(:effects, field: :Effect)
        .add(:actions, field: :Action)
        .add(:resources, field: :Resource)
        .add(:conditions, field: :Condition)
        .add(:sids, field: :Sid)
        .add(:principals, field: :Principal)
  filter.connect(self, :document)

  def to_s
    "Assume Role Rolicy"
  end

  attr_reader :document
  def initialize(document)
    @document = document
  end
end
