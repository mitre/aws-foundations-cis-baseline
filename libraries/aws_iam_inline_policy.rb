# class AwsIamInlinePolicy < Inspec.resource(1)
#   name 'aws_iam_inline_policy'
#   desc 'Verifies settings for individual AWS IAM Inline Policy'
#   example "
#     describe aws_iam_inline_policy(role_name: 'role-1', policy_name: 'policy-01') do
#       it { should exist }
#     end
#   "

#   include AwsResourceMixin

#   def to_s
#     "Inline Policy #{@policy_name}"
#   end

#   def document
#     return PolicyDocumentFilter.new({}) unless @exists
#     policy_data = URI.unescape(@policy.policy_document)
#     document = JSON.parse(policy_data,:symbolize_names => true)[:Statement]
#     PolicyDocumentFilter.new(document)
#   end

#   private

#   def validate_params(raw_params)
#     validated_params = check_resource_param_names(
#       raw_params: raw_params,
#       allowed_params: [:policy_name, :role_name, :group_name, :user_name],
#     )

#     if validated_params.empty?
#       raise ArgumentError, "You must provide the parameter 'policy_name' to aws_iam_policy."
#     end

#     validated_params
#   end

#   def fetch_from_aws
#     backend = AwsIamInlinePolicy::BackendFactory.create

#     if !@role_name.nil?
#       query = { role_name: @role_name, policy_name: @policy_name }
#       @policy = backend.get_role_policy(query)
#     elsif !@group_name.nil?
#       query = { group_name: @group_name, policy_name: @policy_name }
#       @policy = backend.get_role_policy(query)
#     elsif !@user_name.nil?
#       query = { user_name: @user_name, policy_name: @policy_name }
#       @policy = backend.get_role_policy(query)
#     end

#     @exists = !@policy.nil?
#   end

#   class Backend
#     class AwsClientApi
#       BackendFactory.set_default_backend(self)

#       def get_role_policy(criteria)
#         AWSConnection.new.iam_client.get_role_policy(criteria)
#       end

#       def get_user_policy(criteria)
#         AWSConnection.new.iam_client.get_user_policy(criteria)
#       end

#       def get_group_policy(criteria)
#         AWSConnection.new.iam_client.get_group_policy(criteria)
#       end
#     end
#   end
# end

# class PolicyDocumentFilter
#   filter = FilterTable.create
#   filter.add_accessor(:entries)
#         .add_accessor(:where)
#         .add(:exists?) { |x| !x.entries.empty? }
#         .add(:effects, field: :Effect)
#         .add(:actions, field: :Action)
#         .add(:resources, field: :Resource)
#         .add(:conditions, field: :Condition)
#         .add(:sids, field: :Sid)
#         .add(:principals, field: :Principal)
#   filter.connect(self, :document)

#   attr_reader :document
#   def initialize(document)
#     @document = document
#   end
# end