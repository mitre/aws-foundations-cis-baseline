require '_aws'

class AwsEc2SecurityGroup < Inspec.resource(1)
  name 'aws_ec2_security_group'
  desc 'Verifies settings for an individual AWS Security Group.'
  example '
    describe aws_ec2_security_group("sg-12345678") do
      it { should exist }
    end
  '

  include AwsResourceMixin
  attr_reader :description, :group_id, :group_name, :vpc_id, :ingress_rules, :egress_rules

  def to_s
    "EC2 Security Group #{@group_id}"
  end

  # Underlying FilterTable implementation.
  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:type, field: :type)
        .add(:group_ids, field: :group_id)
        .add(:from_port, field: :from_port)
        .add(:to_port, field: :to_port)
        .add(:ip_protocol, field: :ip_protocol)
        .add(:ip_ranges, field: :ip_ranges)
        .add(:ipv_6_ranges, field: :ipv_6_ranges)
  filter.connect(self, :access_key_data)

  def access_key_data
    @table
  end

  def open_on_port?(port)
    @ingress_rules.each do |rule|
      # Will skip unless the port is equal to the from port or
      # the rule allows all traffic, or it is between the to and from port.
      next unless port == rule.from_port \
                  or (rule.to_port.nil? and rule.from_port.nil?) \
                  or (!rule.to_port.nil? and port.between?(rule.from_port, rule.to_port))
      rule.ip_ranges.each do |ip_range|
        if ip_range.cidr_ip == '0.0.0.0/0' or ip_range.cidr_ip == 'ALL'
          return true
        end
      end
    end
    false
  end

  private

  def validate_params(raw_params)
    recognized_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:id, :group_id, :group_name, :vpc_id],
      allowed_scalar_name: :group_id,
      allowed_scalar_type: String,
    )

    # id is an alias for group_id
    recognized_params[:group_id] = recognized_params.delete(:id) if recognized_params.key?(:id)

    if recognized_params.key?(:group_id) && recognized_params[:group_id] !~ /^sg\-[0-9a-f]{8}/
      raise ArgumentError, 'aws_ec2_security_group security group ID must be in the format "sg-" followed by 8 hexadecimal characters.'
    end

    if recognized_params.key?(:vpc_id) && recognized_params[:vpc_id] !~ /^vpc\-[0-9a-f]{8}/
      raise ArgumentError, 'aws_ec2_security_group VPC ID must be in the format "vpc-" followed by 8 hexadecimal characters.'
    end

    validated_params = recognized_params

    if validated_params.empty?
      raise ArgumentError, 'You must provide parameters to aws_ec2_security_group, such as group_name, group_id, or vpc_id.g_group.'
    end
    validated_params
  end

  def fetch_from_aws
    backend = AwsEc2SecurityGroup::BackendFactory.create

    # Transform into filter format expected by AWS
    filters = []
    [
      :description,
      :group_id,
      :group_name,
      :vpc_id,
      :ingress_rules,
      :egress_rules,
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
    dsg_response = backend.describe_security_groups(filters: filters)
    if dsg_response.security_groups.empty?
      @exists = false
      return
    end

    @exists = true
    @description   = dsg_response.security_groups[0].description
    @group_id      = dsg_response.security_groups[0].group_id
    @group_name    = dsg_response.security_groups[0].group_name
    @vpc_id        = dsg_response.security_groups[0].vpc_id
    @ingress_rules = dsg_response.security_groups[0].ip_permissions
    @egress_rules  = dsg_response.security_groups[0].ip_permissions_egress
    populate_ingress_egress_rules
  end

  def populate_ingress_egress_rules
    @table = []
    @ingress_rules.each do |rule|
      rule = Hash[rule.each_pair.to_a]
      rule[:type] = 'ingress'
      @table.push(rule)
    end
    @egress_rules.each do |rule|
      rule = Hash[rule.each_pair.to_a]
      rule[:type] = 'egress'
      @table.push(rule)
    end
  end

  class Backend
    class AwsClientApi < Backend
      AwsEc2SecurityGroup::BackendFactory.set_default_backend self

      def describe_security_groups(query)
        AWSConnection.new.ec2_client.describe_security_groups(query)
      end
    end
  end
end