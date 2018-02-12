require '_aws'

class AwsConfigurationRecorder < Inspec.resource(1)
  name 'aws_config_recorder'
  desc 'Verifies settings for AWS Configuration Recorder'
  example "
    describe aws_config_recorder do
      it { should exist }
      it { should be_default }
      it { should be_recording }
      it { should be_all_supported }
      it { should have_include_global_resource_types }
    end
  "

  include AwsResourceMixin
  attr_reader :role_arn , :resource_types, :recorder_name, :resp

  def to_s
    "Configuration_Recorder: #{@recorder_name}"
  end

  def default?
    @recorder_name.eql?('default')
  end

  def all_supported?
    @all_supported
  end

  def has_include_global_resource_types?
    @include_global_resource_types
  end

  def status
    return unless @exists
    backend = AwsConfigurationRecorder::BackendFactory.create
    @resp = backend.describe_configuration_recorder_status(@query)
    @status = @resp.configuration_recorders_status.first.to_h
  end

  def recording?
    return unless @exists
    status[:recording]
  end

  private

  def validate_params(raw_params)
    validated_params = check_resource_param_names(
      raw_params: raw_params,
      allowed_params: [:recorder_name],
      allowed_scalar_name: :recorder_name,
      allowed_scalar_type: String,
    )

    validated_params
  end

  def fetch_from_aws
    backend = AwsConfigurationRecorder::BackendFactory.create

    if @recorder_name.nil?
      @query = { configuration_recorder_names: ['default'] }
    else
      @query = { configuration_recorder_names: [@recorder_name] }
    end

    @resp = backend.describe_configuration_recorders(@query)
    @exists = !@resp.empty?
    return unless @exists

    @recorder = @resp.configuration_recorders.first.to_h
    @recorder_name = @recorder[:name]
    @role_arn = @recorder[:role_arn]
    @all_supported = @recorder[:recording_group][:all_supported]
    @include_global_resource_types = @recorder[:recording_group][:include_global_resource_types]
    @resource_types = @recorder[:recording_group][:resource_types]
  end

  class Backend
    class AwsClientApi
      BackendFactory.set_default_backend(self)

      def describe_configuration_recorders(query)
        AWSConnection.new.configservice_client.describe_configuration_recorders(query)
      rescue Aws::ConfigService::Errors::NoSuchConfigurationRecorderException
        return {}
      end

      def describe_configuration_recorder_status(query)
        AWSConnection.new.configservice_client.describe_configuration_recorder_status(query)
      end
    end
  end
end
