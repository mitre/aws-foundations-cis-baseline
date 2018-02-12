require '_aws'

# author: Miles Tjandrawidjaja
class AwsIamRootUser < Inspec.resource(1)
  name 'aws_iam_root_user'
  desc 'Verifies settings for AWS root account'
  example "
    describe aws_iam_root_user do
      it { should have_access_key }
    end
  "

  def initialize(conn = AWSConnection.new)
    @client = conn.iam_client
  end

  def has_access_key?
    summary_account['AccountAccessKeysPresent'] == 1
  end

  def has_mfa_enabled?
    summary_account['AccountMFAEnabled'] == 1
  end

  def has_virtual_mfa_devices?
    virtual_mfa_devices.each do |device|
      if %r{arn:aws:iam::\d{12}:mfa\/root-account-mfa-device} =~
        device['serial_number']
        return true
      end
    end
    false
  end
  
  def to_s
    'AWS Root-User'
  end

  private

  def summary_account
    @summary_account ||= @client.get_account_summary.summary_map
  end

  def virtual_mfa_devices
    @client.list_virtual_mfa_devices.virtual_mfa_devices
  end
end
