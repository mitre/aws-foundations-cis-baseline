control 'aws-foundations-cis-3.8' do
  title 'Ensure rotation for customer created symmetric CMKs is enabled '
  desc "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key
material stored within the KMS which is tied to the key ID of the Customer Created customer
master key (CMK). It is the backing key that is used to perform cryptographic operations such
as encryption and decryption. Automated key rotation currently retains all prior backing
keys so that decryption of encrypted data can take place transparently. It is recommended
that CMK key rotation be enabled for symmetric keys. Key rotation can not be enabled for any
asymmetric CMK. "
  desc 'rationale', "Rotating encryption keys helps reduce the potential impact of a compromised key as data
encrypted with a new key cannot be accessed with a previous key that may have been
exposed.
Keys should be rotated every year, or upon event that would result in the
compromise of that key. "
  desc 'check', "**From Console:**

1. Sign in to the AWS Management Console and open the IAM console at
[https://console.aws.amazon.com/iam](https://console.aws.amazon.com/iam).
2. In
the left navigation pane, choose `Customer managed keys`
3. Select a customer managed CMK
where `Key spec = SYMMETRIC_DEFAULT`
4. Underneath the `General configuration` panel
open the tab `Key rotation`
5. Ensure that the checkbox `Automatically rotate this KMS key
every year.` is activated
6. Repeat steps 3 - 5 for all customer managed CMKs where \"Key spec =
SYMMETRIC_DEFAULT\"

**From Command Line:**

1. Run the following command to get a
list of all keys and their associated `KeyIds`
```
 aws kms list-keys
```
2. For each
key, note the KeyId and run the following command
```
describe-key --key-id
<kms_key_id>
```
3. If the response contains \"KeySpec = SYMMETRIC_DEFAULT\" run the
following command
```
 aws kms get-key-rotation-status --key-id
<kms_key_id>
```
4. Ensure `KeyRotationEnabled` is set to `true`
5. Repeat steps 2 - 4
for all remaining CMKs "
  desc 'fix', "**From Console:**

1. Sign in to the AWS Management Console and open the IAM console at
[https://console.aws.amazon.com/iam](https://console.aws.amazon.com/iam).
2. In
the left navigation pane, choose `Customer managed keys` .
3. Select a customer managed CMK
where `Key spec = SYMMETRIC_DEFAULT`
4. Underneath the \"General configuration\" panel
open the tab \"Key rotation\"
5. Check the \"Automatically rotate this KMS key every year.\"
checkbox

**From Command Line:**

1. Run the following command to enable key
rotation:
```
 aws kms enable-key-rotation --key-id <kms_key_id>
``` "
  desc 'impact', "Creation, management, and storage of CMKs may require additional time from and
administrator. "
  impact 0.5
  ref 'https://aws.amazon.com/kms/pricing/:https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final'
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['3.11'] },
  ]

  # TODO: I am making this happen
  # 
#  bundle exec inspec exec . -t aws:// --reporter cli json:test.json --filter-empty-profiles --enhanced-outcomes --controls '/aws-foundations-cis-3.8/'     
# [2023-12-06T00:54:41-05:00] WARN: Input 'exempt_kms_keys' does not have a value. Use --input-file or --input to provide a value for 'exempt_kms_keys' or specify a  value with `input('exempt_kms_keys', value: 'somevalue', ...)`.
# [2023-12-06T00:54:41-05:00] WARN: Input 'exempt_kms_keys' does not have a value. Use --input-file or --input to provide a value for 'exempt_kms_keys' or specify a  value with `input('exempt_kms_keys', value: 'somevalue', ...)`.
# [2023-12-06T00:54:41-05:00] WARN: Input 'exempt_kms_keys' does not have a value. Use --input-file or --input to provide a value for 'exempt_kms_keys' or specify a  value with `input('exempt_kms_keys', value: 'somevalue', ...)`.
# [2023-12-06T00:54:41-05:00] WARN: Input 'exempt_kms_keys' does not have a value. Use --input-file or --input to provide a value for 'exempt_kms_keys' or specify a  value with `input('exempt_kms_keys', value: 'somevalue', ...)`.
# [2023-12-06T00:54:41-05:00] WARN: Input 'exempt_kms_keys' does not have a value. Use --input-file or --input to provide a value for 'exempt_kms_keys' or specify a  value with `input('exempt_kms_keys', value: 'somevalue', ...)`.

# Profile:   aws-foundations-cis-baseline (aws-foundations-cis-baseline)
# Version:   2.0.2
# Target:    aws://
# Target ID: b91c5f76-58c3-5a19-a3cf-fa122b50e151

#   N/R  aws-foundations-cis-3.8: Ensure rotation for customer created symmetric CMKs is enabled 
#      ↺  This control is skipped since the aws_kms_keys resource returned an empty coustomer managed and enabled kms key list


# Profile Summary: 0 successful controls, 0 control failures, 1 control not reviewed, 0 controls not applicable, 0 controls have error
# Test Summary: 0 successful, 0 failures, 1 skipped
# /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:60:in `respond_to?': stack level too deep (SystemStackError)
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:60:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/gems/activesupport-7.0.8/lib/active_support/core_ext/object/json.rb:61:in `as_json'
#          ... 10904 levels...
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/bin/inspec:25:in `load'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/bin/inspec:25:in `<main>'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/bin/ruby_executable_hooks:22:in `eval'
#         from /Users/alippold/.rvm/gems/ruby-3.0.4/bin/ruby_executable_hooks:22:in `<main>'
#         
#  This is causing the json reporter to die and not write a report

# TODO: I also have uncaught exceptions

  customer_created_symmetric_cmk = (aws_kms_keys.key_arns - input('exempt_kms_keys')).select { |key|
    aws_kms_key(key).enabled? && !aws_kms_key(key).managed_by_aws?
  }

  only_if("No non-exempt customer managed KMS keys were discovered", impact: 0.0) { !customer_created_symmetric_cmk.empty? }

  failing_keys = customer_created_symmetric_cmk.select { |key|
    !aws_kms_key(key).has_rotation_enabled?
  }

  describe "All customer-managed KMS keys" do
    it "should have rotation enabled" do
      expect(failing_keys).to be_empty, "Customer-managed KMS keys without rotation enabled:\t#{failing_keys}"
    end
  end
end
