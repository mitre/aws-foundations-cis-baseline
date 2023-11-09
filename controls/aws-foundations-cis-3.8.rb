# encoding: UTF-8

control "aws-foundations-cis-3.8" do
  title "Ensure rotation for customer created symmetric CMKs is enabled "
  desc "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key 
material stored within the KMS which is tied to the key ID of the Customer Created customer 
master key (CMK). It is the backing key that is used to perform cryptographic operations such 
as encryption and decryption. Automated key rotation currently retains all prior backing 
keys so that decryption of encrypted data can take place transparently. It is recommended 
that CMK key rotation be enabled for symmetric keys. Key rotation can not be enabled for any 
asymmetric CMK. "
  desc "rationale", "Rotating encryption keys helps reduce the potential impact of a compromised key as data 
encrypted with a new key cannot be accessed with a previous key that may have been 
exposed.
Keys should be rotated every year, or upon event that would result in the 
compromise of that key. "
  desc "check", "**From Console:**

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
  desc "fix", "**From Console:**

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
  desc "impact", "Creation, management, and storage of CMKs may require additional time from and 
administrator. "
  impact 0.5
  ref 'https://aws.amazon.com/kms/pricing/:https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final'
  tag nist: ['IA-5(1)','SC-28','SC-28(1)']
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["3.11"]}
  ]

  aws_kms_keys.key_arns.each do |key|
    next unless aws_kms_key(key).enabled? && !aws_kms_key(key).managed_by_aws?
    describe aws_kms_key(key) do
      it { should have_rotation_enabled }
    end
  end

  if aws_kms_keys.key_arns.none? { |key| aws_kms_key(key).enabled? && !aws_kms_key(key).managed_by_aws? }
    describe 'Control skipped because no enabled kms keys were found' do
      skip 'This control is skipped since the aws_kms_keys resource returned an empty coustomer managed and enabled kms key list'
    end
  end
end
