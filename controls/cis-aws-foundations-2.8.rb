control 'cis-aws-foundations-2.8' do
  title 'Ensure rotation for customer created CMKs is enabled'
  desc  "AWS Key Management Service (KMS) allows customers to rotate the
backing key which is key material stored within the KMS which is tied to the
key ID of the Customer Created customer master key (CMK). It is the backing key
that is used to perform cryptographic operations such as encryption and
decryption. Automated key rotation currently retains all prior backing keys so
that decryption of encrypted data can take place transparently. It is
recommended that CMK key rotation be enabled."
  impact 0.7
  tag "rationale": "Rotating encryption keys helps reduce the potential impact
of a compromised key as data encrypted with a new key cannot be accessed with a
previous key that may have been exposed."
  tag "cis_impact": ''
  tag "cis_rid": '2.8'
  tag "cis_level": 2
  tag "csc_control": ''
  tag "nist": ['SC-12', 'Rev_4']
  tag "cce_id": 'CCE-78920-6'
  tag "check": "Via the Management Console:

* Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/iam [https://console.aws.amazon.com/iam].

 'In the left navigation pane, choose Encryption Keys.
* Select a customer created master key (CMK)
* Under the Key Policy section, move down to Key Rotation_._
* Ensure the Rotate this key every year checkbox is checked.

'Via CLI

* Run the following command to get a list of all keys and their associated
KeyIds

'aws kms list-keys

* For each key, note the KeyId and run the following command

'aws kms get-key-rotation-status --key-id _<kms_key_id>_
* Ensure KeyRotationEnabled is set to true"
  tag "fix": "Via the Management Console:

* Sign in to the AWS Management Console and open the IAM console at
https://console.aws.amazon.com/iam [https://console.aws.amazon.com/iam].

 'In the left navigation pane, choose Encryption Keys.
* Select a customer created master key (CMK)
* Under the Key Policy section, move down to Key Rotation_._
* Check the Rotate this key every year checkbox.

'Via CLI

* Run the following command to enable key rotation:

'aws kms enable-key-rotation --key-id _<kms_key_id>_
"
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
