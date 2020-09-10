# encoding: UTF-8

control "aws-foundations-cis-2.8" do
  title "Ensure rotation for customer created CMKs is enabled"
  desc  "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the Customer Created customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently. It is recommended that CMK key rotation be enabled."
  desc  "rationale", "Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed."
  desc  "check", "Via the Management Console:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam](https://console.aws.amazon.com/iam).
    2. In the left navigation pane, choose `Encryption Keys` .
    3. Select a customer created master key (CMK)
    4. Under the `Key Policy` section, move down to `Key Rotation` _._
    5. Ensure the `Rotate this key every year` checkbox is checked.

    Via CLI
    1. Run the following command to get a list of all keys and their associated `KeyIds`
    ```
     aws kms list-keys
    ```
    2. For each key, note the KeyId and run the following command
    ```
     aws kms get-key-rotation-status --key-id
    ```
    3. Ensure `KeyRotationEnabled` is set to `true`"
  desc  "fix", "Via the Management Console:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/iam](https://console.aws.amazon.com/iam).
    2. In the left navigation pane, choose `Encryption Keys` .
    3. Select a customer created master key (CMK)
    4. Under the `Key Policy` section, move down to `Key Rotation` _._
    5. Check the `Rotate this key every year` checkbox.

    Via CLI
    1. Run the following command to enable key rotation:
    ```
     aws kms enable-key-rotation --key-id
    ```"
  impact 0.5
  tag severity: "Medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-6']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Maintenance, Monitoring and Analysis of Audit Logs CONTROL:6 DESCRIPTION:Maintenance, Monitoring and Analysis of Audit Logs;"
  tag ref: "https://aws.amazon.com/kms/pricing/:http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf"


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