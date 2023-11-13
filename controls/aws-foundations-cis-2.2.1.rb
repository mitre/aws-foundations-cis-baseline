control "aws-foundations-cis-2.2.1" do
  title "Ensure EBS Volume Encryption is Enabled in all Regions "
  desc "Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store
(EBS) service. While disabled by default, forcing encryption at EBS volume creation is
supported. "
  desc "rationale",
       "Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can
nullify the impact of disclosure if the encryption remains unbroken. "
  desc "check",
       "**From Console:**

1. Login to AWS Management Console and open the Amazon EC2 console
using https://console.aws.amazon.com/ec2/
2. Under `Account attributes`, click `EBS
encryption`.
3. Verify `Always encrypt new EBS volumes` displays `Enabled`.
4. Review
every region in-use.

**Note:** EBS volume encryption is configured per
region.

**From Command Line:**

1. Run
```
aws --region <region> ec2
get-ebs-encryption-by-default
```
2. Verify that `\"EbsEncryptionByDefault\": true`
is displayed.
3. Review every region in-use.

**Note:** EBS volume encryption is
configured per region. "
  desc "fix",
       "**From Console:**

1. Login to AWS Management Console and open the Amazon EC2 console
using https://console.aws.amazon.com/ec2/
2. Under `Account attributes`, click `EBS
encryption`.
3. Click `Manage`.
4. Click the `Enable` checkbox.
5. Click `Update EBS
encryption`
6. Repeat for every region requiring the change.

**Note:** EBS volume
encryption is configured per region.

**From Command Line:**

1. Run
```
aws
--region <region> ec2 enable-ebs-encryption-by-default
```
2. Verify that
`\"EbsEncryptionByDefault\": true` is displayed.
3. Repeat every region requiring the
change.

**Note:** EBS volume encryption is configured per region. "
  desc "additional_information",
       "Default EBS volume encryption only applies to newly created EBS volumes. Existing EBS
volumes are **not** converted automatically. "
  desc "impact",
       "Losing access or removing the KMS key in use by the EBS volumes will result in no longer being
able to access the volumes. "
  impact 0.5
  ref "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html:https://aws.amazon.com/blogs/aws/new-opt-in-to-default-encryption-for-new-ebs-volumes/"
  tag nist: %w[SC-28 SC-28(1)]
  tag severity: "medium "
  tag cis_controls: [{ "8" => ["3.11"] }]

  describe "No Tests Defined Yet" do
    skip "No Tests have been written for this control yet"
  end
end
