# encoding: UTF-8

control "aws-foundations-cis-1.18" do
  title "Ensure security contact information is registered"
  desc  "AWS provides customers with the option of specifying the contact information for account's security team. It is recommended that this information be provided."
  desc  "rationale", "Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them."
  desc  "check", "Perform the following in the AWS Management Console to determine if security contact information is present:

    1. Click on your account name at the top right corner of the console
    2. From the drop-down menu Click `My Account`
    3. Scroll down to the `Alternate Contacts` section
    4. Ensure contact information is specified in the `Security` section"
  desc  "fix", "Perform the following in the AWS Management Console to establish security contact information:

    1. Click on your account name at the top right corner of the console.
    2. From the drop-down menu Click `My Account`
    3. Scroll down to the `Alternate Contacts` section
    4. Enter contact information in the `Security` section

    Note: Consider specifying an internal email distribution list to ensure emails are regularly monitored by more than one individual."
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['IR-1']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Incident Response and Management CONTROL:19 DESCRIPTION:Incident Response and Management;"

  
  describe 'Control has to be tested manually' do
    skip 'This control must be manually reviewed'
  end
end