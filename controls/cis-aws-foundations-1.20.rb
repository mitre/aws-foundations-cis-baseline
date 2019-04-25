control 'cis-aws-foundations-1.20' do
  title 'Ensure security contact information is registered'
  desc  "AWS provides customers with the option of specifying the contact
information for account's security team. It is recommended that this
information be provided."
  impact 0.3
  tag "rationale": "Specifying security-specific contact information will help
ensure that security advisories sent by AWS reach the team in your organization
that is best equipped to respond to them."
  tag "cis_impact": ''
  tag "cis_rid": '1.20'
  tag "cis_level": 1
  tag "csc_control": ''
  tag "nist": ['IA-4', 'Rev_4']
  tag "cce_id": 'CCE-79200-2'
  tag "check": "Perform the following in the AWS Management Console to
determine if security contact information is present:

* Click on your account name at the top right corner of the console
* From the drop-down menu Click My Account
* Scroll down to the Alternate Contacts section
* Ensure contact information is specified in the Security section"
  tag "fix": "Perform the following in the AWS Management Console to establish
security contact information:

* Click on your account name at the top right corner of the console.
* From the drop-down menu Click My Account
* Scroll down to the Alternate Contacts section
* Enter contact information in the Security section

'Note: Consider specifying an internal email distribution list to ensure emails
are regularly monitored by more than one individual."

  describe 'Control has to be tested manually' do
    skip 'This control must be manually reviewed'
  end
end
