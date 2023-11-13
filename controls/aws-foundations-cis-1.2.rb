control 'aws-foundations-cis-1.2' do
  title 'Ensure security contact information is registered '
  desc "AWS provides customers with the option of specifying the contact information for account's
security team. It is recommended that this information be provided. "
  desc 'rationale',
       "Specifying security-specific contact information will help ensure that security
advisories sent by AWS reach the team in your organization that is best equipped to respond to
them. "
  desc 'check',
       "Perform the following to determine if security contact information is present:

**From
Console:**

1. Click on your account name at the top right corner of the console
2. From
the drop-down menu Click `My Account`
3. Scroll down to the `Alternate Contacts`
section
4. Ensure contact information is specified in the `Security` section

**From
Command Line:**

1. Run the following command:

```
aws account
get-alternate-contact --alternate-contact-type SECURITY
```
2. Ensure proper
contact information is specified for the `Security` contact. "
  desc 'fix',
       "Perform the following to establish security contact information:

**From
Console:**

1. Click on your account name at the top right corner of the console.
2. From
the drop-down menu Click `My Account`
3. Scroll down to the `Alternate Contacts`
section
4. Enter contact information in the `Security` section

**From Command
Line:**
Run the following command with the following input
parameters:
--email-address, --name, and --phone-number.

```
aws account
put-alternate-contact --alternate-contact-type SECURITY
```

**Note:** Consider
specifying an internal email distribution list to ensure emails are regularly monitored by
more than one individual. "

  impact 0.5
  tag nist: ['IR-6']
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['17.2'] }]
  if aws_security_contact.configured?
    describe aws_security_contact do
      its('email_address.first') { should cmp "#{input('primary_contact')[:address_line_1]}" }
      its('name.fist') { should cmp "#{input('primary_contact')[:city]}" }
      its('phone_number.first') { should cmp "#{input('primary_contact')[:full_name]}" }
    end
  else
    raise 'The AWS Security Account is not Configured or cannot be accessed'
  end
end
