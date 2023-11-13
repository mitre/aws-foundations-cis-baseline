control 'aws-foundations-cis-1.1' do
  title 'Maintain current contact details '
  desc "
    Ensure contact email and telephone details for AWS accounts are current and map to more than
    one individual in your organization.

    An AWS account supports a number of contact
    details, and AWS will use these to contact the account owner if activity judged to be in breach
    of Acceptable Use Policy or indicative of likely security compromise is observed by the AWS
    Abuse team. Contact details should not be for a single individual, as circumstances may arise
    where that individual is unavailable. Email contact details should point to a mail alias
    which forwards email to multiple individuals within the organization; where feasible,
    phone contact details should point to a PABX hunt group or other call-forwarding system. "

  desc 'rationale', "If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will
    attempt to contact the account owner by email and phone using the contact details listed. If
    this is unsuccessful and the account behavior needs urgent mitigation, proactive measures
    may be taken, including throttling of traffic between the account exhibiting suspicious
    behavior and the AWS API endpoints and the Internet. This will result in impaired service to
    and from the account in question, so it is in both the customers' and AWS' best interests that
    prompt contact can be established. This is best achieved by setting AWS account contact
    details to point to resources which have multiple individuals as recipients, such as email
    aliases and PABX hunt groups. "
  desc 'check', %q{
    This activity can only be performed via the AWS Console, with a user who has permission to read
    and write Billing information (aws-portal:\\*Billing )

    1. Sign in to the AWS Management
    Console and open the `Billing and Cost Management` console at
    https://console.aws.amazon.com/billing/home#/.
    2. On the navigation bar, choose your
    account name, and then choose `Account`.
    3. On the `Account Settings` page, review and
    verify the current details.
    4. Under `Contact Information`, review and verify the current
    details.}
  desc 'fix', %q{
    This activity can only be performed via the AWS Console, with a user who has permission to read
    and write Billing information (aws-portal:\\*Billing ).

    1. Sign in to the AWS Management
    Console and open the `Billing and Cost Management` console at
    https://console.aws.amazon.com/billing/home#/.
    2. On the navigation bar, choose your
    account name, and then choose `Account`.
    3. On the `Account Settings` page, next to
    `Account Settings`, choose `Edit`.
    4. Next to the field that you need to update, choose
    `Edit`.
    5. After you have entered your changes, choose `Save changes`.
    6. After you have
    made your changes, choose `Done`.
    7. To edit your contact information, under `Contact
    Information`, choose `Edit`.
    8. For the fields that you want to change, type your updated
    information, and then choose `Update`. }
  impact 0.5
  ref 'https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-account-payment.html#contact-info'
  tag nist: ['IR-6']
  tag severity: 'medium '
  tag cis_controls: [
    { '8' => ['17.2'] },
  ]

  if aws_primary_contact.configured?
    describe aws_primary_contact do
      it { should be_configured }
      its('address_line_1.first') { should cmp "#{input('primary_contact')[:address_line_1]}" }
      its('city.fist') { should cmp "#{input('primary_contact')[:city]}" }
      its('full_name.first') { should cmp "#{input('primary_contact')[:full_name]}" }
      its('phone_numer.first') { should cmp "#{input('primary_contact')[:phone_number]}" }
      its('postal_code.first') { should cmp "#{input('primary_contact')[:postal_code]}" }
    end
  else
    raise "The AWS Account's Primary Contact information is not configured"
  end
end
