# encoding: UTF-8

control "aws-foundations-cis-1.21" do
  title "Ensure IAM users are managed centrally via identity federation or AWS Organizations for 
multi-account environments "
  desc "In multi-account environments, IAM user centralization facilitates greater user control. 
User access beyond the initial account is then provided via role assumption. Centralization 
of users can be accomplished through federation with an external identity provider or 
through the use of AWS Organizations. "
  desc "rationale", "Centralizing IAM user management to a single identity store reduces complexity and thus the 
likelihood of access management errors. "
  desc "check", "For multi-account AWS environments with an external identity provider... 

1. Determine 
the master account for identity federation or IAM user management
2. Login to that account 
through the AWS Management Console
3. Click `Services` 
4. Click `IAM` 
5. Click 
`Identity providers`
6. Verify the configuration

Then..., determine all accounts 
that should not have local users present. For each account...

1. Determine all accounts 
that should not have local users present
2. Log into the AWS Management Console
3. Switch 
role into each identified account
4. Click `Services` 
5. Click `IAM` 
6. Click 
`Users`
7. Confirm that no IAM users representing individuals are present

For 
multi-account AWS environments implementing AWS Organizations without an external 
identity provider... 

1. Determine all accounts that should not have local users 
present
2. Log into the AWS Management Console
3. Switch role into each identified 
account
4. Click `Services` 
5. Click `IAM` 
6. Click `Users`
7. Confirm that no IAM 
users representing individuals are present "
  desc "fix", "The remediation procedure will vary based on the individual organization's implementation 
of identity federation and/or AWS Organizations with the acceptance criteria that no 
non-service IAM users, and non-root accounts, are present outside the account providing 
centralized IAM user management. "
  impact 0.5
  tag nist: ['AC-2(1)']
  tag severity: "medium "
  tag cis_controls: [
    {"8" => ["5.6"]}
  ]
end
