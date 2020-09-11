# encoding: UTF-8

control "aws-foundations-cis-1.15" do
  title "Ensure security questions are registered in the AWS account"
  desc  "The AWS support portal allows account owners to establish security questions that can be used to authenticate individuals calling AWS customer service for support. It is recommended that security questions be established."
  desc  "rationale", "When creating a new AWS account, a default super user is automatically created. This account is referred to as the \"root\" account. It is recommended that the use of this account be limited and highly controlled. During events in which the Root password is no longer accessible or the MFA token associated with root is lost/destroyed it is possible, through authentication using secret questions and associated answers, to recover root login access."
  desc  "check", "Perform the following in the AWS Management Console:

    1. Login to the AWS account as root
    2. On the top right you will see the __
    3. Click on the __
    4. From the drop-down menu Click `My Account`
    5. In the `Configure Security Challenge Questions` section on the `Personal Information` page, configure three security challenge questions.
    6. Click `Save questions` ."
  desc  "fix", "Perform the following in the AWS Management Console:

    1. Login to the AWS Account as root
    2. Click on the __ from the top right of the console
    3. From the drop-down menu Click _My Account_
    4. Scroll down to the `Configure Security Questions` section
    5. Click on `Edit`
    6. Click on each `Question`
     - From the drop-down select an appropriate question
     - Click on the `Answer` section
     - Enter an appropriate answer
     - Follow process for all 3 questions
    7. Click `Update` when complete
    8. Place Questions and Answers and place in a secure physical location"
  impact 0.5
  tag severity: "Low"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AC-2']
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Account Monitoring and Control CONTROL:16 DESCRIPTION:Account Monitoring and Control;"

  
  describe 'Control has to be tested manually' do
    skip 'This control must be manually reviewed'
  end
end