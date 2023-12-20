control 'aws-foundations-cis-1.3' do
  title 'Ensure security questions are registered in the AWS account '
  desc "
    The AWS support portal allows account owners to establish security questions that can be used
    to authenticate individuals calling AWS customer service for support. It is recommended
    that security questions be established.
    "
  desc 'rationale',
       "When creating a new AWS account, a default super user is automatically created. This account
    is referred to as the 'root user' or 'root' account. It is recommended that the use of this
    account be limited and highly controlled. During events in which the 'root' password is no
    longer accessible or the MFA token associated with 'root' is lost/destroyed it is possible,
    through authentication using secret questions and associated answers, to recover 'root'
    user login access.
    "
  desc 'check',
       "**From Console:**

    1. Login to the AWS account as the 'root' user
    2. On the top right you
    will see the _<Root\\_Account\\_Name>_
    3. Click on the _<Root\\_Account\\_Name>_
    4. From
    the drop-down menu Click `My Account`
    5. In the `Configure Security Challenge Questions`
    section on the `Personal Information` page, configure three security challenge
    questions.
    6. Click `Save questions` . "

  desc 'fix',
       "**From Console:**

    1. Login to the AWS Account as the 'root' user
    2. Click on the
    _<Root\\_Account\\_Name>_ from the top right of the console
    3. From the drop-down menu Click
    _My Account_
    4. Scroll down to the `Configure Security Questions` section
    5. Click on
    `Edit`
    6. Click on each `Question`
    - From the drop-down select an appropriate question

    - Click on the `Answer` section
    - Enter an appropriate answer
    - Follow process for all 3
    questions
    7. Click `Update` when complete
    8. Save Questions and Answers and place in a
    secure physical location."

  impact 0.5
  tag nist: ['IR-6']
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['17.2'] }]

  only_if('AWS GovCloud only allows you to Manually view Account information, please review this requirement in the AWS GovCloud Console.') {
    !aws_sts_caller_identity.govcloud?
  }

  describe 'Requirement must be tested manually' do
    skip "
      This control must be manually reviewed, AWS does not support validation of the
      Security Challenge Questions in the AWS CLI or by an API.
      Examine the root account's security challenge questions in the AWS Managment Console."
  end
end
