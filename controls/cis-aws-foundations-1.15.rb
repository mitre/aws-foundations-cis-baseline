control 'cis-aws-foundations-1.15' do
  title 'Ensure security questions are registered in the AWS account'
  desc  "The AWS support portal allows account owners to establish security
questions that can be used to authenticate individuals calling AWS customer
service for support. It is recommended that security questions be established."
  impact 0.3
  tag "rationale": "When creating a new AWS account, a default super user is
automatically created. This account is referred to as the 'root' account. It is
recommended that the use of this account be limited and highly controlled.
During events in which the Root password is no longer accessible or the MFA
token associated with root is lost/destroyed it is possible, through
authentication using secret questions and associated answers, to recover root
login access."
  tag "cis_impact": ''
  tag "cis_rid": '1.15'
  tag "cis_level": 1
  tag "cis_control_number": ''
  tag "nist": ['IA-2', 'Rev_4']
  tag "cce_id": ''
  tag "check": "Perform the following in the AWS Management Console:

* Login to the AWS account as root
* On the top right you will see the _<Root_Account_Name>_
* Click on the _<Root_Account_Name>_
* From the drop-down menu Click My Account
* In the Configure Security Challenge Questions section on the Personal
Information page, configure three security challenge questions.
* Click Save questions."
  tag "fix": "Perform the following in the AWS Management Console:

* Login to the AWS Account as root
* Click on the _<Root_Account_Name>_ from the top right of the console
* From the drop-down menu Click _My Account_
* Scroll down to the Configure Security Questions section
* Click on Edit

* Click on each Question

* From the drop-down select an appropriate question
* Click on the Answer section

* Enter an appropriate answer

* Follow process for all 3 questions


* Click Update when complete
* Place Questions and Answers and place in a secure physical location"

  describe 'Control has to be tested manually' do
    skip 'This control must be manually reviewed'
  end
end
