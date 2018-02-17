IAM_MANAGER_ROLE_NAME= attribute(
  'iam_manager_role_name',
  description: 'iam manager role name',
  default: "iam_manager_role_name"
)

IAM_MASTER_ROLE_NAME= attribute(
  'iam_master_role_name',
  description: 'iam master role name',
  default: "iam_master_role_name"
)

IAM_MANAGER_USER_NAME= attribute(
  'iam_manager_user_name',
  description: 'iam manager user name',
  default: "iam_manager_user_name"
)

IAM_MASTER_USER_NAME= attribute(
  'iam_master_user_name',
  description: 'iam master user name',
  default: "iam_master_user_name"
)

IAM_MANAGER_GROUP_NAME= attribute(
  'iam_manager_group_name',
  description: 'iam manager group name',
  default: "iam_manager_group_name"
)

IAM_MASTER_GROUP_NAME= attribute(
  'iam_master_group_name',
  description: 'iam master group name',
  default: "test-role-group"
)

IAM_MANAGER_POLICY= attribute(
  'iam_manager_policy',
  description: 'iam manager policy',
  default: "iam_manager_policy"
)

IAM_MASTER_POLICY= attribute(
  'iam_master_policy',
  description: 'iam master policy',
  default: "iam_master_policy"
)

IAM_MANAGER_ASSUME_POLICY= attribute(
  'iam_manager_assume_policy',
  description: 'iam manager assume policy',
  default: "iam_manager_assume_policy"
)

IAM_MASTER_ASSUME_POLICY= attribute(
  'iam_master_assume_policy',
  description: 'iam master assume policy',
  default: "iam_master_assume_policy"
)

control "cis-aws-foundations-1.18" do
  title "Ensure IAM Master and IAM Manager roles are active"
  desc  "Ensure IAM Master and IAM Manager roles are in place for IAM
administration and assignment of administrative permissions for other services
to other roles.

'An IAM role is conceptually 'a container of permissions resembling a user
account which cannot be directly logged into, but which must instead be assumed
from an existing user account which has appropriate permissions to do so', in
the manner of roles in Unix Role-Based Access Control (RBAC). In AWS, roles can
also be assigned to EC2 instances and Lambda functions.

Control over IAM, which is also defined and mediated by a number of
fine-grained permissions, should be divided between a number of roles, such
that no individual user in a production account has full control over IAM."
  impact 0.4
  tag "rationale": "IAM is the principal point of control for service
configuration access, and 'control over IAM' means 'control over the
configuration of all other assets in the AWS account'. Therefore it is
recommended that control of this degree of security criticality should be
divided among multiple individuals within an organisation, in a manner such
that no individual retains enough control over IAM to 'rewrite themselves to
root'.

Roles are recommended for security-sensitive capabilities, as the act of
assuming a role generates a set of ephemeral credentials using the Security
Token Service (STS) and these credentials - being a token, an AWS Access Key
and an AWS Secret Access Key - are needed to make API calls in the context of
the role. STS credentials expire after a configurable period (default 12 hours,
minimum 15 minutes, maximum 36 hours), and this reduces the risk of engineers
hard-wiring these keys into code, and therefore further reduces the risk of the
keys being mishandled.

The current recommendation is to divide account and permission configuration
permissions between 2 roles, which are:

IAM Master: creates users, groups and roles; assigns permissions to roles
IAM Manager: assigns users and roles to groups

In this model, IAM Master and IAM Manager must work together in a 2-person rule
manner, in order for a user to gain access to a permission."
  tag "cis_impact": ""
  tag "cis_rid": "1.18"
  tag "cis_level": 1
  tag "severity": "low"
  tag "csc_control": ""
  tag "nist": ["AC-6(7)", "Rev_4"]
  tag "cce_id": ""
  tag "check": "Using the Amazon unified CLI, from a user or role which has the
iam:ListRoles and iam:GetRolePolicy permissions:

List the configured roles:

'aws iam list-roles --query 'Roles[*].{RoleName:RoleName, Arn:Arn}'

'The output should contain entries with 'RoleName': '_<iam_manager_role_name>_'
and 'Rolename': '_<iam_master_role_name>_'

Examine the permissions associated with each of these roles:

'aws iam get-role-policy --role-name _<iam_manager_role_name>_

'aws iam get-role-policy --role-name _<iam_master_role_name>_

The _<iam_master_role_name>_ role should include the following Actions with an
Allow effect:

iam:AttachRolePolicy
iam:CreateGroup
iam:CreatePolicy
iam:CreatePolicyVersion
iam:CreateRole
iam:CreateUser
iam:DeleteGroup
iam:DeletePolicy
iam:DeletePolicyVersion
iam:DeleteRole
iam:DeleteRolePolicy
iam:DeleteUser
iam:PutRolePolicy
iam:GetPolicy
iam:GetPolicyVersion
iam:GetRole
iam:GetRolePolicy
iam:GetUser
iam:GetUserPolicy
iam:ListEntitiesForPolicy
iam:ListGroupPolicies
iam:ListGroups
iam:ListGroupsForUser
iam:ListPolicies
iam:ListPoliciesGrantingServiceAccess
iam:ListPolicyVersions
iam:ListRolePolicies
iam:ListAttachedGroupPolicies
iam:ListAttachedRolePolicies
iam:ListAttachedUserPolicies
iam:ListRoles
iam:ListUsers

and the following Actions with a Deny effect:

iam:AddUserToGroup
iam:AttachGroupPolicy
iam:DeleteGroupPolicy
iam:DeleteUserPolicy
iam:DetachGroupPolicy
iam:DetachRolePolicy
iam:DetachUserPolicy
iam:PutGroupPolicy
iam:PutUserPolicy
iam:RemoveUserFromGroup
iam:UpdateGroup
iam:UpdateAssumeRolePolicy
iam:UpdateUser

The _<iam_manager_role_name>_ role should include the following Actions with an
Allow effect:

iam:AddUserToGroup
iam:AttachGroupPolicy
iam:DeleteGroupPolicy
iam:DeleteUserPolicy
iam:DetachGroupPolicy
iam:DetachRolePolicy
iam:DetachUserPolicy
iam:PutGroupPolicy
iam:PutUserPolicy
iam:RemoveUserFromGroup
iam:UpdateGroup
iam:UpdateAssumeRolePolicy
iam:UpdateUser
iam:GetPolicy
iam:GetPolicyVersion
iam:GetRole
iam:GetRolePolicy
iam:GetUser
iam:GetUserPolicy
iam:ListEntitiesForPolicy
iam:ListGroupPolicies
iam:ListGroups
iam:ListGroupsForUser
iam:ListPolicies
iam:ListPoliciesGrantingServiceAccess
iam:ListPolicyVersions
iam:ListRolePolicies
iam:ListAttachedGroupPolicies
iam:ListAttachedRolePolicies
iam:ListAttachedUserPolicies
iam:ListRoles
iam:ListUsers

and the following Actions with a Deny effect:

iam: AttachRolePolicy
iam:CreateGroup
iam:CreatePolicy
iam:CreatePolicyVersion
iam:CreateRole
iam:CreateUser
iam:DeleteGroup
iam:DeletePolicy
iam:DeletePolicyVersion
iam:DeleteRole
iam:DeleteRolePolicy
iam:DeleteUser
iam:PutRolePolicy

Other iam:* Actions may be included in these policies as needed.

Both policies should also be limited by a Condition that MFA authentication is
in effect, by containing:

'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}

in the Allow effect section (provided IAM Federation has not been configured).


Each role needs to be assumable by at least one user or group:

'aws iam get-role --role-name _<iam_manager_role_name>_

'aws iam get-role --role-name _<iam_master_role_name>_

'should display the AssumeRolePolicyDocument indicating which users and groups
are able to assume the roles. No user or group should be able to assume both
roles."
  tag "fix": "Using the Amazon unified CLI, from a user or role which has the
iam:CreateRole, iam:CreatePolicy and iam:PutRolePolicy permissions:

'aws iam create-role --role-name _<iam_manager_role_name>_

'aws iam create-role --role-name _<iam_master_role_name>_

'aws iam put-role-policy --role-name _<iam_manager_role_name>_ --policy-name
_<iam_manager_permissions_policy>_ --policy-document
<a>file://IAM-Manager-policy.json</a>

'aws iam put-role-policy --role-name _<iam_master_role_name>_ --policy-name
_<iam_master_permissions_policy>_ --policy-document
<a>file://IAM-Master-policy.json</a>

'where IAM-Master-policy.json contains:

'{

' 'Version': '2012-10-17',

' 'Statement': [{

' 'Action': [

' 'iam:CreateGroup',

''iam:CreatePolicy',

''iam:CreatePolicyVersion',

''iam:CreateRole',

''iam:CreateUser',

''iam:DeleteGroup',

''iam:DeletePolicy',

''iam:DeletePolicyVersion',

''iam:DeleteRole',

''iam:DeleteRolePolicy',

''iam:DeleteUser',

''iam:PutRolePolicy',

''iam:GetPolicy',

''iam:GetPolicyVersion',

''iam:GetRole',

''iam:GetRolePolicy',

''iam:GetUser',

''iam:GetUserPolicy',

''iam:ListEntitiesForPolicy',

''iam:ListGroupPolicies',

''iam:ListGroups',

''iam:ListGroupsForUser',

''iam:ListPolicies',

''iam:ListPoliciesGrantingServiceAccess',

''iam:ListPolicyVersions',

''iam:ListRolePolicies',

''iam:ListAttachedGroupPolicies',

''iam:ListAttachedRolePolicies',

''iam:ListAttachedUserPolicies',

''iam:ListRoles',

''iam:ListUsers'

' ],

' 'Effect': 'Allow',

' 'Resource': '*',

' 'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}

' }],

' 'Action': [

''iam:AddUserToGroup',

''iam:AttachGroupPolicy',

''iam:DeleteGroupPolicy',

''iam:DeleteUserPolicy',

''iam:DetachGroupPolicy',

''iam:DetachRolePolicy',

''iam:DetachUserPolicy',

''iam:PutGroupPolicy',

''iam:PutUserPolicy',

''iam:RemoveUserFromGroup',

''iam:UpdateGroup',

''iam:UpdateAssumeRolePolicy',

''iam:UpdateUser'

' ],

' 'Effect': 'Deny',

' 'Resource': '*'

' }]

'}

'and where IAM-Manager-policy.json contains:

'{

' 'Version': '2012-10-17',

' 'Statement': [{

' 'Action': [

''iam:AddUserToGroup',

''iam:AttachGroupPolicy',

''iam:DeleteGroupPolicy',

''iam:DeleteUserPolicy',

''iam:DetachGroupPolicy',

''iam:DetachRolePolicy',

''iam:DetachUserPolicy',

''iam:PutGroupPolicy',

''iam:PutUserPolicy',

''iam:RemoveUserFromGroup',

''iam:UpdateGroup',

''iam:UpdateAssumeRolePolicy',

''iam:UpdateUser',

''iam:GetPolicy',

''iam:GetPolicyVersion',

''iam:GetRole',

''iam:GetRolePolicy',

''iam:GetUser',

''iam:GetUserPolicy',

''iam:ListEntitiesForPolicy',

''iam:ListGroupPolicies',

''iam:ListGroups',

''iam:ListGroupsForUser',

''iam:ListPolicies',

''iam:ListPoliciesGrantingServiceAccess',

''iam:ListPolicyVersions',

''iam:ListRolePolicies',

''iam:ListAttachedGroupPolicies',

''iam:ListAttachedRolePolicies',

''iam:ListAttachedUserPolicies',

''iam:ListRoles',

''iam:ListUsers'

' ],

' 'Effect': 'Allow',

' 'Resource': '*',

' 'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}

' }],

' 'Action': [

' 'iam:CreateGroup',

''iam:CreatePolicy',

''iam:CreatePolicyVersion',

''iam:CreateRole',

''iam:CreateUser',

''iam:DeleteGroup',

''iam:DeletePolicy',

''iam:DeletePolicyVersion',

''iam:DeleteRole',

''iam:DeleteRolePolicy',

''iam:DeleteUser',

''iam:PutRolePolicy'

' ],

' 'Effect': 'Deny',

' 'Resource': '*'

' }]

'}

'Note that each of IAM-Manager-policy.json and IAM-Master-policy.json can
contain other iam:* permissions in either Allow or Deny Action lists, depending
on what other requirements are in place in the account.

'Each of these roles needs to be assumable by a different user or group.

'For appropriate users or groups (groups are recommended):

'aws iam put-user-policy --user-name _<iam_user>_ --policy-name
_<assume_iam_master_role_policy>_ --policy-document
<a>file://Assume-IAM-Master.json</a>

'aws iam put-user-policy --user-name _<iam_user>_ --policy-name
_<assume_iam_manager_role_policy>_ --policy-document
<a>file://Assume-IAM-Manager.json</a>

'or

'aws iam put-group-policy --group-name _<iam_group>_  --policy-name
_<assume_iam_master_role_policy>_ --policy-document
<a>file://Assume-IAM-Master.json</a>

'aws iam put-group-policy --group-name _<iam_group>_ --policy-name
_<assume_iam_manager_role_policy> _--policy-document
<a>file://Assume-IAM-Manager.json</a>

'where Assume-IAM-Master.json is:

'{

' 'Version': '2012-10-17',

' 'Statement': {

' 'Effect': 'Allow',

' 'Action': 'sts:AssumeRole',

' 'Resource': 'arn:aws:iam::_<aws_account_number>_:role/<iam_master_role_name>'


' }

'}

'and Assume-IAM-Manager.json is:

'{

' 'Version': '2012-10-17',

' 'Statement': {

' 'Effect': 'Allow',

' 'Action': 'sts:AssumeRole',

' 'Resource': 'arn:aws:iam::<aws_account_number>:role/<iam_manager_role_name>'


' }

'}"

master_allow_actions = [
  "iam:AttachRolePolicy",
  "iam:CreateGroup",
  "iam:CreatePolicy",
  "iam:CreatePolicyVersion",
  "iam:CreateRole",
  "iam:CreateUser",
  "iam:DeleteGroup",
  "iam:DeletePolicy",
  "iam:DeletePolicyVersion",
  "iam:DeleteRole",
  "iam:DeleteRolePolicy",
  "iam:DeleteUser",
  "iam:PutRolePolicy",
  "iam:GetPolicy",
  "iam:GetPolicyVersion",
  "iam:GetRole",
  "iam:GetRolePolicy",
  "iam:GetUser",
  "iam:GetUserPolicy",
  "iam:ListEntitiesForPolicy",
  "iam:ListGroupPolicies",
  "iam:ListGroups",
  "iam:ListGroupsForUser",
  "iam:ListPolicies",
  "iam:ListPoliciesGrantingServiceAccess",
  "iam:ListPolicyVersions",
  "iam:ListRolePolicies",
  "iam:ListAttachedGroupPolicies",
  "iam:ListAttachedRolePolicies",
  "iam:ListAttachedUserPolicies",
  "iam:ListRoles",
  "iam:ListUsers",
]

master_deny_actions= [
 "iam:AddUserToGroup",
 "iam:AttachGroupPolicy",
 "iam:DeleteGroupPolicy",
 "iam:DeleteUserPolicy",
 "iam:DetachGroupPolicy",
 "iam:DetachRolePolicy",
 "iam:DetachUserPolicy",
 "iam:PutGroupPolicy",
 "iam:PutUserPolicy",
 "iam:RemoveUserFromGroup",
 "iam:UpdateGroup",
 "iam:UpdateAssumeRolePolicy",
 "iam:UpdateUser"
]


manager_allow_actions=  [
 "iam:AddUserToGroup",
 "iam:AttachGroupPolicy",
 "iam:DeleteGroupPolicy",
 "iam:DeleteUserPolicy",
 "iam:DetachGroupPolicy",
 "iam:DetachRolePolicy",
 "iam:DetachUserPolicy",
 "iam:PutGroupPolicy",
 "iam:PutUserPolicy",
 "iam:RemoveUserFromGroup",
 "iam:UpdateGroup",
 "iam:UpdateAssumeRolePolicy",
 "iam:UpdateUser",
 "iam:GetPolicy",
 "iam:GetPolicyVersion",
 "iam:GetRole",
 "iam:GetRolePolicy",
 "iam:GetUser",
 "iam:GetUserPolicy",
 "iam:ListEntitiesForPolicy",
 "iam:ListGroupPolicies",
 "iam:ListGroups",
 "iam:ListGroupsForUser",
 "iam:ListPolicies",
 "iam:ListPoliciesGrantingServiceAccess",
 "iam:ListPolicyVersions",
 "iam:ListRolePolicies",
 "iam:ListAttachedGroupPolicies",
 "iam:ListAttachedRolePolicies",
 "iam:ListAttachedUserPolicies",
 "iam:ListRoles",
 "iam:ListUsers"
]

manager_deny_actions= [
 "iam:AttachRolePolicy",
 "iam:CreateGroup",
 "iam:CreatePolicy",
 "iam:CreatePolicyVersion",
 "iam:CreateRole",
 "iam:CreateUser",
 "iam:DeleteGroup",
 "iam:DeletePolicy",
 "iam:DeletePolicyVersion",
 "iam:DeleteRole",
 "iam:DeleteRolePolicy",
 "iam:DeleteUser",
 "iam:PutRolePolicy"
]

mfa_condition = {
                    "Bool": {
                        "aws:MultiFactorAuthPresent": "true"
                    }
                } 

  describe "Master Policy Allow Actions " do
    subject { master_allow_actions }
    it { should be_in aws_iam_policy('dev-IAM-MANAGER-POLICY').document.where(Effect: "Allow").actions.flatten }
  end

  describe "Master Policy Deny Actions " do
    subject { master_deny_actions }
    it { should be_in aws_iam_policy('dev-IAM-MANAGER-POLICY').document.where(Effect: "Deny").actions.flatten}
  end

  describe aws_iam_policy('dev-IAM-MANAGER-POLICY') do
    it { should be_attached_to_role('dev-iam-master-role') }
  end

  describe aws_iam_role('dev-iam-master-role').assume_role_policy_document do
    its('actions') { should be_in ['sts:AssumeRole','sts:AssumeRoleWithSAML','sts:AssumeRoleWithWebIdentity'] }
  end

  describe aws_iam_role('dev-iam-master-role').assume_role_policy_document.where(Action: "sts:AssumeRole").where(Effect: "Allow") do
    its("principals.to_s") { should match ":user/#{IAM_MASTER_USER_NAME}"}
    its("principals.to_s") { should_not match ":user/#{IAM_MANAGER_USER_NAME}"}
  end

  describe "Master Policy Allow Actions " do
    subject { master_allow_actions }
    it { should be_in aws_iam_policy('dev-IAM-MANAGER-POLICY').document.where(Effect: "Allow").actions.flatten }
  end

  describe "Master Policy Deny Actions " do
    subject { master_deny_actions }
    it { should be_in aws_iam_policy('dev-IAM-MANAGER-POLICY').document.where(Effect: "Deny").actions.flatten}
  end

  describe aws_iam_policy('dev-IAM-MANAGER-POLICY') do
    it { should be_attached_to_role('dev-iam-master-role') }
  end

  describe aws_iam_role('dev-iam-master-role').assume_role_policy_document do
    its('actions') { should be_in ['sts:AssumeRole','sts:AssumeRoleWithSAML','sts:AssumeRoleWithWebIdentity'] }
  end

  describe aws_iam_role('dev-iam-master-role').assume_role_policy_document.where(Action: "sts:AssumeRole").where(Effect: "Allow") do
    its("principals.to_s") { should match ":user/#{IAM_MASTER_USER_NAME}"}
    its("principals.to_s") { should_not match ":user/#{IAM_MANAGER_USER_NAME}"}
  end

  # describe aws_iam_policy(IAM_MASTER_POLICY).document.where(Effect: "Allow") do
  #   its("actions.flatten") { should match_array master_allow_actions}
  #   its("conditions") { should include mfa_condition }
  # end

  # describe aws_iam_policy(IAM_MASTER_POLICY).document.where(Effect: "Deny") do
  #   its("actions.flatten") { should match_array master_deny_actions}
  # end

  # describe aws_iam_policy(IAM_MASTER_POLICY) do
  #   it { should be_attached_to_role(IAM_MASTER_ROLE_NAME) }
  # end

  # describe aws_iam_role(IAM_MASTER_ROLE_NAME).assume_role_policy_document.where(Action: "sts:AssumeRole") do
  #   its("effects") { should match_array ["Allow"]}
  #   its("principals.to_s") { should match ":user/#{IAM_MASTER_USER_NAME}"}
  # end

  # describe aws_iam_policy(IAM_MASTER_ASSUME_POLICY).document.where(Action: "sts:AssumeRole") do
  #   its("effects") { should match_array ["Allow"]}
  #   its("resources.to_s") { should match ":role/#{IAM_MASTER_ROLE_NAME}" }
  #   its("resources.to_s") { should_not match ":role/#{IAM_MANAGER_ROLE_NAME}" }
  # end

  # describe aws_iam_group(IAM_MASTER_GROUP_NAME) do
  #   its('attached_policies') { should include IAM_MASTER_ASSUME_POLICY }
  #   its('users') { should include IAM_MASTER_USER_NAME }
  # end


  # describe aws_iam_policy(IAM_MANAGER_POLICY).document.where(Effect: "Allow") do
  #   its("actions") { should match_array manager_allow_actions}
  #   its("conditions") { should include mfa_condition }
  # end

  # describe aws_iam_policy(IAM_MANAGER_POLICY).document.where(Effect: "Deny") do
  #   its("actions.flatten") { should match_array manager_deny_actions}
  # end

  # describe aws_iam_policy(IAM_MANAGER_POLICY) do
  #   it { should be_attached_to_role(IAM_MANAGER_ROLE_NAME) }
  # end

  # describe aws_iam_role(IAM_MANAGER_ROLE_NAME).assume_role_policy_document.where(Action: "sts:AssumeRole") do
  #   its("effects") { should match_array ["Allow"]}
  #   its("principals.to_s") { should match ":user/#{IAM_MANAGER_USER_NAME}"}
  # end

  # describe aws_iam_policy(IAM_MANAGER_ASSUME_POLICY).document.where(Action: "sts:AssumeRole") do
  #   its("effects") { should match_array ["Allow"]}
  #   its("resources.first") { should match ":role/#{IAM_MANAGER_ROLE_NAME}" }
  # end

  # describe aws_iam_group(IAM_MANAGER_GROUP_NAME) do
  #   its('attached_policies') { should include IAM_MANAGER_ASSUME_POLICY }
  #   its('users') { should include IAM_MANAGER_USER_NAME }
  # end
end
