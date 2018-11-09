# cis-aws-foundations-baseline 
Inspec profile as per CIS Amazon Web Services Foundations Benchmark v1.1.0 - 11-29-2016

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile implement the [CIS AWS Foundations Benchmark](https://github.com/aaronlippold/cis-aws-foundations-baseline) in an automated way to provide security best-practice tests in an AWS environment.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Versioning and State of Development
This project uses the [Semantic Versioning Policy](https://semver.org/). 

### Branches
The master branch contains the latest version of the software leading up to a new release. 

Other branches contain feature-specific updates. 

### Tags
Tags indicate official releases of the project.

Please note 0.x releases are works in progress (WIP) and may change at any time.   

## Requirements

- [InSpec](http://inspec.io/) at least version 2.1
- [AWS CLI](https://aws.amazon.com/cli/) at least version 2.x

### Tested Platforms

This profile is being developed and tested along side a `hardening` recipe implemented in Terraform. The [cis-aws-foundations-hardening](https://github.com/aaronlippold/cis-aws-foundations-hardening) will help you configure and deploy your AWS environment to meet the requirements of the security baseline.

## Get started

Bundle install required gems <br>
- `bundle install`

Before running the profile with InSpec, define environment variables with your AWS region and credentials.  InSpec supports the following standard AWS variables:

- `AWS_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (optional)

## Attributes

We use a yml attribute file to steer the configuration, the following options are available:
The followiing attributes must be set to accepted/documented values which is 
then verified by the applicable controls.

These attributes are generated if the profile is used with the Terraform hardening receipe (https://github.com/aaronlippold/cis-aws-foundations-hardening) with kitchen-terraform.

- default aws key age (1.4), <br>
`aws_key_age: 90`

- Make the password length (1.9), <br>
`pwd_length: 14`

- make the aws_cred_age an attribute (1.11), <br>
`aws_cred_age: 90`

- description: 'default aws region', <br>
`aws_region: 'us-east-1'`

- description: 'iam manager role name',<br>
`iam_manager_role_name: "iam_manager_role_name"`

- description: 'iam master role name',<br>
`iam_master_role_name: "iam_master_role_name"`

- description: 'iam manager user name',<br>
`iam_manager_user_name: "iam_manager_user_name"`

- description: 'iam master user name',<br>
`iam_master_user_name: "iam_master_user_name"`

- description: 'iam manager policy name',<br>
`iam_manager_policy_name: "iam_manager_policy"`

- description: 'iam master policy name',<br>
`iam_master_policy_name: "iam_master_policy"`

- description: 'list of instances that have specific roles',<br>
`aws_actions_performing_instance_ids: ["aws_access_instance_id"]`

- description: 'Config service list and settings in all relevant regions',<br>
```
config_service:
    us-east-1: 
      s3_bucket_name: "s3_bucket_name_value"
      sns_topic_arn: "sns_topic_arn_value"
    us-east-2: 
      s3_bucket_name:  "s3_bucket_name_value"
      sns_topic_arn: "sns_topic_arn_value"
    us-west-1: 
      s3_bucket_name:  "s3_bucket_name_value"
      sns_topic_arn: "sns_topic_arn_value"
    us-west-2: 
      s3_bucket_name:  "s3_bucket_name_value"
      sns_topic_arn: "sns_topic_arn_value"

```


- description: 'SNS topics list and details in all relevant regions',<br>
```
sns_topics: 
    topic_arn1 : 
      owner : "owner_value"
      region : "region_value"
    topic_arn2 :
      owner : "owner_value"
      region : "region_value"`
```
  

- description: 'SNS subscription list and details in all relevant regions', <br>
```
sns_subscriptions: 
    subscription_arn1: 
      endpoint: "endpoint_value"
      owner: "owner_value"
      protocol: "protocol_value"
    subscription_arn2: 
      endpoint: "endpoint_value"
      owner: "owner_value"
      protocol: "protocol_value"`
```


## Generate Attributes

The repo includes a script : generate_attributes.rb to generate part of the attributes required for the profile.
The script will inspect aws regions: us-east-1, us-east-2, us-west-1, us-west-2 to generate the following attributes to STDOUT.

```
- config_delivery_channels
- sns_topics
- sns_subscriptions
```
The generated attributes __must be reviewed carefully__ and can be placed in the atttributes yaml file required for the inspec run.

Usage:
```
  ruby generate_attributes.rb
```
## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

```
# Clone Inspec Profile
$ git clone https://github.com/aaronlippold/cis-aws-foundations-baseline

# Install Gems
$ bundle install

# Set required ENV variables
$ export AWS_ACCESS_KEY_ID=key-id
$ export AWS_SECRET_ACCESS_KEY=access-key

# Provide required data in attributes.yml
# Following script can be used to auto-generate part of the attributes.yml
$ ruby generate_attributes.rb

# run profile locally and directly from Github
$ inspec exec /path/to/profile -t aws:// --attrs=attributes.yml

# run profile locally and directly from Github with cli & json output 
$ inspec exec /path/to/profile -t aws:// --attrs=attributes.yml --reporter cli json:aws-results.json

```

### Run individual controls

In order to verify individual controls, just provide the control ids to InSpec:

```
$ inspec exec /path/to/profile --attrs=attributes.yml --controls cis-aws-foundations-1.10
```

## Contributors + Kudos

- Rony Xavier [rx294](https://github.com/rx294)
- Aaron Lippold [aaronlippold](https://github.com/aaronlippold)

## License and Author

### Authors

- Author:: Rony Xaiver [rx294@gmail.com](mailto:rx294@gmail.com)
- Author:: Aaron Lippold [lippold@gmail.com](mailto:lippold@gmail.com)

## NOTICE  

© 2018 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

## NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.   

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

## NOTICE

CIS Benchmarks are published by the Center for Internet Security (CIS), see: https://www.cisecurity.org/.
