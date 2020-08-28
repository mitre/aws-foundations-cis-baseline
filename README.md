# cis-aws-foundations-baseline

InSpec profile to validate your VPC to the standards of the CIS Amazon Web Services Foundations Benchmark v1.2.0 - 05-23-2018

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile implement the [CIS AWS Foundations Benchmark](https://github.com/mitre/cis-aws-foundations-baseline) in an automated way to provide security best-practice tests in an AWS environment.

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

- [InSpec](http://inspec.io/) at least version 4.x
- [AWS CLI](https://aws.amazon.com/cli/) at least version 2.x

### Tested Platforms

This profile is being developed and tested along side a `hardening` recipe implemented in Terraform. The [cis-aws-foundations-hardening](https://github.com/mitre/cis-aws-foundations-hardening) will help you configure and deploy your AWS environment to meet the requirements of the security baseline.

## Get started

### Installing InSpec 

If needed - install inspec on your 'runner' system - i.e. your orchestration server, your workstation, your bastion host or your instance you wish to evlauate.

  a. InSpec has prepackaged installers for all platforms here: https://www.inspec.io/downloads, or 
  
  b. If you already have a ruby environment (`2.4.x`) installed on your 'runner' system - you can just do a simple `gem install inspec`, or 
  
  c. You can use the AWS SSM suite to run InSpec on your AWS assets - see the InSpec + SSM documation here: https://aws.amazon.com/blogs/mt/using-aws-systems-manager-to-run-compliance-scans-using-inspec-by-chef/
  
### Get the CIS AWS Foundations Baseline

You will need to download the InSpec Profile to your `runner` system. You can do this via `git` or the GitHub Web interface, etc.

  a. `git clone https://github.com/mitre/cis-aws-foundations-baseline`, or 
  
  b. Save a Zip or tar.gz copy of the master branch from the `Clone or Download` button of this project

### Setting up dependencies in your Ruby and InSpec Environments

The profile uses Bundler to manage needed dependencies - so you will need to installed the needed gems via bundler before you run the profile. Change directories to your your cloned inspec profile then do a `bundle install`. 

  a. `cd cis-aws-foundations-baseline` 
  
  b. `bundle install`

### Minimum Permissions needed to Run this Profile

The IAM account used to run this profile against the AWS environment needs to attached through a group or role with at least `AWS IAM "ReadOnlyAccess" Managed Policy` 

### Getting MFA Aware AWS Access, Secret and Session Tokens

You will need to ensure your AWS CLI environment has the right system environment variables set with your AWS region and credentials and session token to use the AWS CLI and InSpec resources in the AWS environment. InSpec supports the following standard AWS variables:

- `AWS_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (optional) - required if MFA is enabled

### Notes on MFA

In any AWS MFA enabled environment - you need to use `derived credentials` to use the CLI. Your default `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` will not satisfy the MFA Policies in AWS environments. 

- The AWS documentation is here: https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
- The AWS profile documentation is here: https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
- A useful bash script for automating this is here: https://gist.github.com/dinvlad/d1bc0a45419abc277eb86f2d1ce70625

To generate credentials using an AWS Profile you will need to use the following AWS CLI commands.

  a. `aws sts get-session-token --serial-number arn:aws:iam::<$YOUR-MFA-SERIAL> --token-code <$YOUR-CURRENT-MFA-TOKEN> --profile=<$YOUR-AWS-PROFILE>` 

  b. Then export the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` that was generated by the above command.

### Building your `inputs.yml` file

We use a yml attribute file to steer the configuration, the following options are available:
The followiing attributes must be set to accepted/documented values which is
then verified by the applicable controls.

These attributes are generated if the profile is used with the Terraform hardening receipe (https://github.com/mitre/cis-aws-foundations-hardening) with kitchen-terraform.

- Primary aws region (2.5), <br>
`default_aws_region: 'us-east-1'`

- Compliant CloudTrail trail name (3.x), <br>
`aws_cloudtrail_trail: "aws_cloudtrail_trail"`

- Maximum aws key age (1.4), <br>
`aws_key_age: 90`

- Password length (1.9), <br>
`pwd_length: 14`

- Maximum IAM account age (1.11), <br>
`aws_cred_age: 90`

- List of **documented service accounts** which are exempt from the MFA requirement' (1.2),<br>
`service_account_mfa_exceptions:`<br>
  `- user1`<br>
  `- user2`<br>
  `- ...`<br>

- Config service list and settings in all relevant regions (2.5),<br>
```
config_delivery_channels:
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

## Generate Attributes

The repo includes a script : generate_attributes.rb to generate part of the attributes required for the profile.
The script will inspect aws regions: us-east-1, us-east-2, us-west-1, us-west-2 to generate the following attribute to STDOUT.

```
- config_delivery_channels
```
The generated attributes __must be reviewed carefully__. 
Only __valid__ channels should be placed in the inputs.yml file.

Usage:
```
  ruby generate_attributes.rb
```

## Additional optional attributes the user may add to their inputs file:

```
# description: 'list of buckets exempted from inspection' (2.3, 2.6),
exception_bucket_list: ["exception_bucket_name"]

# description: 'list of security groups exempted from inspection' (4.1, 4.2),
exception_security_group_list: ["exception_security_group_name"]
```

## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

```
# Clone Inspec Profile
$ git clone https://github.com/mitre/cis-aws-foundations-baseline

# Install Gems
$ bundle install

# Set required ENV variables
$ export AWS_ACCESS_KEY_ID=key-id
$ export AWS_SECRET_ACCESS_KEY=access-key
$ export AWS_SESSION_TOKEN=session_token
$ export AWS_REGION=us-west-1

# Run the `generate_attributes.rb` 
$ ruby generate_attributes.rb
# The generated attributes __must be reviewed carefully__. 
# Only __valid__ channels should be placed in the inputs.yml file.

# To run profile locally and directly from Github
$ inspec exec /path/to/profile -t aws:// --input-file=inputs.yml

# To run profile locally and directly from Github with cli & json output 
$ inspec exec /path/to/profile -t aws:// --input-file=inputs.yml --reporter cli json:aws-results.json

# To run profile locally and directly from Github with cli & json output, in a specific region with a specific AWS profile
$ inspec exec /path/to/profile -t aws://us-east-1/<mycreds-profile> --input-file=inputs.yml --reporter cli json:aws-results.json

```

### Run individual controls

In order to verify individual controls, just provide the control ids to InSpec:

```
$ inspec exec /path/to/profile --input-file=inputs.yml --controls cis-aws-foundations-1.10
```

## Contributors + Kudos

- Rony Xavier [rx294](https://github.com/rx294)
- Aaron Lippold [aaronlippold](https://github.com/aaronlippold)
- Shivani Karikar [karikarshivani](https://github.com/karikarshivani)

## License and Author

### Authors

- Author:: Rony Xaiver [rx294@gmail.com](mailto:rx294@gmail.com)
- Author:: Aaron Lippold [lippold@gmail.com](mailto:lippold@gmail.com)

## NOTICE

© 2018 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE

CIS Benchmarks are published by the Center for Internet Security (CIS), see: https://www.cisecurity.org/.
