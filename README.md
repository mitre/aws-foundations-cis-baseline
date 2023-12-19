# aws-foundations-cis-baseline

InSpec profile to validate the secure configuration of Amazon Web Services against [CIS'](https://www.cisecurity.org/cis-benchmarks/) Amazon Web Services Foundations Benchmark Version 2.0.0 - 06-28-2023

## Getting Started

It is intended and recommended that InSpec and this profile be run from a **"runner"** host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over **AWS CLI**.

**For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.**

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

This baseline also requires the AWS Command Line Interface (CLI) which is available at the [AWS CLI](https://aws.amazon.com/cli/) site (at least version 2.x).

### Minimum Permissions needed to Run this Profile

The IAM account used to run this profile against the AWS environment needs to attached through a group or role with at least `AWS IAM "ReadOnlyAccess" Managed Policy`

### Getting MFA Aware AWS Access, Secret and Session Tokens

You will need to ensure your AWS CLI environment has the right system environment variables set with your AWS region and credentials and session token to use the AWS CLI and InSpec resources in the AWS environment. InSpec supports the following standard AWS variables:

- `AWS_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (optional) - required if MFA is enabled

### Notes on MFA

In any AWS MFA enabled environment, you will need to use `derived credentials` to use the CLI. Your default `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` will not satisfy the MFA Policies in AWS environments.

- The AWS documentation is here: https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
- The AWS profile documentation is here: https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
- A useful bash script for automating this is here: https://gist.github.com/dinvlad/d1bc0a45419abc277eb86f2d1ce70625

To generate credentials using an AWS Profile you will need to use the following AWS CLI commands.

a. `aws sts get-session-token --serial-number arn:aws:iam::<$YOUR-MFA-SERIAL> --token-code <$YOUR-CURRENT-MFA-TOKEN> --profile=<$YOUR-AWS-PROFILE>`

b. Then export the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` that was generated by the above command.

## Tailoring to Your Environment

InSpec uses _inputs_, given in input files passed to the InSpec executable, to tailor profiles to run against specific environments. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

The `inspec.yml` metadata file at the root of this profile includes default values for each input. Any input that you do not explicitly set will be set to these defaults. 

An example inputs file, recorded in YAML format, is given below, with comments to explain the purpose of each input and which controls it is used in (note that '[]' represents an empty list in YAML format).

```yaml
# Flag to disable some of the longer-running controls (do not enable in production)
# controls disabled by this flag: 1.4, 1.5, 1.6, 1.7, 1.12, 1.14, 5.1, 5.2, 5.3
disable_slow_controls: false

# Primary aws region (3.5, 5.2, 5.3)
default_aws_region: 'us-east-1'

# Flag to force the profile to only test the default region in AWS -- useful if your entire environment is in one region
ignore_other_regions: false

# List of regions exempted from inspection (1.20, 4.16, 5.2)
exempt_regions:
  - us-east-2
  - us-west-2
  - eu-central-1
  - eu-west-1
  - eu-west-2
  - eu-west-3
  - eu-north-1
  - ap-south-1
  - ap-southeast-2
  - ap-southeast-1
  - sa-east-1
  - ca-central-1
  - ap-northeast-1
  - ap-northeast-2
  - ap-northeast-3

# List of ports that you wish to exclude from validation (allow connections from these ports)
# (5.1, 5.2, 5.3)
exempt_ports:
  - 3389

# List of protocols that you wish to exclude from validation (allow connections over these protocols)
# (Note that AWS uses '-1' to indicate ALL)
# (5.1, 5.2, 5.3)
exempt_protocols:
  - 17

# List of KMS Keys exempted from inspection (3.8)
exempt_kms_keys:
  - "kms_key_name"
  - ...

# List of route table IDs exempted from inspection (5.5)
exempt_routes:
  - "route_id"
  - ...

# List of vpc IDs exempted from inspection (5.4)
exempt_vpcs:
  - "vpc_id"
  - ...

# List of S3 buckets exempted from inspection (2.1.1, 2.1.2, 2.1.4, 3.3, 3.6)
exempt_buckets:
  - "exception_bucket_name"
  - ...

# If you only want to inspect a single S3 bucket, give its name here (2.1.1, 2.1.2)
single_bucket: ""

# List of EC2 instances exempted from inspection (5.6)
exempt_ec2s:
  - "exception_ec2_name"
  - ...

# List of EFS exempted from inspection (2.4.1)
exempt_efs:
  - "exception_efs_name"
  - ...

# If you only want to inspect a single EFS, give its name here (2.4.1)
single_efs: ""

# List of RDS DB identifiers exempted from inspection (2.3.1, 2.3.2, 2.3.3)
exempt_rds:
  - "exception_rds_name"
  - ...

# If you only want to inspect a single RDS DB, give its name here (2.3.1, 2.3.2, 2.3.3)
single_rds: ""

# Flag to ignore non-running EC2s during inspection
skip_stopped_ec2s: false

# List of security groups exempted from inspection (5.2, 5.3)
exempt_security_groups: 
  - "exception_security_group_name"
  - ...

  # List of ruby regex patterns to exempt from evaluation (5.2, 5.3)
exempt_sg_patterns: 
  - /exempt-sg/
  - ...

# List of **documented service accounts** which are exempt from the MFA requirement (1.10)
service_account_mfa_exceptions:
  - user1
  - user2
  - ...

# You can specify one single CloudTrail name to inspect instead of all of them (3.10, 3.11)
single_trail: []

# IDs of network ACLs to exempt from evaluation (5.1)
exempt_acl_ids: []

# Port ranges used in the environment for remote access management
# Can be given as a single integer or as a Ruby range with double-period syntax, ex 1..1024
# (5.1, 5.2, 5.3)
remote_management_port_ranges:
  - 22

# Protocols used in the environment for remote access management (5.1, 5.2)
# (Note that AWS defines '-1' as equivalent to ALL)
remote_management_protocols:
  - 17
  - -1

# Config service list and settings in all relevant regions (3.5)
# (Note that this value can be found by running the `generate_inputs.rb` script)
config_delivery_channels:
  us-east-1:
    s3_bucket_name: "s3_bucket_name_value"
    sns_topic_arn: "sns_topic_arn_value"
  us-east-2:
    s3_bucket_name: "s3_bucket_name_value"
    sns_topic_arn: "sns_topic_arn_value"
  us-west-1:
    s3_bucket_name: "s3_bucket_name_value"
    sns_topic_arn: "sns_topic_arn_value"
  us-west-2:
    s3_bucket_name: "s3_bucket_name_value"
    sns_topic_arn: "sns_topic_arn_value"

# Email and Phone number of primary PoC for this AWS environment (1.1)
primary_contact:
  phone_number: "555-857-6309"
  email_address: "me@you.com"
  
# Email and Phone number of security PoC for this AWS environment (1.2)
primary_contact:
  phone_number: "555-857-6309"
  email_address: "me@you.com"

# The last data on which the root account should have logged in, given in YYYYMMDD (1.7)
last_root_login_date: 20231201

# If your environment is monitoring stored data via a tool OTHER THAN AWS Macie, specify its name here  (2.1.3)
third_party_data_management_tool: ""

# If your environment is monitoring API call via tools OTHER THAN AWS CloudTrail and Cloudwatch, specify its name here (4.14, 4.15)
third_party_api_monitoring_tool: ""
```

## Benchmark Status

| **Status** | **Reviewed** | **Recommendation** | **Uses Input**                                    |
| ---------- | ------------ | ------------------ | ------------------------------------------------- |
| Done       | Yes          | 1.1                | primary_contact                                   |
| Done       | Yes          | 1.2                | security_contact                                  |
| Manual     | Yes          | 1.3                | None                                              |
| Done       | Yes          | 1.4                | disable_slow_controls                             |
| Done       | Yes          | 1.5                | disable_slow_controls                             |
| Done       | Yes          | 1.6                | disable_slow_controls                             |
| Done       | Yes          | 1.7                | disable_slow_controls<br>last_root_login_date<br> |
| Done       | Yes          | 1.8                | None                                              |
| Done       | Yes          | 1.9                | None                                              |
| Done       | Yes          | 1.10               | service_account_mfa_exceptions                    |
| Done       | Yes          | 1.11               | None                                              |
| Done       | Yes          | 1.12               | disable_slow_controls                             |
| Done       | Yes          | 1.13               | None                                              |
| Done       | Yes          | 1.14               | disable_slow_controls                             |
| Done       | Yes          | 1.15               | None                                              |
| Done       | Yes          | 1.16               | None                                              |
| Done       | Yes          | 1.17               | None                                              |
| Done       | Yes          | 1.18               | None                                              |
| Done       | Yes          | 1.19               | None                                              |
| Done       | Yes          | 1.20               | exempt_regions                                    |
| Manual     | Yes          | 1.21               | None                                              |
| Done       | Yes          | 1.22               | None                                              |
| Done       | Yes          | 2.1.1              | exempt_buckets<br>single_bucket                   |
| Done       | Yes          | 2.1.2              | exempt_buckets<br>single_bucket                   |

| Done       | No           | 2.1.2              | exempt_buckets<br>single_bucket                   |
| Done       | No           | 2.1.3              | third_party_management_tool<br>exempt_buckets     |
| Done       | Yes          | 2.1.4              | exempt_buckets                                    |
| Done       | Yes          | 2.2.1              | None                                              |
| Done       | Yes          | 2.3.1              | exempt_rds<br>single_rds                          |
| Done       | Yes          | 2.3.2              | exempt_rds<br>single_rds                          |
| Done       | Yes          | 2.3.3              | exempt_rds<br>single_rds                          |
| Done       | Yes          | 2.4.1              | exempt_efs<br>single_efs                          |
| Done       | Yes          | 3.1                | None                                              |
| Done       | Yes          | 3.2                | None                                              |
| Done       | Yes          | 3.3                | None                                              |
| Done       | Yes          | 3.4                | None                                              |
| Done       | Yes          | 3.5                | config_delivery_channels                          |
| Done       | Yes          | 3.6                | exempt_buckets                                    |
| Done       | Yes          | 3.7                | None                                              |
| Done       | Yes          | 3.8                | exempt_kms_keys                                   |
| Done       | Yes          | 3.9                | None                                              |
| Done       | Yes          | 3.10               | single_trail                                      |
| Done       | Yes          | 3.11               | single_trail                                      |
| Done       | Yes          | 4.1                | None                                              |
| Done       | Yes          | 4.2                | None                                              |
| Done       | Yes          | 4.3                | None                                              |
| Done       | Yes          | 4.4                | None                                              |
| Done       | Yes          | 4.5                | None                                              |
| Done       | Yes          | 4.6                | None                                              |
| Done       | Yes          | 4.7                | None                                              |
| Done       | Yes          | 4.8                | None                                              |
| Done       | Yes          | 4.9                | None                                              |
| Done       | Yes          | 4.10               | None                                              |
| Done       | Yes          | 4.11               | None                                              |
| Done       | Yes          | 4.12               | None                                              |
| Done       | Yes          | 4.13               | None                                              |
| Done       | Yes          | 4.14               | third_party_api_monitoring_tool                   |
| Done       | Yes          | 4.15               | third_party_api_monitoring_tool                   |
| Done       | Yes          | 4.16               | exempt_regions                                    |
| No         | Yes          | 5.1                | disable_slow_controls<br>remote_management_port_ranges<br>exempt_ports<br>exempt_protocols<br>remote_management_protocols<br>exempt_acl_ids|
| Done       | Yes          | 5.2                | disable_slow_controls<br>default_aws_region<br>ignore_other_regions<br>exempt_regions<br>remote_management_port_ranges<br>exempt_ports<br>exempt_protocols<br>remote_management_protocols<br>exempt_security_groups<br>exempt_sg_patterns|
| Done       | Yes          | 5.3                |disable_slow_controls<br>default_aws_region<br>ignore_other_regions<br>exempt_regions<br>remote_management_port_ranges<br>exempt_ports<br>exempt_protocols<br>remote_management_protocols<br>exempt_security_groups<br>exempt_sg_patterns|
| Done       | Yes          | 5.4                | exempt_vpcs                                       |
| Done       | Yes          | 5.5                | exempt_routes                                     |
| Done       | Yes          | 5.6                | skip_stopped_ec2<br>exempt_ec2s                   |

### Manual Checks

Note that not all controls in the CIS Benchmarks can be done automatically. This profile will mark the output of those controls as "skipped." Be sure to manually review any skipped controls, and if desired, use the MITRE SAF CLI's [Attestation](https://saf-cli.mitre.org/#attest) feature to save your manual attestations into the same file as your automated test results.

## Generate Inputs

The repo includes a script : generate_inputs.rb to generate part of the inputs required for the profile.
The script will inspect aws regions: us-east-1, us-east-2, us-west-1, us-west-2 to generate the following input to STDOUT.

```
- config_delivery_channels
```

## Usage

```
# Set required ENV variables
$ export AWS_ACCESS_KEY_ID=key-id
$ export AWS_SECRET_ACCESS_KEY=access-key
$ export AWS_SESSION_TOKEN=session_token
$ export AWS_REGION=us-west-1

# Run the `generate_inputs.rb`
$ ruby generate_inputs.rb
# The generated inputs __must be reviewed carefully__.
# Only __valid__ channels should be placed in the inputs.yml file.
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/aws-foundations-cis-baseline/archive/master.tar.gz --target aws:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the **"runner"** host uses this profile baseline for the first time, follow these steps:

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/aws-foundations-cis-baseline
inspec archive aws-foundations-cis-baseline
inspec exec <name of generated archive> --target aws:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

For every successive run, follow these steps to always have the latest version of this baseline:

```
cd aws-foundations-cis-baseline
git pull
cd ..
inspec archive aws-foundations-cis-baseline --overwrite
inspec exec <name of generated archive> --target aws:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into **[heimdall-lite](https://heimdall-lite.mitre.org/)** for a user-interactive, graphical view of the InSpec results.

The JSON InSpec results file may also be loaded into a **[full heimdall server](https://github.com/mitre/heimdall)**, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors

- Aaron Lippold - [aaronlippold](https://github.com/aaronlippold)
- Will Dower - [wdower](https://github.com/wdower)
- Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

### Special Thanks

- Eugene Aronne - [ejaronne](https://github.com/ejaronne)

### NOTICE

© 2018-2023 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.

### NOTICE

CIS Benchmarks are published by the Center for Internet Security (CIS), see: https://www.cisecurity.org/.
