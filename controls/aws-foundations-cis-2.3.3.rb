control 'aws-foundations-cis-2.3.3' do
  title 'Ensure that public access is not given to RDS Instance '
  desc "Ensure and verify that RDS database instances provisioned in your AWS account do restrict
unauthorized access in order to minimize security risks. To restrict access to any publicly
accessible RDS database instance, you must disable the database Publicly Accessible flag
and update the VPC security group associated with the instance. "
  desc 'rationale',
       "Ensure that no public-facing RDS database instances are provisioned in your AWS account and
restrict unauthorized access in order to minimize security risks. When the RDS instance
allows unrestricted access (0.0.0.0/0), everyone and everything on the Internet can
establish a connection to your database and this can increase the opportunity for malicious
activities such as brute force attacks, PostgreSQL injections, or DoS/DDoS attacks. "
  desc 'check',
       "**From Console:**

1. Log in to the AWS management console and navigate to the RDS
dashboard at https://console.aws.amazon.com/rds/.
2. Under the navigation panel, On
RDS Dashboard, click `Databases`.
3. Select the RDS instance that you want to examine.
4.
Click `Instance Name` from the dashboard, Under `Connectivity and Security.
5. On the
`Security`, check if the Publicly Accessible flag status is set to `Yes`, follow the
below-mentioned steps to check database subnet access.
- In the `networking` section,
click the subnet link available under `Subnets`
- The link will redirect you to the VPC
Subnets page.
- Select the subnet listed on the page and click the `Route Table` tab from the
dashboard bottom panel. If the route table contains any entries with the destination `CIDR
block set to 0.0.0.0/0` and with an `Internet Gateway` attached.
- The selected RDS
database instance was provisioned inside a public subnet, therefore is not running within a
logically isolated environment and can be accessible from the Internet.
6. Repeat steps
no. 4 and 5 to determine the type (public or private) and subnet for other RDS database
instances provisioned in the current region.
8. Change the AWS region from the navigation
bar and repeat the audit process for other regions.

**From Command Line:**

1. Run
`describe-db-instances` command to list all RDS database names, available in the selected
AWS region:
```
aws rds describe-db-instances --region <region-name> --query
'DBInstances[*].DBInstanceIdentifier'
```
2. The command output should return each
database instance `identifier`.
3. Run again `describe-db-instances` command using the
`PubliclyAccessible` parameter as query filter to reveal the database instance Publicly
Accessible flag status:
```
aws rds describe-db-instances --region <region-name>
--db-instance-identifier <db-instance-name> --query
'DBInstances[*].PubliclyAccessible'
```
4. Check for the Publicly Accessible
parameter status, If the Publicly Accessible flag is set to `Yes`. Then selected RDS database
instance is publicly accessible and insecure, follow the below-mentioned steps to check
database subnet access
5. Run again `describe-db-instances` command using the RDS
database instance identifier that you want to check and appropriate filtering to describe
the VPC subnet(s) associated with the selected instance:
```
aws rds
describe-db-instances --region <region-name> --db-instance-identifier <db-name>
--query 'DBInstances[*].DBSubnetGroup.Subnets[]'
```
- The command output should
list the subnets available in the selected database subnet group.
6. Run
`describe-route-tables` command using the ID of the subnet returned at the previous step to
describe the routes of the VPC route table associated with the selected subnet:
```
aws
ec2 describe-route-tables --region <region-name> --filters
\"Name=association.subnet-id,Values=<SubnetID>\" --query
'RouteTables[*].Routes[]'
```
- If the command returns the route table associated with
database instance subnet ID. Check the `GatewayId` and `DestinationCidrBlock` attributes
values returned in the output. If the route table contains any entries with the `GatewayId`
value set to `igw-xxxxxxxx` and the `DestinationCidrBlock` value set to `0.0.0.0/0`, the
selected RDS database instance was provisioned inside a public subnet.
- Or
- If the
command returns empty results, the route table is implicitly associated with subnet,
therefore the audit process continues with the next step
7. Run again
`describe-db-instances` command using the RDS database instance identifier that you want
to check and appropriate filtering to describe the VPC ID associated with the selected
instance:
```
aws rds describe-db-instances --region <region-name>
--db-instance-identifier <db-name> --query
'DBInstances[*].DBSubnetGroup.VpcId'
```
- The command output should show the VPC ID
in the selected database subnet group
8. Now run `describe-route-tables` command using
the ID of the VPC returned at the previous step to describe the routes of the VPC main route table
implicitly associated with the selected subnet:
```
aws ec2 describe-route-tables
--region <region-name> --filters \"Name=vpc-id,Values=<VPC-ID>\"
\"Name=association.main,Values=true\" --query 'RouteTables[*].Routes[]'
```
- The
command output returns the VPC main route table implicitly associated with database
instance subnet ID. Check the `GatewayId` and `DestinationCidrBlock` attributes values
returned in the output. If the route table contains any entries with the `GatewayId` value set
to `igw-xxxxxxxx` and the `DestinationCidrBlock` value set to `0.0.0.0/0`, the selected
RDS database instance was provisioned inside a public subnet, therefore is not running
within a logically isolated environment and does not adhere to AWS security best practices. "
  desc 'fix',
       "**From Console:**

1. Log in to the AWS management console and navigate to the RDS
dashboard at https://console.aws.amazon.com/rds/.
2. Under the navigation panel, On
RDS Dashboard, click `Databases`.
3. Select the RDS instance that you want to update.
4.
Click `Modify` from the dashboard top menu.
5. On the Modify DB Instance panel, under the
`Connectivity` section, click on `Additional connectivity configuration` and update the
value for `Publicly Accessible` to Not publicly accessible to restrict public access.
Follow the below steps to update subnet configurations:
- Select the `Connectivity and
security` tab, and click on the VPC attribute value inside the `Networking` section.
-
Select the `Details` tab from the VPC dashboard bottom panel and click on Route table
configuration attribute value.
- On the Route table details page, select the Routes tab
from the dashboard bottom panel and click on `Edit routes`.
- On the Edit routes page, update
the Destination of Target which is set to `igw-xxxxx` and click on `Save` routes.
6. On the
Modify DB Instance panel Click on `Continue` and In the Scheduling of modifications section,
perform one of the following actions based on your requirements:
- Select Apply during the
next scheduled maintenance window to apply the changes automatically during the next
scheduled maintenance window.
- Select Apply immediately to apply the changes right away.
With this option, any pending modifications will be asynchronously applied as soon as
possible, regardless of the maintenance window setting for this RDS database instance. Note
that any changes available in the pending modifications queue are also applied. If any of the
pending modifications require downtime, choosing this option can cause unexpected
downtime for the application.
7. Repeat steps 3 to 6 for each RDS instance available in the
current region.
8. Change the AWS region from the navigation bar to repeat the process for
other regions.

**From Command Line:**

1. Run `describe-db-instances` command to
list all RDS database names identifiers, available in the selected AWS region:
```
aws
rds describe-db-instances --region <region-name> --query
'DBInstances[*].DBInstanceIdentifier'
```
2. The command output should return each
database instance identifier.
3. Run `modify-db-instance` command to modify the
selected RDS instance configuration. Then use the following command to disable the
`Publicly Accessible` flag for the selected RDS instances. This command use the
apply-immediately flag. If you want `to avoid any downtime --no-apply-immediately flag can
be used`:
```
aws rds modify-db-instance --region <region-name>
--db-instance-identifier <db-name> --no-publicly-accessible
--apply-immediately
```
4. The command output should reveal the `PubliclyAccessible`
configuration under pending values and should get applied at the specified time.
5.
Updating the Internet Gateway Destination via AWS CLI is not currently supported To update
information about Internet Gateway use the AWS Console Procedure.
6. Repeat steps 1 to 5 for
each RDS instance provisioned in the current region.
7. Change the AWS region by using the
--region filter to repeat the process for other regions. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html:https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html:https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html:https://aws.amazon.com/rds/faqs/'
  tag nist: ['AC-3']
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['3.3'] }]

  exempt_rds = input('exempt_rds')
  active_rds = aws_rds_instances.db_instance_identifiers.nil? ? [] : aws_rds_instances.db_instance_identifiers
  failing_rds = []

  only_if("This control is Non Applicable. No 'non-exempt' RDS instances were found.", impact: 0.0) { aws_rds_instances.exist? or !(exempt_rds - active_rds).empty? }

  if input('single_rds').present?
    failing_rds << input('single_rds').to_s if aws_rds_instance(input('single_rds')).public?
    describe "The #{input('single_rds')}" do
      it 'should not be public' do
        expect(failing_rds).to be_empty, "Failing RDS:\t#{failing_rds}"
      end
    end
  else
    failing_rds = aws_rds_instances.where { publicly_accessible == true }.db_instance_identifiers - exempt_rds
    describe 'RDS instances' do
      it 'should all not be public' do
        failure_messsage = "Failing RDS:\n#{failing_rds.join(", \n")}"
        failure_messsage += "\nExempt RDS:\n\n#{exempt_rds.join(", \n")}" if exempt_rds.present?
        expect(failing_rds).to be_empty, failure_messsage
      end
    end
  end
end
