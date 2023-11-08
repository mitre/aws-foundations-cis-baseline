# encoding: UTF-8

control "aws-foundations-cis-5.5" do
  title "Ensure routing tables for VPC peering are \"least access\" "
  desc "Once a VPC peering connection is established, routing tables must be updated to establish any 
connections between the peered VPCs. These routes can be as specific as desired - even peering 
a VPC to only a single host on the other side of the connection. "
  desc "rationale", "Being highly selective in peering routing tables is a very effective way of minimizing the 
impact of breach as resources outside of these routes are inaccessible to the peered VPC. "
  desc "check", "Review routing tables of peered VPCs for whether they route all subnets of each VPC and whether 
that is necessary to accomplish the intended purposes for peering the VPCs.

**From 
Command Line:**

1. List all the route tables from a VPC and check if \"GatewayId\" is 
pointing to a _<peering\\_connection\\_id>_ (e.g. pcx-1a2b3c4d) and if 
\"DestinationCidrBlock\" is as specific as desired.
```
aws ec2 describe-route-tables 
--filter \"Name=vpc-id,Values=<vpc_id>\" --query 
\"RouteTables[*].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes, 
AssociatedSubnets:Associations[*].SubnetId}\"
``` "
  desc "fix", "Remove and add route table entries to ensure that the least number of subnets or hosts as is 
required to accomplish the purpose for peering are routable.

**From Command 
Line:**

1. For each _<route\\_table\\_id>_ containing routes non compliant with your 
routing policy (which grants more than desired \"least access\"), delete the non compliant 
route:
```
aws ec2 delete-route --route-table-id <route_table_id> 
--destination-cidr-block <non_compliant_destination_CIDR>
```
 2. Create a new 
compliant route:
```
aws ec2 create-route --route-table-id <route_table_id> 
--destination-cidr-block <compliant_destination_CIDR> --vpc-peering-connection-id 
<peering_connection_id>
``` "
  desc "additional_information", "If an organization has AWS transit gateway implemented in their VPC architecture they should 
look to apply the recommendation above for \"least access\" routing architecture at the AWS 
transit gateway level in combination with what must be implemented at the standard VPC route 
table. More specifically, to route traffic between two or more VPCs via a transit gateway VPCs 
must have an attachment to a transit gateway route table as well as a route, therefore to avoid 
routing traffic between VPCs an attachment to the transit gateway route table should only be 
added where there is an intention to route traffic between the VPCs. As transit gateways are 
able to host multiple route tables it is possible to group VPCs by attaching them to a common 
route table. "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonVPC/latest/PeeringGuide/peering-configurations-partial-access.html:https://docs.aws.amazon.com/cli/latest/reference/ec2/create-vpc-peering-connection.html'
  tag nist: []
  tag severity: "medium "
end