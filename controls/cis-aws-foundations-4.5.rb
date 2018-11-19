control 'cis-aws-foundations-4.5' do
  title "Ensure routing tables for VPC peering are 'least access'"
  desc  "Once a VPC peering connection is estalished, routing tables must be
updated to establish any connections between the peered VPCs. These routes can
be as specific as desired - even peering a VPC to only a single host on the
other side of the connection."
  impact 0.7
  tag "rationale": "Being highly selective in peering routing tables is a very
effective way of minimizing the impact of breach as resources outside of these
routes are inaccessible to the peered VPC."
  tag "cis_impact": ''
  tag "cis_rid": '4.5'
  tag "cis_level": 2
  tag "csc_control": ''
  tag "nist": ['SC-7', 'Rev_4']
  tag "cce_id": ''
  tag "check": "Review routing tables of peered VPCs for whether they route all
subnets of each VPC and whether that is necessary to accomplish the intended
purposes for peering the VPCs.

'Via CLI:

* List all the route tables from a VPC and check if 'GatewayId' is pointing to
a _<peering_connection_id>_ (e.g. pcx-1a2b3c4d) and if 'DestinationCidrBlock'
is as specific as desired.

'aws ec2 describe-route-tables --filter 'Name=vpc-id,Values=_<vpc_id>_' --query
'RouteTables[*].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes,
AssociatedSubnets:Associations[*].SubnetId}'"
  tag "fix": "Remove and add route table entries to ensure that the least
number of subnets or hosts as is required to accomplish the purpose for peering
are routable.

'Via CLI:

* For each _<route_table_id> _containing routes non compliant with your routing
policy (which grants more than desired 'least access'), delete the non
compliant route:

'aws ec2 delete-route --route-table-id _<route_table_id>_
--destination-cidr-block _<non_compliant_destination_CIDR>_

' 2. Create a new compliant route:

'aws ec2 create-route --route-table-id _<route_table_id>_
--destination-cidr-block _<compliant_destination_CIDR>_
--vpc-peering-connection-id _<peering_connection_id>_"

  aws_route_tables.route_table_ids.each do |route_table_id|
    aws_route_table(route_table_id).routes.each do |route|
      next unless route.key?(:vpc_peering_connection_id)

      describe route do
        its([:destination_cidr_block]) { should_not be nil }
      end
    end
    next unless aws_route_table(route_table_id).routes.none? { |route| route.key?(:vpc_peering_connection_id) }

    describe 'No routes with peering connection were found for the route table' do
      skip "No routes with peering connection were found for the route_table #{route_table_id}"
    end
  end
  if aws_route_tables.route_table_ids.empty?
    describe 'Control skipped because no route tables were found' do
      skip 'This control is skipped since the aws_route_tables resource returned an empty route table list'
    end
  end
end
