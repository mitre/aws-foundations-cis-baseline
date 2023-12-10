for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); 
  do for port in 22 3389; 
    do for groupId in $(aws ec2 describe-security-groups --region "$region" --filters Name=ip-permission.from-port,Values=$port Name=ip-permission.to-port,Values=$port --query 'SecurityGroups[?((IpPermissions.IpRanges.CidrIp == "0.0.0.0/0") || (IpPermissions.Ipv6Ranges.CidrIpv6 == "::/0"))].[GroupId]' --output text); 
      do echo "Region: $region Port: $port GroupId: $groupId"; 
    done; 
  done; 
done
