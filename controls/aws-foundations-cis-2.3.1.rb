control 'aws-foundations-cis-2.3.1' do
  title 'Ensure that encryption-at-rest is enabled for RDS Instances '
  desc "Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to
encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is
encrypted, Amazon RDS handles authentication of access and decryption of your data
transparently with a minimal impact on performance. "
  desc 'rationale',
       "Databases are likely to hold sensitive and critical data, it is highly recommended to
implement encryption in order to protect your data from unauthorized access or disclosure.
With RDS encryption enabled, the data stored on the instance's underlying storage, the
automated backups, read replicas, and snapshots, are all encrypted. "
  desc 'check',
       "**From Console:**

1. Login to the AWS Management Console and open the RDS dashboard at
https://console.aws.amazon.com/rds/
2. In the navigation pane, under RDS dashboard,
click `Databases`.
3. Select the RDS Instance that you want to examine
4. Click `Instance
Name` to see details, then click on `Configuration` tab.
5. Under Configuration Details
section, In Storage pane search for the `Encryption Enabled` Status.
6. If the current
status is set to `Disabled`, Encryption is not enabled for the selected RDS Instance database
instance.
7. Repeat steps 3 to 7 to verify encryption status of other RDS Instance in same
region.
8. Change region from the top of the navigation bar and repeat audit for other
regions.

**From Command Line:**

1. Run `describe-db-instances` command to list
all RDS Instance database names, available in the selected AWS region, Output will return
each Instance database identifier-name.
 ```
aws rds describe-db-instances --region
<region-name> --query 'DBInstances[*].DBInstanceIdentifier'
```
2. Run again
`describe-db-instances` command using the RDS Instance identifier returned earlier, to
determine if the selected database instance is encrypted, The command output should return
the encryption status `True` Or `False`.
```
aws rds describe-db-instances --region
<region-name> --db-instance-identifier <DB-Name> --query
'DBInstances[*].StorageEncrypted'
```
3. If the StorageEncrypted parameter value is
`False`, Encryption is not enabled for the selected RDS database instance.
4. Repeat steps
1 to 3 for auditing each RDS Instance and change Region to verify for other regions "
  desc 'fix',
       "**From Console:**

1. Login to the AWS Management Console and open the RDS dashboard at
https://console.aws.amazon.com/rds/.
2. In the left navigation panel, click on
`Databases`
3. Select the Database instance that needs to be encrypted.
4. Click on
`Actions` button placed at the top right and select `Take Snapshot`.
5. On the Take Snapshot
page, enter a database name of which you want to take a snapshot in the `Snapshot Name` field and
click on `Take Snapshot`.
6. Select the newly created snapshot and click on the `Action`
button placed at the top right and select `Copy snapshot` from the Action menu.
7. On the Make
Copy of DB Snapshot page, perform the following:

- In the New DB Snapshot Identifier
field, Enter a name for the `new snapshot`.
- Check `Copy Tags`, New snapshot must have the
same tags as the source snapshot.
- Select `Yes` from the `Enable Encryption` dropdown list
to enable encryption, You can choose to use the AWS default encryption key or custom key from
Master Key dropdown list.

8. Click `Copy Snapshot` to create an encrypted copy of the
selected instance snapshot.
9. Select the new Snapshot Encrypted Copy and click on the
`Action` button placed at the top right and select `Restore Snapshot` button from the Action
menu, This will restore the encrypted snapshot to a new database instance.
10. On the
Restore DB Instance page, enter a unique name for the new database instance in the DB Instance
Identifier field.
11. Review the instance configuration details and click `Restore DB
Instance`.
12. As the new instance provisioning process is completed can update
application configuration to refer to the endpoint of the new Encrypted database instance
Once the database endpoint is changed at the application level, can remove the unencrypted
instance.

**From Command Line:**

1. Run `describe-db-instances` command to list
all RDS database names available in the selected AWS region, The command output should return
the database instance identifier.
```
aws rds describe-db-instances --region
<region-name> --query 'DBInstances[*].DBInstanceIdentifier'
```
2. Run
`create-db-snapshot` command to create a snapshot for the selected database instance, The
command output will return the `new snapshot` with name DB Snapshot Name.
```
aws rds
create-db-snapshot --region <region-name> --db-snapshot-identifier
<DB-Snapshot-Name> --db-instance-identifier <DB-Name>
```
3. Now run
`list-aliases` command to list the KMS keys aliases available in a specified region, The
command output should return each `key alias currently available`. For our RDS encryption
activation process, locate the ID of the AWS default KMS key.
```
aws kms list-aliases
--region <region-name>
```
4. Run `copy-db-snapshot` command using the default KMS key
ID for RDS instances returned earlier to create an encrypted copy of the database instance
snapshot, The command output will return the `encrypted instance snapshot
configuration`.
```
aws rds copy-db-snapshot --region <region-name>
--source-db-snapshot-identifier <DB-Snapshot-Name>
--target-db-snapshot-identifier <DB-Snapshot-Name-Encrypted> --copy-tags
--kms-key-id <KMS-ID-For-RDS>
```
5. Run `restore-db-instance-from-db-snapshot`
command to restore the encrypted snapshot created at the previous step to a new database
instance, If successful, the command output should return the new encrypted database
instance configuration.
```
aws rds restore-db-instance-from-db-snapshot --region
<region-name> --db-instance-identifier <DB-Name-Encrypted>
--db-snapshot-identifier <DB-Snapshot-Name-Encrypted>
```
6. Run
`describe-db-instances` command to list all RDS database names, available in the selected
AWS region, Output will return database instance identifier name Select encrypted database
name that we just created DB-Name-Encrypted.
```
aws rds describe-db-instances
--region <region-name> --query 'DBInstances[*].DBInstanceIdentifier'
```
7. Run
again `describe-db-instances` command using the RDS instance identifier returned
earlier, to determine if the selected database instance is encrypted, The command output
should return the encryption status `True`.
```
aws rds describe-db-instances
--region <region-name> --db-instance-identifier <DB-Name-Encrypted> --query
'DBInstances[*].StorageEncrypted'
``` "
  impact 0.5
  ref 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html:https://aws.amazon.com/blogs/database/selecting-the-right-encryption-options-for-amazon-rds-and-amazon-aurora-database-engines/#:~:text=With%20RDS%2Dencrypted%20resources%2C%20data'
  ref 'https://aws.amazon.com/rds/features/security/'
  tag nist: %w{SC-28 SC-28(1)}
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['3.11'] }]

  exempt_rds = input('exempt_rds')
  failing_rds = []
  
  only_applicable_if('This control is Non Applicable since no unexempt RDS instances were found.') { !aws_rds_instances.entries.empty? or !(exempt_rds - aws_rds_file_systems.db_instance_identifiers).empty? }

  if input('single_rds').present?
    failing_rds << input('single_rds').to_s unless aws_rds_instance(input('single_rds')).encrypted?
    describe "The #{input('single_rds')}" do
      it 'is encrypted' do
        expect(failing_rds).to be_empty, "Failing RDS:\t#{failing_rds}"
      end
    end
  else  
    failing_rds = aws_rds_instances.where { storage_encrypted != true }
    describe 'RDS instances' do
      it 'should all be encrypted' do
        failure_messsage = "Failing RDS:\n#{failing_rds.join(", \n")}"
        failure_messsage += "\nExempt RDS:\n\n#{exempt_rds.join(", \n")}" if exempt_rds.present?
        expect(failing_rds).to be_empty, failure_messsage
      end
    end
  end
end
