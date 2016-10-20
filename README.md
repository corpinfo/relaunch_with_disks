# relaunch_keep_disks.py

 This will move a host from one subnet to another. It'll do the following:
 1. create an identical EC2 instance in the destination subnet
 2. delete the disk that booted with this new host
 3. detach the disks from the source
 4. attach the disks to the destination host
 5. boot the destination
 6. terminate the source

 ## Notable:
 - the -s/--source-id option is required. all others are optional
   however, be smart about it. if you move across VPCs you'll need 
   security groups too cause those are VPC specific. Most errors are pretty
   self explanitory
 - No network adapters will move. Any ENIs will have to be reallocated.

 To get usage for using this script, get the full help:
 python relaunch_instance_while_keeping_disks.py --help

 ## example:
 python relaunch_instance_while_keeping_disks.py --source-id i-7654345ac \
    --subnet-id subnet-6543abba \
    --aws-profile default \
    --security-groups sg-abcd1234,sg-4321abba,sg-8765bbcc