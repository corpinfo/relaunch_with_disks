#!/usr/bin/env python

###############################################################################
## relaunch_keep_disks.py
## This will move a host from one subnet to another. It'll do the following:
## 1. create an identical EC2 instance in the destination subnet
## 2. delete the disk that booted with this new host
## 3. detach the disks from the source
## 4. attach the disks to the destination host
## 5. boot the destination
## 6. terminate the source
##
## Notable:
## - the -s/--source-id option is required. all others are optional
##   however, be smart about it. if you move across VPCs you'll need 
##   security groups too cause those are VPC specific. Most errors are pretty
##   self explanitory
## - No network adapters will move. Any ENIs will have to be reallocated.
##
## To get usage for using this script, get the full help:
## python relaunch_instance_while_keeping_disks.py --help
##
## example:
## python relaunch_instance_while_keeping_disks.py --source-id i-7654345ac \
##    --subnet-id subnet-6543abba \
##    --aws-profile default \
##    --security-groups sg-abcd1234,sg-4321abba,sg-8765bbcc
##
###############################################################################

#######################
## TODO:
## need to implement updates: source_instance.sriov_net_support
#######################


import argparse
import base64
import boto3
import json
import logging
import os
import re
import sys


def initialize_logger(output_dir):
  ## silence boto
  logging.getLogger('boto3').setLevel(logging.CRITICAL)
  logging.getLogger('botocore').setLevel(logging.CRITICAL)

  l = logging.getLogger()
  l.setLevel(logging.INFO)
  formatter = logging.Formatter("[%(asctime)s] [Line:%(lineno)d] [%(levelname)s] %(message)s")

  # create console handler and set level to info
  handler = logging.StreamHandler()
  handler.setFormatter(formatter)
  l.addHandler(handler)

  # create file handler and write to file if desired
  if output_dir != None:
    output_file = os.path.splitext(os.path.basename(__file__))[0] + ".log"
    handler = logging.FileHandler(os.path.join(output_dir, output_file),"w", encoding=None, delay="true")
    handler.setFormatter(formatter)
    l.addHandler(handler)

  return l


def parse_opts():
    """Help messages (-h, --help)"""

    ## set what will be the default in opts['aws_profile']
    try:
      aws_profile = os.environ['AWS_DEFAULT_PROFILE']
    except Exception, e:
      aws_profile = "default"

    parser = argparse.ArgumentParser()
    parser.add_argument('-s','--source-id', type=str, required=True, help='REQUIRED: Source instance id (i-xxxxxxxx or i-xxxxxxxxxxxxxxxxx')
    parser.add_argument('-a','--image-id', type=str, default=None, help='Destination image id aka AMI (ami-xxxxxxxx)')
    parser.add_argument('-b','--subnet-id', type=str, default=None, help='Destination subnet id (subnet-xxxxxxxx)')
    parser.add_argument('-c','--dedicated-host', type=str, default=None, help='Place destination on a dedicated host (h-xxxxxxxxxxxxxxxxx)')
    parser.add_argument('-e','--ebs-optimized', type=bool, default=None, help='EBS Optimized setting (true or false)')
    parser.add_argument('-g','--security-groups', type=str, default=None, help='Destination Security Groups, comma separated (sg-xxxxxxxx,sg-yyyyyyyy,sg-zzzzzzzz')
    parser.add_argument('-i','--ip-address', type=str, default=None, help='IP Address OR ENI name (192.168.2.14 or eni-xxxxxxxx')
    parser.add_argument('-k','--key-name', type=str, default=None, help='Destination instance key name (my-keyname)')
    parser.add_argument('-m','--monitoring', type=bool, default=None, help='Detailed monitoring on/off for destination instance (true or false)')
    parser.add_argument('-n','--kernel-id', type=str, default=None, help='Destination instance kernel id')
    parser.add_argument('-o','--iam_role', type=str, default=None, help='Destination instance IAM Role as Name or ARN (MyEC2Role or arn:aws:iam::xxxxxxxxxxxx:role/MyEC2Role')
    parser.add_argument('-p','--aws-profile', type=str, default=aws_profile, help='AWS Profile to use. This overrides AWS_DEFAULT_PROFILE environment variable')
    parser.add_argument('-r','--ramdisk', type=str, default=None, help='Destination instance ramdisk id')
    parser.add_argument('-t','--instance-type', type=str, default=None, help='Destination instance type (t2.micro, m4.xlarge, etc)')
    parser.add_argument('-u','--userdata-file', type=str, default=None, help='Path to file to use as userdata (c:/users/myuser/userdata.txt or /Users/myuser/userdata.sh)')
    parser.add_argument('--ip-address-public', dest='ip_address_public', action='store_true', help='If setting an IP with -i you can add this flag to make the new ENI assign a public IP')
    parser.add_argument('--skip-termination', dest='skip_termination', action='store_true', help='Set this flag if you want to skip terminating the source instance')

    return vars(parser.parse_args())



if __name__ == '__main__':
  l = initialize_logger(None)
  opts = parse_opts()
  if not re.search('^i-([a-f0-9]{8}|[a-f0-9]{17})$', opts['source_id'], re.IGNORECASE):
    l.critical("Source instance id supplied doesnt match known instance id format")
    os.system("python " + __file__ + " --help")
    sys.exit(1)

  if len(sys.argv) < 3:
    l.critical("You must supply --source-id and one other option")
    sys.exit(2)

  ## infomration on which profile we're actually using
  l.info("Using AWS Profile: %s" % opts['aws_profile'])

  try:
    session = boto3.session.Session(profile_name=opts['aws_profile'])
    ec2 = session.resource('ec2')
    ec2client = session.client('ec2')
  except botocore.exceptions.ProfileNotFound, e:
    l.critical("AWS Profile not found. Please run: aws configure --profile %s" % opts['aws_profile'])
    sys.exit(3)



  ## 1. create an identical EC2 instance in the destination subnet
  source_instance = ec2.Instance(opts['source_id'])

  ## make sure they're in the same AZ
  if opts['subnet_id'] != None and ec2.Subnet(source_instance.subnet_id).availability_zone != ec2.Subnet(opts['subnet_id']).availability_zone:
    l.critical("Source instance and destination subnet are not in the same AZ. Please make sure they're both in the same AZ.")
    sys.exit(4)

  ## notify it needs to be stopp(ed|ing)
  if source_instance.state['Name'].lower() not in ["stopped","stopping"]:
    l.warning("Source instance is not stopped/stopping. Please stop it (or get it into a 'stopping' state) before running this script.")
    try:
      raw_input("Please press any to continue or press ctrl+c to exit the script without creating any new artifacts. This script will wait for it to stop if you have it in a stopping state.")
    except KeyboardInterrupt:
      sys.exit(0)


  ## this gets used later on, but we'll save it here
  source_instance_nametag = (tag for tag in source_instance.tags if tag['Key'] == "Name").next()['Value'].lower().strip()


  ## set up destination instance. These first handful of options dont require much logic to implement 
  ## or will be defaulted here and then overwritten further down
  destination_instance_options = {}
  destination_instance_options['DisableApiTermination'] = source_instance.describe_attribute(Attribute='disableApiTermination')['DisableApiTermination']['Value']
  destination_instance_options['EbsOptimized'] = source_instance.ebs_optimized
  destination_instance_options['ImageId'] = source_instance.image_id
  destination_instance_options['InstanceInitiatedShutdownBehavior'] = source_instance.describe_attribute(Attribute='instanceInitiatedShutdownBehavior')['InstanceInitiatedShutdownBehavior']['Value']
  destination_instance_options['InstanceType'] = source_instance.instance_type
  destination_instance_options['MaxCount'] = 1
  destination_instance_options['MinCount'] = 1
  destination_instance_options['Placement'] = source_instance.placement
  destination_instance_options['SecurityGroupIds'] = [sgobject['GroupId'] for sgobject in source_instance.security_groups]
  destination_instance_options['SubnetId'] = source_instance.subnet_id

  ## add IAM role but only include it if we have cmd line or existing isnt None. 
  ## cmd line takes precedence over existing
  if source_instance.iam_instance_profile != None:
    destination_instance_options['IamInstanceProfile'] = {"Arn": source_instance.iam_instance_profile['Arn']}
  if opts['iam_role'] != None:
    if opts['iam_role'].startswith("arn:aws:iam"):
      destination_instance_options['IamInstanceProfile'] = {"Arn": opts['iam_role']}
    else:
      destination_instance_options['IamInstanceProfile'] = {"Name": opts['iam_role']}


  ## override existing image id if required
  if opts['instance_type'] != None:
    destination_instance_options['InstanceType'] = opts['instance_type']


  ## override existing image id if required
  if opts['image_id'] != None:
    destination_instance_options['ImageId'] = opts['image_id']


  ## add key name but only include it if we have cmd line or existing isnt None. 
  ## cmd line takes precedence over existing
  if source_instance.key_name != None:
    destination_instance_options['KeyName'] = source_instance.key_name
  if opts['key_name'] != None:
    destination_instance_options['KeyName'] = opts['key_name']


  ## add kernel but only include it if we have cmd line or existing 
  ## cmd line takes precedence over existing
  if 'Value' in source_instance.describe_attribute(Attribute='kernel')['KernelId']:
    destination_instance_options['KernelId'] = source_instance.describe_attribute(Attribute='kernel')['KernelId']['Value']
  if opts['kernel_id'] != None:
    destination_instance_options['KernelId'] = opts['kernel_id']


  ## add ramdisk but only include it if we have cmd line or existing 
  ## cmd line takes precedence over existing
  if 'Value' in source_instance.describe_attribute(Attribute='ramdisk')['RamdiskId']:
    destination_instance_options['RamdiskId'] = source_instance.describe_attribute(Attribute='ramdisk')['RamdiskId']['Value']
  if opts['ramdisk'] != None:
    destination_instance_options['RamdiskId'] = opts['ramdisk']


  ## EBS Optimized cmd line override
  if opts['ebs_optimized'] != None:
    destination_instance_options['EbsOptimized'] = opts['ebs_optimized']


  ## add monitoring but only include it if we have cmd line or existing 
  ## cmd line takes precedence over existing
  if source_instance.monitoring['State'] == 'enabled':
    destination_instance_options['Monitoring'] = {"Enabled": True}
  else:
    destination_instance_options['Monitoring'] = {"Enabled": False}

  if opts['monitoring'] != None:
    destination_instance_options['Monitoring'] = {"Enabled": opts['monitoring']}


  ## override security groups from cmd line options if exists
  if opts['security_groups'] != None:
    destination_instance_options['SecurityGroupIds'] = opts['security_groups'].split(',')


  ## override subnet from cmd line options if exists
  if opts['subnet_id'] != None:
    destination_instance_options['SubnetId'] = opts['subnet_id']


  ## add userdata but only include it if we have cmd line or existing 
  ## override userdata from cmd line options if exists
  if 'Value' in source_instance.describe_attribute(Attribute='userData')['UserData']:
    destination_instance_options['UserData'] = base64.b64decode(source_instance.describe_attribute(Attribute='userData')['UserData']['Value'])
  if opts['userdata_file'] != None:
    try:
      destination_instance_options['UserData'] = open(opts['userdata_file'], 'r').read()
    except Exception, e:
      log.critical("There's a problem with userdata_file:")
      log.critical(str(e))
      sys.exit(5)


  ## set ENI or IP. If we're setting this, we need to move a couple options around
  if opts['ip_address'] != None:
    ## create the object with DeviceIndex=0 ... this is always set for either eni or ip address
    my_network_object = {}
    my_network_object['DeviceIndex'] = 0

    ## if we use eni, just set it for networkinterfaceid
    if opts['ip_address'].startswith('eni-'):
      my_network_object['NetworkInterfaceId'] = opts['ip_address']
    else:
      my_network_object['Groups'] = destination_instance_options['SecurityGroupIds']
      my_network_object['PrivateIpAddress'] = opts['ip_address']
      my_network_object['SubnetId'] = destination_instance_options['SubnetId']
      my_network_object['AssociatePublicIpAddress'] = opts['ip_address_public']

      ## now remove the 2 things we cant have in the 'main' options for launching an instance:
      del destination_instance_options['SecurityGroupIds']
      del destination_instance_options['SubnetId']

    ## set the options with the proper objeect
    destination_instance_options['NetworkInterfaces'] = [my_network_object]


  ## override dedicated host from cmd line options
  if opts['dedicated_host'] != None and opts['dedicated_host'].startswith('h-'):
    destination_instance_options['Placement'] = {
      "HostId": opts['dedicated_host']
    }



  l.info("Starting destination instance")
  try:
    new_instance_data = ec2client.run_instances(**destination_instance_options)
  except Exception, e:
    l.critical("Problem starting the destination instance. No changes were made.")
    l.critical("Here's the error:")
    l.critical(str(e))
    sys.exit(6)

  destination_instance = ec2.Instance(new_instance_data['Instances'][0]['InstanceId'])
  l.info("Waiting for destination instance [%s] to start" % destination_instance.instance_id)
  destination_instance.wait_until_exists()

  ## now that it exists, tag it and update these
  destination_instance.create_tags(Tags=source_instance.tags)
  destination_instance.modify_attribute(Attribute='sourceDestCheck', Value=str(source_instance.source_dest_check))
  # if source_instance.sriov_net_support != None:
  #   destination_instance.modify_attribute(Attribute='sriovNetSupport', Value=str(source_instance.sriov_net_support))

  destination_instance.wait_until_running()
  destination_instance.stop()
  l.info("Waiting for destination instance [%s] to stop" % destination_instance.instance_id)
  destination_instance.wait_until_stopped()


  ## 2. delete the disk that booted with the destination host
  for dest_vol in destination_instance.volumes.all():
    l.info("Detaching initial volume [%s] from destination instance" % dest_vol.volume_id)
    dest_vol.detach_from_instance(InstanceId=destination_instance.instance_id, Force=True)
    ec2client.get_waiter('volume_available').wait(VolumeIds=[dest_vol.volume_id])
    l.info("Deleting initial volume [%s] from destination instance" % dest_vol.volume_id)
    dest_vol.delete()


  ## make sure source is stopped
  l.info("Waiting for source instance [%s] to stop" % source_instance.instance_id)
  source_instance.wait_until_stopped()

  ## 3. detach the disks from the source
  source_volumes = {}
  for source_vol in source_instance.volumes.all():
    l.info("Detaching volume [%s] from source instance" % source_vol.volume_id)

    ## save info about the volid and the existing mapping. and tag the name of the volume
    source_volumes[source_vol.volume_id] = source_vol.attachments[0]['Device']
    source_vol.create_tags(Tags=[{"Key":"Name","Value":source_instance_nametag+":"+source_vol.attachments[0]['Device']}])

    ## now detach
    source_vol.detach_from_instance(InstanceId=source_instance.instance_id)
    ec2client.get_waiter('volume_available').wait(VolumeIds=[source_vol.volume_id])


  ## 4. attach the disks to the destination host
  attaching_volumes = []
  for source_vol_id in source_volumes:
    l.info("Attaching source volume [%s] to destination instance" % source_vol_id)
    ec2.Volume(source_vol_id).attach_to_instance(InstanceId=destination_instance.instance_id, Device=source_volumes[source_vol_id])
    attaching_volumes.append(source_vol_id)

  l.info("Waiting for all volumes to be attached %s" % attaching_volumes)
  ec2client.get_waiter('volume_in_use').wait(VolumeIds=attaching_volumes)


  ## 5. boot the destination
  l.info("Booting destination instance [%s]" % destination_instance.instance_id)
  destination_instance.start()


  ## 6. terminate the source
  if not opts['skip_termination']:
    l.info("Terminating source instance [%s]" % source_instance.instance_id)
    try:
      source_instance.terminate()
    except Exception, e:
      l.warning("Could not terminate source instance. Please terminate id: %s" % source_instance.instance_id)