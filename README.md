# PL PROJECT - SDN 

## HOW TO RUN PL Command 
In order to run the `pl` command in an linux machine you can execute the following command:
``` python
pip install git+https://github.com/PL-PROJECT-20/pl-topo.git
```
Don't forget to upgarde `pip`. And also need to install Git beforehand.


## HOW TO RUN A TREE TOPOLOGY

In order to run the tree topology first need to create a `pl-tree.yml` file where there are specific names of the containers and their configurations. By default, we have 3 kinds of images of containers:
  1. sw-1, sw-2 : These are the ovs-switches. `sw-1` is considered as the core switch of the tree topology and has direct connection to the 'GATEWAY'.
  2. ctr: is the SDN controller with an image() including "ryu".
  3. usr-1,usr-2 : These are the hosts which contain basic ubuntu image with `nping` traffic generator.
 You can also generate this "pl-tree.yml" file from the setup.py file


cmd to run `pl-tree.yml`-
``` bash
$> cd /home/shenyao1/TOPO/pritom_liz/All_Topology

$> pl --create PL-tree.yml # don't need to add sudo here
```

### PL Help
``` bash
pl --help
usage: pl [-h] [-d] [--create | --destroy] [-s] [-a] topology
Tool to create docker topologies
positional arguments:
  topology       Topology file
optional arguments:
  -h, --help     show this help message and exit
  -d, --debug    Enable Debug
Actions:
  Create or destroy topology
  --create       Create topology
  --destroy      Destroy topology
Save:
  Save or archive the topology
  -s, --save     Save topology configs
  -a, --archive  Archive topology file and configs
```
A successful result will look like following-

![Screenshot](https://github.com/Lizeth2989/PL_SDN/blob/master/pl1.png)

### EDIT TOPOLOGY 

In case of editing the topology, you can connect a new docker container to the existing topology using the following command. It uses namespace configurations with veth links.
   
``` bash
$> sh pl_c2c.sh <container_name1> <container_name2> <veth_name_at_container1> <veth_name_at_container2>
```
The command has 4 paramaters.

  1. <container_name1>: name of the existing container of tree topology.
  2. <container_name2>: name of the new container which will be connected.
  3. <veth_name_at_container1>: name of the new interface in the existing container. 
  4. <veth_name_at_container2>: name of the new interface in the new container.
  
### SCRIPT TO CHANGE IP CONFIGURATIONS OF TOPOLOGY INTERFACES

This script adds the eth interfaces to the OVS bridge (foo) and reconfigures the IPs, netmasks, and gateways of the containers, including sw, ctr, and usr. 

`sudo` command is mandatory to run this script. This is not working with python 2.7. Python3 is mandatory.

``` bash
$> sudo python3 ovs_br_script.py -file /home/shenyao1/TOPO/pritom_liz/All_Topology/PL-tree.yml
```
A successful result will look like following-
![Screenshot](https://github.com/Lizeth2989/PL_SDN/blob/master/pl2.png)

To verify the OVS configuration, you can run the following command in "sw-X" containers.

ovs-vsctl show

### GRE CONNECTION to CONNECT ANOTHER SERVER

(In progress)

## File Description

### File: pritom_liz/2.1.0-
  -with ubuntu image 2.1.0 is running ok. But use the 2.1.4 for the latest updates
  this is based on the new_sw13 folder
  
### File: pritom_liz/2.3.0-
  -with new_sw13 image. But use the 2.4.2 for the latest updates. we also changed the supervisored.conf
  this is based on the new_sw13 folder.
  
### File: pritom_liz/2.5.0-
  -with pritom_liz:2.4.5 image.Changed the PATH of ovs scripts. Every service in ovs running fine. Use pritom_liz:2.5.1 image as latest update
  
### File: new_sw13-
  -this is the base file with ubuntu image. In case anything happes use this

### File: pritom_liz/centOS-
  -with the cent os  partially working. Need to install ovs and create the image.
  
### File: pritom_liz/PL_C2C/pl_c2c.sh -
  -This is the script for connecting two docker container of a same docker network using the veth.(currently we are not using it. But in future it will help us to connect different containers)

### File: pritom_liz/script.py-
  -This is the script to run the "pl" command. This file create the docker topology. Current version supports only binary tree tropology. 

### File: pritom_liz/All_Topology/test.yml-
  - An example that is supported by our "pl" command supports.
    - usr: is the host machines.
    -sw-1: is the Core Switch.
    -ctr: is the controller. 

### File: pritom_liz/ovs_br_script.py-
  - How to run:
    - sudo python3 ovs_br_script.py -file "All_Topology/xxx.yml"
  - This file should be executed after creating the topology. This script is to add all the containers to the controller and delete the eth0 so that the containers follow the topology we assigned. 

### File: pritom_liz/clean_up.py
  - How to run:
    - sudo python3 clean_up.py -file "All_Topology/xxx.yml"
  - This script can be used anytime once the topology has been created. It cleans the ARP, Flow and Group tables. 

### How to start controller
  - ryu-manager --observe-links controller.py

## How to create an IMAGE-

### RUN Dockerfile
sudo docker build -t="pritom_liz:2.1.3" .

### RUN the image first time

check docker image

```bash
sudo docker ps -a
sudo docker run -itd --name=pritom_liz/centos pritom_liz:2.1.3 /usr/bin/supervisord
```
### exec the image
```bash
sudo docker exec -it pritom_liz /bin/bash
```
### edit the image and commint for future update
```bash
sudo docker commit 99583457a8b2 pritom_liz:2.1.4
```
### IMAGE DESCRIPTION: 
  -pritom_liz:2.2.0 has the ryu controller installed
  
  -ovs-sw:latest   this image is with (new_sw13+ryu) just a checkpoint
  
  -pritom_liz:2.2.1 has the ryu controller installed + nping traffic generator
  
  -pritom_liz_centos:1.0.2 CentOS image + ovs (with supervisored)
  
  -usr:1.1.1 user ubuntu image ifconfig + nping
  
  -usr:1.1.2 user ubuntu image ifconfig+ping+iperf
  
  -usr:1.1.3 user ubuntu image ifconfig+ping+iperf+ arp table command
  
  -ryu_ovs:2.1.0 has ryu and ovs installed and it is a bit optimized. but the ovsdb is not running yet
  
  -covs:1.0.0 make it default image. it has ovs and ryu controller and it is optimized.
  
  -pritom_liz:2.5.1 has the ryu controller installed_ ovs services are running
  
  -tovs:1.1.2 has ovs and supervisord. It came from 1.1.1 and then 1.1.0. Can be used in topology.
  
  -tovs_ryu:1.1.0 has ovs and ryu. No supervisord installed
  
  -tovs_ryu:1.1.2 has been executed. Can be used as ctr in the topology. No supervisord here. Came from tovs_ryu:1.1.1
  
  -tovs_ryu:1.1.3 is the lastes came from the tovs_ryu:1.1.2. It a qos_simple_switch_13.py in the usr/local/lib/python2.7/dist-packages/ryu/app folder. 
