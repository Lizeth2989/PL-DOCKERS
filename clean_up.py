#!/usr/bin/python3
import argparse
import yaml
import os
import sys
import docker
import os.path
from ipaddress import IPv4Network

parser = argparse.ArgumentParser()

parser.add_argument('-file', action='store', dest='file_name',
                    help='File name of the topology')

parser.add_argument('--version', action='version', version='LOL')

results = parser.parse_args()

try:
    t_file = os.path.join(os.getcwd(), results.file_name)
    with open(t_file, 'r') as stream:
        t_yml = yaml.safe_load(stream)
except Exceptions as e:
    print("File Location error, Give the full file path")

DOCKER = docker.from_env()
PREFIX = t_yml['PREFIX']
endpoints = t_yml['links'][0]["endpoints"]
IMAGES = []
GATEWAY = t_yml["GATEWAY"]
NET_MASK = str(IPv4Network(t_yml["SUBNET"]).netmask)
for i in endpoints:
    IMAGES.append(PREFIX + "_" + str(i).split(":")[0])
print("The IMAGES are: ", IMAGES)


def get_ip(container_name):
    """
    @:param: container_name is a string  and aname of the container.
    @:returns ctr_ip, ip both are string. 'crt_ip' is the IP of the controller and 'ip' is the IP of the given container

    """
    ip = os.popen(
        "sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + container_name).read()
    ctr_ip = os.popen(
        "sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + PREFIX + "_ctr").read()
    return ctr_ip, ip


def sw_1(container_name):
    print("Inside "+container_name)
    #Commands to clean up tables in OVS switches: ARP table, flow Table, and Group Table
    cmds = ["ip -s -s neigh flush all", "ovs-ofctl -O OpenFlow13 del-flows foo", "ovs-ofctl -O OpenFlow13 del-groups foo"]
    try:
        container = DOCKER.containers.get(container_name)
        for cmd in cmds:
            msg = container.exec_run(cmd)
            if msg[0] != 0:
                print("Error in executing the command: ", cmd)
    except Exception as e:
        print(e)
    print("Command executed for the container: " + container_name)

def controller_host(container_name):
    print("Inside "+container_name)
    ctr_ip, ip = get_ip(container_name)
    if 'ctr' in container_name:
      cmd = ["ip -s -s neigh flush all"]
    else:
      cmd = ["ip -s -s neigh flush all"]
    try:
        container = DOCKER.containers.get(container_name)
        for i in cmd:
            msg = container.exec_run(i)
            if msg[0] != 0:
                print("Error in executing the command: ", i)
    except Exception as e:
        print(e)
    print("Command executed for the container: " + container_name)

def all_sw(container_name):
    print("Inside "+container_name)
    #Commands to clean up tables in OVS switches: ARP table, flow Table, and Group Table
    cmd = ["ip -s -s neigh flush all", "ovs-ofctl -O OpenFlow13 del-flows foo", "ovs-ofctl -O OpenFlow13 del-groups foo"]
    try:
        container = DOCKER.containers.get(container_name)
        for i in cmd:
            msg = container.exec_run(i)
            if msg[0] != 0:
                print("Error in executing the command: ", i)
    except Exception as e:
        print(e)
    print("Command executed for the container: " + container_name)

            
def main():
    for i in IMAGES:
        if "sw-1" in i:
            sw_1(i)
            print("ARP, Flow, and Group entries have been deleted in " , i)
        elif "sw-" in i:
            all_sw(i)
            print("ARP, Flow, and Group entries have been deleted in " , i)
        elif "usr" in i:
            controller_host(i)
            print("ARP entries have been deleted in " , i)
        elif "ctr" in i:
            controller_host(i)
            print("No action for "+i)
        else:
            controller_host(i)
            print("No action for "+i)
            pass



if __name__ == '__main__':
    main()
