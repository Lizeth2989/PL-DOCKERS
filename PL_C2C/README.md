# Add *veth* to your Docker container in one step
Let me introduce you an ultimate BASH script for easily extend a running Docker container with a new veth interface.


`$ cd PL_C2C`

## Usage
`$ sh pl_c2c.sh <container_name1> <container_name2> <veth_name_at_container1> <veth_name_at_container2>`

## Note
`<container_name>` is not the image name, as you can have multiple containers running the same image. If you do not provide any name for your running container during the init phase, Docker automatically assigns one to it.

To specify an own name to your container use `--name <my_container>` argument when starting the container.

If your container is already running, you can distille the output of `docker ps` command to figure out what is the name of the corresponding container.

## What it does
- checks whether the veth pair and the container you want to connect the veth pair to is up and running
- binds a pointer to the container's namespace in the root namespace to enable the usage of `ip netns`
- creates a veth pair with the required names and binds the latter end of it to the container
- brings up each end of the veth pair that becomes ready to use immediately
- cleans up the mess in case of an error during the process

## What it denitiely does not do
- pre-installs any requirements (e.g., net-tools, docker)
- boots up your container
- do any further things with freshly made interfaces (e.g., connect to internet/hypervisor switch)

## Example output
```
$ sudo ./add_veth2container.sh admiring_mahavira veth_root veth_container
Checking whether container admiring_mahavira is running...[OK]
admiring_mahavira is found and up and running

Getting PID of the running container admiring_mahavira: [OK] (24617)

Creating /var/run/netns/ directory...[OK]

Create a symlink admiring_mahavira in /var/run/netns/ pointing to /proc/24617/ns/net...[OK]

Create veth pair veth_root -- veth_container...[OK]

Bringing up veth_container...
[OK]

Bringing up veth_root...
[OK]

Add veth_container to container admiring_mahavira...[OK]

Bring up manually the interface in the container as well...[OK]
```
