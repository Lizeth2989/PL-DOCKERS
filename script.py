'''
usage: script.py [-h help] [-t TREE_STRUCTURE] [-i IMAGE_NAME] [-d DRIVER_VALUE]
                 [-s SUBNET_VALUE] [-g GATEWAY_VALUE]
                 [-a COLLECTION_OF_AUX_ADDRESS] [-destroy DESTROY] [--version]
optional arguments:
  -h, --help            show this help message and exit
  -t TREE_STRUCTURE     Structure of Tree "X_Y" format
  -i IMAGE_NAME         Image name
  -d DRIVER_VALUE       driver value
  -s SUBNET_VALUE       Subnet value
  -g GATEWAY_VALUE      Gateway value
  -a COLLECTION_OF_AUX_ADDRESS
                        List of AUX address
  -destroy DESTROY      Destroy the tropology
  --version             show program's version number and exit
'''

import argparse
import os
import subprocess
parser = argparse.ArgumentParser()

parser.add_argument('-t', action='store', dest='tree_structure',
                    help='Structure of Tree  \"X_Y\" format')

parser.add_argument('-i', action='store', dest='image_name',
                    default='new_sw13',
                    help='Image name')
parser.add_argument('-d', action='store', dest='driver_value',
                    default='veth',
                    help='driver value')

parser.add_argument('-s', action='store', dest='subnet_value',
                    default='10.2.0.0/24',
                    help='Subnet value')

parser.add_argument('-g', action='store', dest='gateway_value',
                    default='10.2.0.254',
                    help='Gateway value')

parser.add_argument('-a', action='append', dest='collection_of_aux_address',
                    default=[],
                    help='List of AUX address',
                    )

parser.add_argument('-destroy', action='store',
                    dest='destroy',
                    help='Destroy the tropology')
                    
parser.add_argument('--version', action='version', version='LOL')

results = parser.parse_args()

def tree_generator(results):
    if results.destroy is not None:
      cmd = "pl --destroy "+results.destroy
      try:
      #subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
        subprocess.call(cmd, shell=True, stderr=subprocess.STDOUT)
      except subprocess.CalledProcessError as e:
        raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))  
      finally:
        return
    total, leaf, level = structure(results.tree_structure)
    host = []
    link={}
    string = "links:\n  - endpoints: "
    host_str = []
    for i in range(1, total+1):
        host_str.append("sw-"+str(i)+":eth0")
        host.append(i)
        link[i] = []
    mylist= host.copy()
    mylist.pop(0)
    host_str.append("ctr:eth0")
    string += str(host_str)+"\n    driver: bridge\n"
    for i,j in link.items():
        link[i].append(mylist[0])
        if len(mylist)==1:
            break
        else:
            mylist.pop(0)
        link[i].append(mylist[0])
        if len(mylist)==1:
            break
        else:
            mylist.pop(0)
    newlink ={}
    for k, v in link.items():
        if newlink.get(k) is None:
            newlink[k] = []
        for j in v:
            newlink[j] = [k]
        for l in v:
            newlink[k].append(l)

    prefix = str(results.tree_structure).replace("_","")
    for a,b in newlink.items():
        for z in b:
            string += "  - endpoints: "+"[\"sw-"+str(a)+":eth"+str(newlink.get(a).index(z)+1)+"\", \"sw-"+str(z)+":eth"+str(newlink.get(z).index(a)+1)+"\"]"+"\n"
    string += "  - endpoints: "+"[\"sw-1:eth3"+"\", \"ctr:eth1"+"\"]"+"\n"
    string += "\nVERSION: 2\ndriver: "+results.driver_value+"\nPREFIX: "+'\"'+prefix+"\"\nCONF_DIR: ./config\nMY_IMAGE: "+results.image_name+"\nPUBLISH_BASE: 9005\nSUBNET: "+results.subnet_value+"\nGATEWAY: "+results.gateway_value+"\nAUX_ADDRESSES: "+str(results.collection_of_aux_address)
    
    file = open(prefix+"_T.yml", "w+")
    file.write(string)
    #print(os.path.exists("34_T.yml"), file.name)
    #subprocess.check_call("docker-topo --create "+file.name, shell=True)
    file.close()
    cmd = "pl --create "+file.name
    try:
      #subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
      subprocess.call(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
    #return string


def structure(num):
    level, leaf = str(num).split('_')[0],str(num).split('_')[1]
    total = ((int(level)-1)<<2) - 1 + int(leaf)
    return total, leaf, level
tree_generator(results)