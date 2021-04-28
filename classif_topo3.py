from mininet.topo import Topo
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.clean import cleanup
from functools import partial

import argparse
import os
import sys
import time
import subprocess

out_dir = './out'

class SDN_Topology(Topo):
    def build(self, n=2):
	h1 = self.addHost("h1")
	h2 = self.addHost("h2")


	s1 = self.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")
	s2 = self.addSwitch("s2", cls=OVSKernelSwitch, protocols="OpenFlow13")
	self.addLink(h1, s1)
	self.addLink(s2, h2)

	for i in range(n):
	    switch = self.addSwitch('s%s' %(i+3))
	    self.addLink(s1, switch)
	    self.addLink(s2, switch)

	self.addLink(h1, s1)
	self.addLink(s2, h2)

	self.addLink(h1, s1)
	self.addLink(s2, h2)

def initializeTopo(n=2):
    topo = SDN_Topology(n)
    net = Mininet(topo=topo, controller=RemoteController('c0', ip='127.0.0.1', port=6633))
    return net

def output_directory(target) :
    if not os.path.exists(out_dir) :
        os.makedirs(out_dir)

    output_dir = os.path.join(out_dir, '{}_{}'.format(target, time.strftime('%m%d_%H%M%S')))
    os.makedirs(output_dir)

    return output_dir

def setup_htb_and_qdisc(aqm_switch, qdisc, rate, delay, limit, loss):
    #os.system('rmmod ifb')
    os.system('modprobe ifb numifbs=3')
    os.system('modprobe act_mirred')

    # clear old queueing disciplines (qdisc) on the interfaces
    aqm_switch.cmd('tc qdisc del dev {}-eth1 root'.format(aqm_switch))
    aqm_switch.cmd('tc qdisc del dev {}-eth1 ingress'.format(aqm_switch))
    aqm_switch.cmd('tc qdisc del dev {}-ifb0 root'.format(aqm_switch))
    aqm_switch.cmd('tc qdisc del dev {}-ifb0 ingress'.format(aqm_switch))

    # create ingress ifb0 on client interface.
    aqm_switch.cmd('tc qdisc add dev {}-eth1 handle ffff: ingress'.format(aqm_switch))
    aqm_switch.cmd('ip link add {}-ifb0 type ifb'.format(aqm_switch))
    aqm_switch.cmd('ip link set dev {}-ifb0 up'.format(aqm_switch))
    aqm_switch.cmd('ifconfig {}-ifb0 txqueuelen 1000'.format(aqm_switch))

    # forward all ingress traffic to the ifb device
    aqm_switch.cmd('tc filter add dev {}-eth1 parent ffff: protocol all u32 '
               'match u32 0 0 action mirred egress redirect '
               'dev {}-ifb0'.format(aqm_switch,aqm_switch))

    # create an egress filter on the IFB device
    aqm_switch.cmd('tc qdisc add dev {}-ifb0 root handle 1: '
               'htb default 11'.format(aqm_switch))

    # Add root class HTB with rate limiting 
    aqm_switch.cmd('tc class add dev {}-ifb0 parent 1: classid 1:11 '
               'htb rate {}mbit'.format(aqm_switch,rate))

    aqm_switch.cmd('tc qdisc add dev {}-eth2 root netem delay {}ms'.format(aqm_switch,delay))

    if qdisc != '': # Add Active Queue Management if enabled
        aqm_switch.cmd('tc qdisc add dev {}-ifb0 parent 1:11 handle 20: {}'.format(aqm_switch, qdisc))

    else : # Set default
        if int(loss) != 0:
            aqm_switch.cmd('tc qdisc add dev {}-ifb0 parent 1:11 handle 20: netem delay 0.1ms limit {} loss {}%'.format(aqm_switch, limit, loss))
        else :
            aqm_switch.cmd('tc qdisc add dev {}-ifb0 parent 1:11 handle 20: netem delay 0.1ms limit {}'.format(aqm_switch, limit))

def iperf_application(net, n, output, duration):
    sender = net.get('h1')
    receiver = net.get('h2')

    start_port = 5000

    # server
    for i in range(n):
	receiver.cmd('iperf -s -p {} &'.format(start_port+i))
    # client
    for i in range(n):
	sender.cmd('iperf -c {} -p {} -t {} -i 0.5 -Z cubic > {} &'.format(receiver.IP(), start_port+i, duration, os.path.join(output, "flow{}_iperf.txt".format(i))))

def set_tcp_dump(net, directory):
    s1 = net.get('s1')
    s3 = net.get('s2')
    FNULL = open(os.devnull,'w')
    subprocess.Popen(['tcpdump', '-i', 's1-eth1', '-n', 'tcp', '-w', '{}/s1_1.pcap'.format(directory), '-s', '200'], stderr=FNULL)
    subprocess.Popen(['tcpdump', '-i', 's2-eth1', '-n', 'tcp', '-w', '{}/s3_1.pcap'.format(directory), '-s', '200'], stderr=FNULL)
    subprocess.Popen(['tcpdump', '-i', 's1-eth5', '-n', 'tcp', '-w', '{}/s1_5.pcap'.format(directory), '-s', '200'], stderr=FNULL)
    subprocess.Popen(['tcpdump', '-i', 's2-eth5', '-n', 'tcp', '-w', '{}/s3_5.pcap'.format(directory), '-s', '200'], stderr=FNULL)
    subprocess.Popen(['tcpdump', '-i', 's1-eth6', '-n', 'tcp', '-w', '{}/s1_6.pcap'.format(directory), '-s', '200'], stderr=FNULL)
    subprocess.Popen(['tcpdump', '-i', 's2-eth6', '-n', 'tcp', '-w', '{}/s3_6.pcap'.format(directory), '-s', '200'], stderr=FNULL)

def configure_host(net):
    sender = net.get('h1')
    receiver = net.get('h2')

    sender.setIP('10.0.0.1/24')
    receiver.setIP('10.0.0.3/24')

    sender.cmd('ifconfig h1-eth1 10.0.1.1/24')
    receiver.cmd('ifconfig h2-eth1 10.0.1.3/24')
    receiver.cmd('sysctl -w net.ipv4.tcp_rmem=\'4096 625000 2500000\'')

    sender.cmd('ifconfig h1-eth2 10.0.2.1/24')
    receiver.cmd('ifconfig h2-eth2 10.0.2.3/24')

    sender.cmd("ip rule add from 10.0.0.1 table 1")
    sender.cmd("ip rule add from 10.0.1.1 table 2")
    sender.cmd("ip rule add from 10.0.2.1 table 3")

    sender.cmd("ip route add 10.0.0.0/24 dev h1-eth0 scope link table 1")
    sender.cmd("ip route add default via 10.0.0.1 dev h1-eth0 table 1")
    sender.cmd("ip route add 10.0.1.0/24 dev h1-eth1 scope link table 2")
    sender.cmd("ip route add default via 10.0.1.1 dev h1-eth1 table 2")
    sender.cmd("ip route add 10.0.2.0/24 dev h1-eth2 scope link table 3")
    sender.cmd("ip route add default via 10.0.2.1 dev h1-eth2 table 3")
 
    receiver.cmd("ip rule add from 10.0.0.3 table 1")
    receiver.cmd("ip rule add from 10.0.1.3 table 2")
    receiver.cmd("ip rule add from 10.0.2.3 table 3")

    receiver.cmd("ip route add 10.0.0.0/24 dev h2-eth0 scope link table 1")
    receiver.cmd("ip route add default via 10.0.0.3 dev h2-eth0 table 1")
    receiver.cmd("ip route add 10.0.1.0/24 dev h2-eth1 scope link table 2")
    receiver.cmd("ip route add default via 10.0.1.3 dev h2-eth1 table 2")
    receiver.cmd("ip route add 10.0.2.0/24 dev h2-eth2 scope link table 3")
    receiver.cmd("ip route add default via 10.0.2.3 dev h2-eth2 table 3")

    sender.cmd('ethtool -K {}-eth0 tso off gso off gro off'.format(sender))
    sender.cmd('tc qdisc add dev {}-eth0 root netem delay 0.1ms'.format(sender))
    receiver.cmd('ethtool -K {}-eth0 tso off gso off gro off'.format(receiver))


def mptcp_iperf_application(net, n, output, duration):
    sender = net.get('h1')
    receiver = net.get('h2')

    port = 5000
    receiver.cmd('iperf -s -p {} &'.format(port))
    sender.cmd('iperf -c {} -p {} -t {} -i 1 -Z cubic > {} &'.format(receiver.IP(), port, duration, os.path.join(output, "mptcpflow_iperf.txt")))

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='controller',
                        default='127.0.0.1:6653', help='Configuration of Remote SDN Controller')
    parser.add_argument('-p', dest='path',
                        default='30:20,30:40,30:100', help='Bandwidth and Delay for each path / default: 2-path, 10Mbps and 10ms')
    parser.add_argument('-o', dest='output',
                        default='SDN', help='Output Directory name')
    parser.add_argument('-d', dest='duration',
                        default='30', help='Test duration (default : 30 sec)')
    arg = parser.parse_args()
	
    # Check and configure output directory
    output_dir = output_directory(arg.output)

    # Configure the path
    pathlist = arg.path.split(',')

    net = initializeTopo(len(pathlist))
    net.start()
    
    
    os.system('sysctl -w net.core.rmem_max=250000000 net.ipv4.tcp_rmem=\'4096 131072 250000000\'')
    os.system('sysctl -w net.core.wmem_max=250000000 net.ipv4.tcp_wmem=\'4096  16384 250000000\'') 

    for i in range(len(pathlist)):
    	setup_htb_and_qdisc(net.get('s%s'%(i+3)), '', int(pathlist[i].split(':')[0]), int(pathlist[i].split(':')[1]),200, 0)

    configure_host(net)

    # Tcpdump
    set_tcp_dump(net, output_dir)
    time.sleep(1)

    # Configure Application
#iperf_application(net, len(pathlist), output_dir, int(arg.duration))
# mptcp_iperf_application(net,len(pathlist), output_dir, int(arg.duration))

    CLI(net)
#   time.sleep(int(arg.duration))
 
    
    net.stop()
    cleanup()
