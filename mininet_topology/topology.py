from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel

class P4Topology(Topo):
    def build(self):
        """Define the network topology based on the research paper using P4 switches and Ryu."""

        # Add P4 switches instead of OVS (BMv2)
        s1 = self.addSwitch('s1', dpid='0000000000000001')  # Attacking switch 1
        s2 = self.addSwitch('s2', dpid='0000000000000002')  # Attacking switch 2
        s3 = self.addSwitch('s3', dpid='0000000000000003')  # Attacking switch 3
        s4 = self.addSwitch('s4', dpid='0000000000000004')  # Intermediary switch
        s5 = self.addSwitch('s5', dpid='0000000000000005')  # Victim switch

        # Hosts (Attackers, Normal users, Victim)
        attackers = [self.addHost(f'h{i}') for i in range(1, 7)]
        users = [self.addHost(f'h{i}') for i in range(7, 10)]
        victim = self.addHost('victim')

        # Connecting attackers to their respective switches
        for h in attackers[:2]: self.addLink(h, s1)
        for h in attackers[2:4]: self.addLink(h, s2)
        for h in attackers[4:]: self.addLink(h, s3)

        # Connecting Users to Intermediate Switch
        for h in users: self.addLink(h, s4)

        # Connecting Victim to its Switch
        self.addLink(victim, s5)

        # Switch Interconnections
        self.addLink(s1, s4)
        self.addLink(s2, s4)
        self.addLink(s3, s4)
        self.addLink(s4, s5)

def run():
    """Start the Mininet network with P4 switches and Ryu controller."""
    topo = P4Topology()
    net = Mininet(topo=topo, controller=None)  # No default controller

    # Add the Ryu Controller (port 6653)
    ryu_controller = RemoteController('ryu', ip='127.0.0.1', port=6653)
    net.addController(ryu_controller)

    net.start()

    print("🚀 P4 Mininet Topology Running with Ryu Controller. Type 'exit' to quit.")
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
