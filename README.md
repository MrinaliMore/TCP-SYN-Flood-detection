# TCP-SYN-Flood-detection
To detect the TCP SYN flood attack by determining the number of SYN packets

Step 1. Get into super user mode: ‘sudo su’
        Start the openvSwitch:  This will start the openVSwitch service in the VM
        ‘/usr/local/share/openvswitch/scripts/ovs-ctl start ’  

Step 2. Check if the bridge is configured properly:
‘ovs-vsctl show’

In case there is no bridge xenbr0, create one:
‘ovs-vsctl add-br xenbr0’   // This will create the openVswitch bridge or datapath named ‘xenbr0’
Ref: https://www.youtube.com/watch?v=rYW7kQRyUvA&index=1&list=LLdvT8AVpA4tyZz9FYUi4Mcg

Git clone the repository. Install tcpreplay.

Step 3. Attach vif to eth port as you did in exercise 2
•	Check which interface has an active host-only IP (192.168.56.*) -- pick eth1
•	ifconfig eth1 0
•	ifconfig xenbr0 <ip address noted above> netmask 255.255.255.0 up
•	ovs-vsctl add-port xenbr0 eth1
•	Check if eth1 is added in the bridge: ‘ovs-vsctl show’ 

Step 4. Create a Xen configuration file, e.g. myinstance.xen

Step 5. Start a new Xen domain using the xen config file myinstance.xen and the command ‘xl create <xen file name>’. 
   You could see the domain named ‘clickos’ in the domain list and that will be in ‘b’ (blocked) state initially. 
   E.g. xl create myinstance.xen
   
Step 6. Write a click configuration file which consists of the click elements to be executed on running the clickOS instance.
   vim tcpsyn.click

Step 7. Start the clickOS instance with the above click file using the command ‘./cosmos/dist/bin/cosmos start <clickos domain name>   <click file name>’ (Run it in the directory where clickos package is downloaded).The state of the domain should change to r(running) or nothing at all(simply hyphens).
e.g. ‘./cosmos/dist/bin/cosmos start clickos tcpsyn.click’  
Run ‘xl list’ command, which should show the domain state as ‘r’ (running) or blank some times.

Step 8. Open 2 putty sessions and ssh to the clickos VM – use xenbr0 IP address (Host Only Adaptor)
Run ‘xl console <clickos domain ID>’ on a VM console to check the running logs of the clickos instance.

Packet’s threshold value is set to 20. As and when the count of SYN packets goes beyond this value, a alert message is printed on the console as shown above.
To terminate the execution use Ctrl + ]   (Control plus closing bracket)

Step 10. After your work is done, you can destroy the clickOS instance using ‘xl destroy <clickos domain ID>’ command.
