################################################################################
##Network Scanning Program##
#Objectives of this program:
    #1. Scan the network
    #2. Create an Arp request directed to broadcast MAC asking for IP
        #Use ARP to ask who has the target IP
        #Set destination MAC to broadcast MAC
    #3. Send packet and receive a response
    #4. Parse the response
    #5. Print Result
        #Improve Readability
        #Improve Reusability 
################################################################################

#Import modules
import scapy.all as scapy #module used to interact with and manipulate network packets, while renaming it to "scapy" to simplify future references of it in our code  
import optparse #module to allow users to provide arguments

def get_arguments(): #allows for user input of IP/IP Range arguments
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Allows user to target a(n) IP/IP Range")
    (options, arguments) = parser.parse_args()
    return options

#function used to create ARP request messages
def scan(ip):
    arp_request= scapy.ARP(pdst=ip) # use arp to ask who has target ip
    broadcast = scapy.Ether (dst="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]

#loop used for data encapsulation
    clients_list=[] #creates list to store client information
    for element in answered_list: #loop function, print each element in the list
        client_dict= {"ip": element[1].psrc, "mac": element[1].hwsrc} #pulls the IP address and the MAC address from the ARP response message
        clients_list.append(client_dict)
    return clients_list

#function used to format and return the results of the scan list in a user-friendly format
def print_result(result_list):
    print("IP \t\t\t MAC Address\n-------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"]) #formats information to be printed from list 
        print("-------------------------------------------")

option=get_arguments() #pulls user provided arguments
scan_output=scan(option.target) #pipes the target (-t provided by the user) into the scan function
print_result(scan_output) #pipes the scan function results into the print_result function
