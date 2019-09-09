import socket
import subprocess
import sys
import os
from datetime import datetime
from netaddr import IPNetwork


# Clear the screen
subprocess.call('clear', shell=True)


def tcp_port_scanner():
	# Ask for input
	remoteServer    = input("Enter a remote host to scan: ")
	remoteServerIP  = socket.gethostbyname(remoteServer)

	# Print a nice banner with information on which host we are about to scan
	print("-" * 60)
	print("Please wait, scanning remote host", remoteServerIP)
	print("-" * 60)

	# Check what time the scan started
	t1 = datetime.now()

	# Using the range function to specify ports (here it will scans all ports between 1 and 1024)

	# We also put in some error handling for catching errors

	try:
		for port in range(1,1025):  
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result = sock.connect_ex((remoteServerIP, port))

			if result == 0:
				print("Port {}: 	 Open".format(port))
			sock.close()

	except KeyboardInterrupt:
		print("You pressed Ctrl+C")
		sys.exit()

	except socket.gaierror:
		print('Hostname could not be resolved. Exiting')
		sys.exit()

	except socket.error:
		print("Couldn't connect to server")
		sys.exit()

	# Checking the time again
	t2 = datetime.now()

	# Calculates the difference of time, to see how long it took to run the script
	total =  t2 - t1

	# Printing the information to screen
	print('Scanning Completed in: ', total)


def host_discovery(address: list):
	"""	
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	FNULL = open(os.devnull, 'w')
	for addr in address:
		res = subprocess.call(['ping', '-q', '-c', '3', addr], stdout=FNULL) 
		if res == 0: 
			temp = addr, "UP"
			return [[temp]]
		elif res == 2: 
			temp = "no response from", addr
			return [[temp]]
		else: 
			temp = addr, "DOWN"
			return [[temp]]


def host_discovery_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	for ip in IPNetwork(host_subnet):
		host_discovery([str(ip)])


def udp_port_scanner(hosts:list): 
	"""
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	for host in hosts:
		os = subprocess.check_output(['nmap', '-sV', host])
		output_list = str(os).split('\\n')
		return [[output_list]]


def udp_port_scanner_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	for ip in IPNetwork(host_subnet):
		udp_port_scanner([str(ip)])


def os_detection(hosts:list):
	"""
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	for host in hosts:
		os = subprocess.check_output(['sudo', 'nmap', '-O', host])
		for line in str(os).split('\\n'):
			if line.startswith('Running') or line.startswith('Aggressive'):
				return [[line]]


def os_detection_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	for ip in IPNetwork(host_subnet):
		os_detection([str(ip)])


def service_detection(hosts:list):
	"""
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	for host in hosts:
		os = subprocess.check_output(['nmap', '-sV', host])
		output_list = str(os).split('\\n')
		return [[output_list]]


def service_detection_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	for ip in IPNetwork(host_subnet):
		service_detection([str(ip)])


if __name__ == '__main__':
	print('HOST DISCOVERY')
	host_discovery(['localhost', 'localhost', '127.0.0.1'])
	host_discovery_subnet('127.0.0.0/24')

	print('OS DETECTION')
	os_detection(['localhost', 'localhost', '127.0.0.1'])
	os_detection_subnet('127.0.0.0/24')

	print('SERVICE DETECTION')
	service_detection(['localhost', 'localhost', '127.0.0.1'])
	service_detection_subnet('127.0.0.0/24')

	print('UDP PORT SCANNER')
	udp_port_scanner(['localhost', 'localhost', '127.0.0.1'])
	udp_port_scanner_subnet('127.0.0.0/24')
