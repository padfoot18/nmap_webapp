import socket
import subprocess
import sys
import os
from datetime import datetime
from netaddr import IPNetwork

subprocess.call('clear', shell=True)


def tcp_port_scanner(remoteServer:list):
	t1 = datetime.now()
	output = []
	for host in remoteServer:
		remoteServerIP  = socket.gethostbyname(host)
		try:
			for port in range(1,1024):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((remoteServerIP, port))
				if result == 0:
					output.append("Port {}: 	 Open".format(port))
				sock.close()
		except socket.gaierror:
			return ['Hostname could not be resolved. Exiting']
		except socket.error:
			return ["Couldn't connect to server"]
		t2 = datetime.now()
		time = t2-t1
		output.append(f'Scanning completed in {time}')
		return output



def tcp_scanner_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	for ip in IPNetwork(host_subnet):
		tcp_port_scanner([str(ip)])


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
