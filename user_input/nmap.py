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
	command = []
	for host in remoteServer:
		temp = []
		remoteServerIP = socket.gethostbyname(host)
		command.append('nmap -sT ' + host)
		try:
			for port in range(1, 1024):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((remoteServerIP, port))
				if result == 0:
					temp.append("Port {}: Open".format(port))
				sock.close()
		except socket.gaierror:
			return ['Hostname could not be resolved. Exiting']
		except socket.error:
			return ["Couldn't connect to server"]
		t2 = datetime.now()
		time = t2-t1
		temp.append(f'Scanning completed in {time}')
		output.append(temp)
	return output, command


def tcp_scanner_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	output = []
	command = []
	for ip in IPNetwork(host_subnet):
		op, cmd = tcp_port_scanner([str(ip)])
		output.append(op)
		command.append(cmd)
	return output, command

def host_discovery(address: list):
	"""	
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	output = []
	command = []
	FNULL = open(os.devnull, 'w')
	for addr in address:
		print(addr)
		res = subprocess.call(['ping', '-q', '-c', '3', addr], stdout=FNULL)
		command.append('nmap -sL ' + addr)
		if res == 0: 
			temp = addr + " is UP"
			output.append([temp])
		elif res == 2: 
			temp = "no response from", addr
			output.append([temp])
		else: 
			temp = addr + " is DOWN"
			output.append([temp])
	return output, command


def host_discovery_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	output = []
	command = []
	for ip in IPNetwork(host_subnet):
		op, cmd = host_discovery([str(ip)])
		output.append(op)
		command.append(cmd)
	return output, command


def udp_port_scanner(hosts:list): 
	"""
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	output = []
	command = []
	for host in hosts:
		print(host)
		os = subprocess.check_output(['nmap', '-sU', '--min-rate', '8000', host])
		command.append('nmap -sU ' + host)
		output_list = str(os).split('\\n')
		output.append('\n'.join(output_list[5:-2]))
	return output, command


def udp_port_scanner_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	output = []
	command = []
	for ip in IPNetwork(host_subnet):
		op, cmd = udp_port_scanner([str(ip)])
		if op[0] != '':
			output.append(op[0])
		command.append(cmd[0])
	return output, command


def os_detection(hosts:list):
	"""
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	output = []
	command = []
	for host in hosts:
		print(host)
		os = subprocess.check_output(['sudo', 'nmap', '-O', '--min-rate', '8000',host])
		command.append('sudo nmap -O ' + host)
		for line in str(os).split('\\n'):
			if line.startswith('Running') or line.startswith('Aggressive'):
				output.append([line])
	return output, command


def os_detection_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	output = []
	command = []
	for ip in IPNetwork(host_subnet):
		op, cmd = os_detection([str(ip)])
		output.append(op)
		command.append(cmd)
	return output, command


def service_detection(hosts:list):
	"""
	WORKS FOR SINGLE AND MULTIPLE IP's
	"""
	output = []
	command = []
	for host in hosts:
		print(host)
		os = subprocess.check_output(['nmap', '-sV', '--min-rate', '8000', host])
		command.append('nmap -sV ' + host)
		output_list = str(os).split('\\n')
		output.append('\n'.join(output_list[5:10]))
	return output, command


def service_detection_subnet(host_subnet:str):
	"""
	WORKS FOR A SUBNET
	"""
	output = []
	command = []
	for ip in IPNetwork(host_subnet):
		op, cmd = service_detection([str(ip)])
		if op[0] != '':
			output.append(op)
		command.append(cmd)
	return output, command


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
