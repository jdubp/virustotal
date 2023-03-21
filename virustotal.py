#!/usr/bin/env python

import argparse
import csv
import json
import os
import urllib
import re
from collections import defaultdict, Counter


import requests
# Suppressing SSL Warnings (InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning)
# req.packages.urllib3.disable_warnings()
import urllib3

urllib3.disable_warnings()

http_proxy=''
https_proxy=''
proxy_dict = { "http" : http_proxy, "https" : https_proxy }

#
# Class for VirusTotal-API library with common methods
#
class VirusTotal(object):
	#
	# Parent object for VirusTotal-API library. Creation of this object will allow
	# use of the VirusTotal API for python based projects
	#

	def __init__(self):
		self.api = ''
		self.base = 'https://www.virustotal.com/api/v3'

	def search(self,query,limit):
		file_ids = []
		query_string = query + '&limit='+str(limit)+'&descriptors_only=true&order=first_submission_date-'
		# Encode query, & is safe (should not be encoded)
		uri = '/intelligence/search?query={}'.format(urllib.parse.quote(query_string, safe='&'))
		url = self.base + uri
		header = {'Content-Type': 'application/json', 'Accept': 'application/json', 'x-apikey': self.api}

		resp = requests.get(url, proxies=proxy_dict, headers=header, verify=False)

		if resp.status_code == 200:
			js = resp.json()
			data = js['data']
			for file in data:
				id = file['id']
				file_ids.append(id)	
				# Get other data
				#for i in attributes:
					#magic = i[magic]
					#md5 = i[md5]
					#vhash = i[vhash]
			#print(json.dumps(js, sort_keys=True, indent=4))
		else:
			print('[!] ERROR: ' + uri + ' ' + str(resp.status_code) + ' and message: ' + str(resp.content))
			raise Exception('ERROR - VirusTotal API failure')

		return file_ids

	def ip_addresses(self,ip,endpoint):
		uri = '/ip_addresses/{}/{}'.format(ip,endpoint)
		url = self.base + uri
		header = {'Content-Type': 'application/json', 'Accept': 'application/json', 'x-apikey': self.api}

		resp = requests.get(url, proxies=proxy_dict, headers=header, verify=False)
		
		# Results dict
		r = {}
		# Lists to hold ip details
		hostnames = []

		if resp.status_code == 200:
			js = resp.json()
			#print(json.dumps(js, sort_keys=True, indent=4))	
			data = js['data']
			for i in data:
				attributes = i['attributes']
				
				#WHOIS
				if attributes.get('whois_map'):
					org_name = attributes['whois_map']['OrgName']
					reg_date = attributes['whois_map']['RegDate']
					update = attributes['whois_map']['Updated Date']
					reg_country = attributes['whois_map']['Registrant Country']	
				#RESOLUTIONS
				if attributes.get('host_name'):
					hostnames.append(attributes['host_name'])
			
			if endpoint == 'historical_whois':	
				r['organization_name'] = org_name
				r['registration_date'] = reg_date
				r['last_updated'] = update
				r['registration_country'] = reg_country
				
			if endpoint == 'resolutions':
				r['hostnames'] = hostnames

			return r
														
		else:
			print('[!] ERROR: ' + uri + ' ' + str(resp.status_code) + ' and message: ' + str(resp.content))
			raise Exception('ERROR - VirusTotal API failure')
		
	def domains(self,domain,endpoint):
		uri = '/domains/{}/{}'.format(domain,endpoint)
		url = self.base + uri
		header = {'Content-Type': 'application/json', 'Accept': 'application/json', 'x-apikey': self.api}

		resp = requests.get(url, proxies=proxy_dict, headers=header, verify=False)
		
		# Results dict
		r = {}
		# Lists to hold domain details
		siblings = []
		subdomains = []

		if resp.status_code == 200:
			js = resp.json()
			#print(json.dumps(js, sort_keys=True, indent=4))	
			data = js['data']
			for i in data:
				attributes = i['attributes']
				id = i['id']
				
				#SIBLINGS
				if endpoint == 'siblings':
					siblings.append(id)
				#SUBDOMAINS
				if endpoint == 'subdomains':
					subdomains.append(id)
				
			if subdomains:
				r['subdomains'] = subdomains
			if siblings:
				r['siblings'] = siblings

			return r
														
		else:
			print('[!] ERROR: ' + uri + ' ' + str(resp.status_code) + ' and message: ' + str(resp.content))
			raise Exception('ERROR - VirusTotal API failure')
		
	def files(self,id,endpoint):		
		uri = '/files/{}/{}'.format(id,endpoint)
		url = self.base + uri
		header = {'Content-Type': 'application/json', 'Accept': 'application/json', 'x-apikey': self.api}

		resp = requests.get(url, proxies=proxy_dict, headers=header, verify=False)
		
		# Results dict
		r = {}
		# Lists to hold behavior details
		files_written = []
		files_dropped = []
		files_deleted = []
		registry_keys_set = []
		mutexes_created = []
		processes_created = []
		command_executions = []
		processes_tree = []
		dns_lookups = []
		ip_traffic = []
		http_conversations = []
		ja3_digests = []
		# List to hold itw urls
		itw = []

		if resp.status_code == 200:
			js = resp.json()
			#print(json.dumps(js, sort_keys=True, indent=4))	
			data = js['data']
			for i in data:
				attributes = i['attributes']
				
				#ENDPOINT
				if attributes.get('files_written'):
					for file in attributes['files_written']:
						if file not in files_written:
							files_written.append(file)
					
				if attributes.get('files_dropped'):
					for file in attributes['files_dropped']:
						dropped_info = {'file' : file['path'], 'sha256' : file['sha256']}
						if dropped_info not in files_dropped:
							files_dropped.append(dropped_info)
				if attributes.get('files_deleted'):
					for file in attributes['files_deleted']:
						if file not in files_deleted:
							files_deleted.append(file)							
				if attributes.get('registry_keys_set'):
					for key in attributes['registry_keys_set']:
						if key not in registry_keys_set:
							registry_keys_set.append(key)
				if attributes.get('mutexes_created'):
					for mutex in attributes['mutexes_created']:
						if mutex not in mutexes_created:
							mutexes_created.append(mutex)
				if attributes.get('processes_created'):
					for proc in attributes['processes_created']:
						if proc not in processes_created:
							processes_created.append(proc)			
				if attributes.get('command_executions'):
					for cmd in attributes['command_executions']:
						if cmd not in command_executions:
							command_executions.append(cmd)	
				if attributes.get('processes_tree'):
					parent_proc = ''
					processes = []
					child_processes = []
					#print(json.dumps(attributes['processes_tree'], sort_keys=True, indent=4))
					proc_tree = attributes['processes_tree'][0]
					parent_proc = proc_tree['name']
					
					# Look for children processes
					if proc_tree.get('children'):
						children = proc_tree['children']
						for proc in children:
							processes.append(proc['name'])
							
							# Look for grandchild processes
							if proc.get('children'):
								childs = proc['children']
								for c in childs:
									child_processes.append(c['name'])
									
					# Populate dict with process tree information
					tree_info = {'parent_process' : parent_proc, 'processes' : processes, 'children' : child_processes}
					if tree_info not in processes_tree:
						processes_tree.append(tree_info)				
					
				# NETWORK
				if attributes.get('dns_lookups'):
					for dns in attributes['dns_lookups']:
						dns_info = {}
						keys = ['hostname', 'resolved_ips']
						# Keys don't always exist
						for key in keys:
							if dns.get(key):
								dns_info[key] = dns[key]
								# Enrich Domain data	
								if key == 'hostname':
									r = self.domains(dns_info[key],'siblings')
									dns_info.update(r)
									r = self.domains(dns_info[key],'subdomains')
									dns_info.update(r)									
							else:
								dns_info[key] = ''
						if dns_info not in dns_lookups:
							dns_lookups.append(dns_info)
				if attributes.get('ip_traffic'):
					for ip in attributes['ip_traffic']:
						ip_info = {}
						keys = ['destination_ip', 'destination_port', 'transport_layer_protocol']
						# Keys don't always exist
						for key in keys:
							if ip.get(key):
								ip_info[key] = ip[key]
								# Enrich IP data
								if key == 'destination_ip':
									r = self.ip_addresses(ip[key],'historical_whois')
									ip_info.update(r)
									r = self.ip_addresses(ip[key],'resolutions')
									ip_info.update(r)
							else:
								ip_info[key] = ''
						if ip_info not in ip_traffic:
							ip_traffic.append(ip_info)		
				if attributes.get('http_conversations'):
					for http in attributes['http_conversations']:
						http_info = {'request_method' : http['request_method'], 'url' : http['url']}
						if http_info not in http_conversations:
							http_conversations.append(http_info)	
				if attributes.get('ja3_digests'):
					for ja3 in attributes['ja3_digests']:
						if ja3 not in ja3_digests:
							ja3_digests.append(ja3)
				
				#ITW_URLS
				if attributes.get('url'):
					itw_info = {}
					keys = ['last_http_response_code', 'url']
					for key in keys:
						itw_info[key] = attributes[key]
					itw.append(itw_info)
							
			if endpoint == 'behaviours':
				r['files_written'] = files_written
				r['files_dropped'] = files_dropped
				r['files_deleted'] = files_deleted
				r['registry_keys_set'] = registry_keys_set
				r['mutexes_created'] = mutexes_created 
				r['processes_created'] = processes_created
				r['command_executions'] = command_executions
				r['processes_tree'] = processes_tree
				r['dns_lookups'] = dns_lookups
				r['ip_traffic'] = ip_traffic
				r['http_conversations'] = http_conversations
				r['ja3_digests'] = ja3_digests
			if endpoint == 'itw_urls':
				r['itw_urls'] = itw
			
			return r
														
		else:
			print('[!] ERROR: ' + uri + ' ' + str(resp.status_code) + ' and message: ' + str(resp.content))
			raise Exception('ERROR - VirusTotal API failure')
			

def main():
	# Command line parsing
	parser = argparse.ArgumentParser(description='VirusTotal Intelligence behavioral search script', epilog='Example: virustotal.py -s vhash:"bcaa8efd9d034720c132fc5e491050c3" -d 5 -l 10')
	# Optional arguments
	parser.add_argument('-s', '--search', help='A VirusTotal Intelligence search modifier')
	parser.add_argument('-d', '--days', type=int, default=3, help='Filters the files to be returned according to the number of days since first submission, default: 3') 
	parser.add_argument('-l', '--limit', type=int, default=3, help='Limit the number of results returned, default: 5')
	args = parser.parse_args()

	# Require search input
	if not args.search:
		parser.error('[!] ERROR - Please specify a VirusTotal Intelligence search modifier')
		parser.print_help()
		sys.exit()
		
	# Build search string
	# If a MD5 was provided run a simple search
	md5_pattern = r'\b([a-f0-9]{32}|[A-F0-9]{32})\b'
	if re.match(md5_pattern, args.search):
		query = args.search
	else:
		query = 'have:behavior fs:'+str(args.days)+'d+ '+args.search
	# Return IDs 
	vt = VirusTotal()
	search_limit = args.limit
	ids = vt.search(query, search_limit)
	
	# Query IDs for behavior
	behaviors = []
	for id in ids:
		r = {}
		r.update({'file_id': id })
		r.update(vt.files(id,'itw_urls'))
		r.update(vt.files(id,'behaviours'))
		behaviors.append(r)

	# Merge results into a single dictionary
	container = {}
	container['results'] = behaviors
	dd = defaultdict(list)
	for result in container['results']:
		for k, v in result.items():
			# Avoid creating nested inner lists and remove duplicates
			if isinstance(v, (list)):
				for i in v:
					if i not in dd[k]:
						dd[k].append(i)
			else:
				dd[k].append(v)
	
	# Print results
	for k, v in dd.items():
		print()
		print('[*] ' + k.upper())
		# Some values are simple lists, sort them
		try:
			v.sort()
			for i in v:
				# Some list content is JSON
				if isinstance(i, dict):
					print(json.dumps(v, sort_keys=True, indent=4))
				else:
					print(i)
		# Some values are lists of dictionary items, sort will fail
		except:
			pass
			print(json.dumps(v, sort_keys=True, indent=4))


			
if __name__ == "__main__":
	main()
