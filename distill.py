#!/usr/local/bin/python3

import csv
from glob import glob
import nmap
import re
import sys
import time

ip_regex = re.compile('\d{1,3}\.' + sys.argv[1] + '\.\d{1,3}\.\d{1,3}')
file_names = sorted((glob("../*-active_IPs.csv")))
y_set = set()
n_dictionary = {}
hostname_dict = {}
output_filename = 'active_IPs-{}.csv'.format(sys.argv[1])

def get_reader(file_name):
	# Remove null bytes for corruption in some files e.g. 2018-08-08
	return csv.reader(x.replace('\0', '') for x in open(file_name))

print ("\nProcessing {}".format(file_names[-1]))

for file_name in file_names:
	file_data = get_reader(file_name)
	n_dictionary[file_name] = set(row[1] for row in file_data if ip_regex.match(row[1]) and row[14] == 'N')

not_checked_in_IPs = set.intersection(*n_dictionary.values())
current_set = n_dictionary[file_names[-1]]
ghost_ips = current_set - not_checked_in_IPs

file_data = get_reader(file_names[-1])
for row in file_data:
	hostname_dict[row[1]] = row[2]

# -sn means it's only a ping scan, not a port scan
nm = nmap.PortScanner()
nm.scan(hosts=' '.join(not_checked_in_IPs), arguments='-sn -n')
hosts_list = [(x, nm[x]['status']) for x in nm.all_hosts()]

unpingable_IPs = not_checked_in_IPs - set(nm.all_hosts())

print ("\nRemoving {} down hosts: {}".format(len(unpingable_IPs), ', '.join(["{} ({})".format(ip, hostname_dict[ip]) for ip in unpingable_IPs])))

file_data = get_reader(file_names[-1])
writer = csv.writer(open(output_filename, 'w'), quoting=csv.QUOTE_ALL)
new_rows = []
for row in file_data:
	#if row[1] in not_checked_in_IPs and row[6] != 'CABLETRON':
	if row[1] in nm.all_hosts() and row[6] != 'CABLETRON':
		new_rows += [[row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[11], row[12], row[13]]]
sorted_new_rows = sorted(new_rows, key=lambda row: row[1])
writer.writerows((sorted_new_rows))

print ("\nRemoving {} hosts for which there was a prior active_IPs list that didn't include it:".format(len(ghost_ips)))

for ip in ghost_ips:
	missing = []
	for file_name in file_names:
		file_data = get_reader(file_name)
		if ip not in n_dictionary[file_name]:
			missing.append(file_name)
	print ("{} ({}) is missing from '{}' and {} others".format(ip, hostname_dict[ip], missing[0][3:], len(missing) - 1 ))

print ("\nWrote {}".format(output_filename))