#!/usr/local/bin/python3

import csv
from glob import glob
import nmap
import re
import sys
import time

ip_regex = re.compile('\d{1,3}\.' + sys.argv[1] + '\.\d{1,3}\.\d{1,3}')
subnet_regex = re.compile('18.' + sys.argv[1])
file_names = sorted((glob("../*-active_IPs.csv")))
y_set = set()
n_dictionary = {}
hostname_dict = {}
output_filename = 'active_IPs-{}.csv'.format(sys.argv[1])

def get_reader(file_name):
	# Remove null bytes for corruption in some files e.g. 2018-08-08
	file = (x.replace('\0','') for x in open(file_name))
	# Skip first line so first line has correct number of column headers
	next(file)
	reader = csv.DictReader(file)
	# Find beginning of specified subnet
	any (subnet_regex.match(list(e.values())[0]) for e in reader)
	# Update column headers - don't want to assume they are the same as top of file
	reader.fieldnames = list(next(reader).values())
	return reader

print ("\nCurrent file: {}".format(file_names[-1]))
print('Processing {} past files.'.format(len(file_names) - 1), end='', flush=True)

# Creates a { filename -> set-of-ips dictionary, ... }, where all ips in the dictionaries match argv[1] and have 'N' for DHCP check-in
for file_name in file_names:
	print('.', end='', flush=True)
	file_data = get_reader(file_name)
	n_dictionary[file_name] = set(row['Address'] for row in file_data if ip_regex.match(row['Address']) and row['DHCP Check-in'] == 'N')

never_checked_in_IPs = set.intersection(*n_dictionary.values())
current_set = n_dictionary[file_names[-1]]
ghost_ips = current_set - never_checked_in_IPs
current_file_data = list(get_reader(file_names[-1]))
current_IPs = [row['Address'] for row in current_file_data if ip_regex.match(row['Address']) and row['DHCP Check-in'] == 'N']

for row in current_file_data:
	hostname_dict[row['Address']] = row['Hostname']

# -sn means it's only a ping scan, not a port scan
nm = nmap.PortScanner()
nm.scan(hosts=' '.join(current_IPs), arguments='-sn -n')
hosts_list = [(x, nm[x]['status']) for x in nm.all_hosts()]

unpingable_IPs = set(current_IPs) - set(nm.all_hosts())
print (len(current_IPs))
print ("\nRemoving {} down hosts: {}".format(len(unpingable_IPs), ', '.join(["{} ({})".format(ip, hostname_dict[ip]) for ip in unpingable_IPs])))

#file_data = get_reader(file_names[-1])
writer = csv.writer(open(output_filename, 'w'), quoting=csv.QUOTE_ALL)
triage0_rows = []
triage1_rows = []
for row in [row for row in current_file_data if row['Address'] in current_IPs]:
	#if row[1] in never_checked_in_IPs and row[6] != 'CABLETRON':
	if row['Address'] not in unpingable_IPs and row['Address'] in never_checked_in_IPs and row['Vendor'] != 'CABLETRON':
		triage0_rows += [list(row.values())[1:-4] + ['Host up', 'Never checked in'] ]
	elif row['Vendor'] != 'CABLETRON':
		up = 'Host down' if row['Address'] in unpingable_IPs else 'Host up'
		checked = 'Never checked in' if row['Address'] in never_checked_in_IPs else 'May have checked in'
		triage1_rows += [list(row.values())[1:-4] + [up, checked] ]
sorted_triage0_rows = sorted(triage0_rows, key=lambda row: row[1])
sorted_triage1_rows = sorted(triage1_rows, key=lambda row: row[1])
writer.writerows(sorted_triage0_rows + sorted_triage1_rows)

print ("\nRemoving {} hosts for which there was a prior active_IPs list that didn't include it:".format(len(ghost_ips)))

for ip in ghost_ips:
	missing = []
	for file_name in file_names:
		if ip not in n_dictionary[file_name]:
			missing.append(file_name)
	print ("{} ({}) is missing from '{}' and {} others".format(ip, hostname_dict[ip], missing[0][3:], len(missing) - 1 ))

print ("\nWrote {}".format(output_filename))