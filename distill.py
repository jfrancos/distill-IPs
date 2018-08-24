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
current_file_name = file_names[-1]
y_set = set()
n_dictionary = {}
n_files = {}
hostname_dict = {}
output_filename = 'active_IPs-{}.csv'.format(sys.argv[1])
triage = [[], [], [], [], [], []]

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
	# Create list of relevant dicts
	dict_list = [row for row in reader if 
		ip_regex.match(row['Address']) and
		row['Vendor'] != 'CABLETRON' and
		not row['Hostname'].startswith('AV-')]
	return dict_list

print('Processing {} past files.'.format(len(file_names) - 1), end='', flush=True)

# Creates a { filename -> set-of-ips dictionary, ... }, where all ips in the dictionaries match argv[1] and have 'N' for DHCP check-in
for file_name in file_names:
	print('.', end='', flush=True)
	file_data = get_reader(file_name)
	n_files[file_name] = [row for row in file_data if row['DHCP Check-in'] == 'N']
	n_dictionary[file_name] = set(row['Address'] for row in n_files[file_name])
	y_set |= set([row['Address'] for row in file_data if row['DHCP Check-in'] == 'Y'])

never_checked_in_IPs = set.intersection(*n_dictionary.values())
current_set = n_dictionary[file_names[-1]]
ghost_ips = current_set - never_checked_in_IPs
current_file_data = n_files[file_names[-1]]

print ('\nCurrent file: {} has {} rows'.format(file_names[-1], len(current_set)))

for row in current_file_data:
	hostname_dict[row['Address']] = row['Hostname']

# -sn means it's only a ping scan, not a port scan
nm = nmap.PortScanner()
nm.scan(hosts=' '.join(current_set), arguments='-sn -n')
pingable_IPs = set(nm.all_hosts())

def add_row_to_list (row, level):
	up = 'Host down' if address not in pingable_IPs else 'Host up'
	checked = 'Never checked in' if address in never_checked_in_IPs else 'Has checked in' if address in y_set else 'May have checked in'
	triage[level] += [list(row.values())[1:-4] + [up, checked] ]

for row in current_file_data:
	address = row['Address']
	pingable = 0 if address in pingable_IPs else 3
	if address in never_checked_in_IPs:
		add_row_to_list(row, 0 + pingable)
	elif address not in y_set:
		add_row_to_list(row, 1 + pingable)
	else:
		add_row_to_list(row, 2 + pingable)

for level in triage:
	level.sort(key=lambda row: row[1])

rows = [item for sublist in triage for item in sublist]
writer = csv.writer(open(output_filename, 'w'), quoting=csv.QUOTE_ALL)
writer.writerows(rows)

print ("\nRemoving {} hosts for which there was a prior active_IPs list that didn't include it:".format(len(ghost_ips)))

for ip in ghost_ips:
	missing = []
	for file_name in file_names:
		if ip not in n_dictionary[file_name]:
			missing.append(file_name)
	print ("{} ({}) is missing from '{}' and {} others".format(ip, hostname_dict[ip], missing[0][3:], len(missing) - 1 ))

print ("\nWrote {}".format(output_filename))