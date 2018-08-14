#!/usr/local/bin/python3

import csv
from glob import glob
import re
import sys

ip_regex = re.compile('\d{1,3}\.' + sys.argv[1] + '\.\d{1,3}\.\d{1,3}')
file_names = sorted((glob("*-active_IPs.csv")))
n_sets = []
y_set = set()
current_set = set()

for file_name in file_names:
	# Remove null bytes for corruption in some files e.g. 2018-08-08
	file_data = csv.reader(x.replace('\0', '') for x in open(file_name))
	n_set = set()

	for IP in [row[1] for row in file_data if ip_regex.match(row[1]) and row[14] == 'N']:
		n_set.add(IP)
	n_sets.append(n_set)

not_checked_in_IPs = set.intersection(*n_sets)

file_data = csv.reader(x.replace('\0', '') for x in open(file_names[-1]))
for IP in [row[1] for row in file_data if ip_regex.match(row[1]) and row[14] == 'N']:
	current_set.add(IP)

ghost_ips = current_set - not_checked_in_IPs
print (len(ghost_ips))

for ip in ghost_ips:
	missing = []
	for file_name in file_names:
		file_data = csv.reader(x.replace('\0', '') for x in open(file_name))
		if ip not in [row[1] for row in file_data if ip_regex.match(row[1]) and row[14] == 'N']:
			missing.append(file_name)
	print (ip + " is missing from '" + missing[0] + "' and " + str(len(missing) - 1 )  + " others")

print (len(not_checked_in_IPs))