#!/usr/local/bin/python3

import csv
from glob import glob
import re
import time
import sys

ip_regex = re.compile('\d{1,3}\.' + sys.argv[1] + '\.\d{1,3}\.\d{1,3}')
file_names = sorted((glob("../*-active_IPs.csv")))
y_set = set()
#current_set = set()
n_dictionary = {}

def get_reader(file_name):
	# Remove null bytes for corruption in some files e.g. 2018-08-08
	return csv.reader(x.replace('\0', '') for x in open(file_name))

for file_name in file_names:
	file_data = get_reader(file_name)
	n_dictionary[file_name] = set(row[1] for row in file_data if ip_regex.match(row[1]) and row[14] == 'N')

not_checked_in_IPs = set.intersection(*n_dictionary.values())

#for IP in n_dictionary[file_names[-1]]:
	#current_set.add(IP)
current_set = n_dictionary[file_names[-1]]

ghost_ips = current_set - not_checked_in_IPs
print (len(ghost_ips))

for ip in ghost_ips:
	missing = []
	for file_name in file_names:
		file_data = get_reader(file_name)
		if ip not in n_dictionary[file_name]:
			missing.append(file_name)
	print (ip + " is missing from '" + missing[0] + "' and " + str(len(missing) - 1 )  + " others")

print (len(not_checked_in_IPs))