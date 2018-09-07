#!/usr/local/bin/python3

import csv
from glob import glob
import json
import nmap
import os
from fpdf import FPDF
import multiprocessing
import pprint
import re
import selenium.webdriver as webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import sys
import time

if os.geteuid() != 0:
	exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

pp = pprint.PrettyPrinter(indent=4)
nmap_cache_filename = 'nmap_cache.json'
ip_regex = re.compile('\d{1,3}\.' + sys.argv[1] + '\.\d{1,3}\.\d{1,3}')
subnet_regex = re.compile('18.' + sys.argv[1])
file_names = sorted((glob("../*-active_IPs.csv")))
y_set = set()
n_dictionary = {}
n_files = {}
output_filename = 'active_IPs-{}.csv'.format(sys.argv[1])
triage = [[], [], [], [], [], []]

hostname_dict = {}
web_interface_dict = {}

## Remove duplicate files
last = None
removed_files_tally = 0
for file_name in list(file_names):  # list() because we're removing from file_names as we go
	with open(file_name) as raw_file:
		file = raw_file.read()
	if file == last:
		removed_files_tally += 1
		file_names.remove(file_name)
	last = file
## ---------------------

try:
	with open (nmap_cache_filename) as nmap_cache_file:
		nmap_cache = json.loads(nmap_cache_file.read())
except (IOError, ValueError) as e:
	nmap_cache = {}

print ("nmap_cache has {} entries".format(len(nmap_cache)))

def get_reader(file_name):
	# Remove null bytes for corruption in some files e.g. 2018-08-08
	file = (x.replace('\0','') for x in open(file_name))
	# Skip until table for specified subnet
	any (e.startswith('18.' + sys.argv[1]) for e in file)
	reader = csv.DictReader(file)
	# Create list of relevant dicts
	dict_list = [row for row in reader if 
		ip_regex.match(row['Address']) and
		row['Vendor'] != 'CABLETRON' and
		not row['Hostname'].startswith('CD-') and
		not row['Contact'] == 'cdrennan@MIT.EDU' and
		not row['Location'] == '68-171' and
		not row['Location'].startswith('68-588') and
		not row['Hostname'].startswith('AV-')]
	return dict_list

print('Processing {} unique files out of {} files.'.format(len(file_names), len(file_names) + removed_files_tally), end='', flush=True)

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
nm1 = nmap.PortScanner()
version = nm1.nmap_version()
print ("Using nmap {}.{}".format(version[0], version[1]))
nm1.scan(hosts=' '.join(current_set), arguments='-sn -n')
pingable_IPs = set(nm1.all_hosts())

print ('Scanning {} hosts'.format(len(pingable_IPs)))
nm2 = nmap.PortScannerAsync()
nmap_tally = 0

def callback(host, scan_result):
	global nmap_tally, nmap_cache, web_interface_dict
	nmap_tally += 1
	print ('\r{}/{}'.format(nmap_tally, len(pingable_IPs)), end='', flush=True)
	scan = scan_result.get('scan')
	host_info = scan.get(host)
	print (host_info)
	match = host_info.get('osmatch')
	if match:
		nmap_cache[host] = match[0]['name']
		with open (nmap_cache_filename, 'w') as nmap_cache_file:
			json.dump(nmap_cache, nmap_cache_file)
	tcp = scan_result['scan'][host].get('tcp')
	if tcp and 80 in tcp.keys():
		web_interface_dict[host] = True
	else:
		web_interface_dict[host] = False

hosts_to_scan = pingable_IPs - set(nmap_cache.keys())
print (' '.join(pingable_IPs - set(nmap_cache.keys())))
nm2.scan(hosts=' '.join(pingable_IPs - set(nmap_cache.keys())), arguments='-O -n', callback=callback)

while nm2.still_scanning():
	print('.', end='', flush=True)
	nm2.wait(2)

print (web_interface_dict)

hosts_to_scan = pingable_IPs
nm3 = nmap.PortScannerAsync()

options = webdriver.ChromeOptions()
options.add_argument('headless')
#options.add_argument("--window-size=800,325")
options.add_argument("--window-size=1224,490")

desired_capabilities = {"acceptInsecureCerts": True}
driver = webdriver.Chrome(chrome_options=options, desired_capabilities=desired_capabilities)
#driver.implicitly_wait(2)
png_names = multiprocessing.Manager().list()
pdf = FPDF(format='letter')
pdf.set_font('Arial','',10)

def callback3(host, scan_result):
	tcp = scan_result['scan'][host].get('tcp')
	if tcp and 80 in tcp.keys() and tcp[80]['state'] == 'open':
		print ("found webpage for {}".format(host))
		driver.get('http://{}'.format(host))
		try:
			alert = driver.switch_to_alert()
			alert.dismiss()
		except Exception:
			pass
		#time.sleep(2)
		png_name = '{}.png'.format(host)
		driver.get_screenshot_as_file(png_name)
		png_names.append(png_name)

print (hosts_to_scan)
nm3.scan(hosts=' '.join(hosts_to_scan), arguments='-n -Pn -p 80', callback=callback3)
while nm3.still_scanning():
	print('.', end='', flush=True)
	nm3.wait(1)

driver.quit()

for i, name in enumerate(png_names):
	if i % 3 == 0:
		print ('resetting')
		pdf.add_page()
	else:
		pdf.line(0, pdf.get_y(), 215, pdf.get_y())
		pdf.set_y(pdf.get_y() + 3)
	pdf.write(0, '{} / {}\n'.format(hostname_dict[name[:-4]], name[:-4]))
	pdf.set_y(pdf.get_y() + 3)
	pdf.image(name, w=195)

pdf.output("pages.pdf", "F")

def add_row_to_list (row, level):
	address = row['Address']
	up = 'Host down' if address not in pingable_IPs else 'Host up'
	checked = 'Never checked in' if address in never_checked_in_IPs else 'Has checked in' if address in y_set else 'May have checked in'
	triage[level] += [list(row.values())[1:-4] + [up, checked, nmap_cache.get(address,'')] ]

for row in current_file_data:
	address = row['Address']
	pingable = 0 if address in pingable_IPs else 3
	if address in never_checked_in_IPs:
		add_row_to_list(row, 0 + pingable)
	elif address not in y_set:
		#pass
		add_row_to_list(row, 1 + pingable)
	else:
		#pass
		add_row_to_list(row, 2 + pingable)

for level in triage:
	level.sort(key=lambda row: row[1])

rows = [item for sublist in triage for item in sublist]
writer = csv.writer(open(output_filename, 'w'), quoting=csv.QUOTE_ALL)
writer.writerows(rows)

#print ("\nRemoving {} hosts for which there was a prior active_IPs list that didn't include it:".format(len(ghost_ips)))

for ip in ghost_ips:
	missing = []
	for file_name in file_names:
		if ip not in n_dictionary[file_name]:
			missing.append(file_name)
			#print (file_name)
	print ("{} ({}) is missing from '{}' and {} others".format(ip, hostname_dict[ip], missing[0][3:], len(missing) - 1 ))
print ("\nWrote {}".format(output_filename))