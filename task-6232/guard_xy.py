
from __future__ import division
import sys
import math
import os
import pygeoip
import StringIO
import stem.descriptor
import socket
import json

from optparse import OptionParser
from binascii import b2a_hex, a2b_base64, a2b_hex
from stem.descriptor.server_descriptor import RelayDescriptor, BridgeDescriptor
from consensus_parser import *

def check_family(path):
  while path:
    relay = path.pop()
    fp = '$'+relay.fingerprint
    nick = relay.nickname
    family = relay.family
    for relay in path:
      for member in relay.family:
        if member == fp or member == nick:
          if ('$'+ relay.fingerprint in family or relay.nickname in family):
            continue
          else:
            return False
  return True

def get_net_address(ipaddress):
	mask = '255.255.0.0'
	anded = []
	for ip, m in zip(ipaddress.split('.'), mask.split('.')):
		anded.append(str(int(ip) & int(m)))
	return '.'.join(anded)

def run(file_name, x_bandwidth):
  routers = []
  router = None
    
  routers, valid_after = parse_consensus(file_name, gi_db, as_db, options.server_desc)

  if len(routers) <= 0:
    return
    
  total_bw = 0
    
  family_routers = []
  map_fingerprint_routers = {} #map nickname to each router object
  map_nick_routers = {} #map fingerprint to each router object
  no_of_subnets = {} #no of different /16 subnets each country have
  total_no_of_subnets = 0
  relay_countries = {} #dict containinig dict of different bandwidth count in a each country
  bw_countries = {} #dict of total bandwidth of each country
    
  for router in routers:
    if not router.bandwidth:
      continue
    total_bw += router.bandwidth

    if router.nickname != "Unnamed":
      map_nick_routers[router.nickname] = router
      map_fingerprint_routers['$'+router.fingerprint] = router
      
    if relay_countries.has_key(router.country):
      bw_countries[router.country] += router.bandwidth
      net_address = get_net_address(router.ip) #returns network address of the given ip
      if not no_of_subnets[router.country].__contains__(net_address):
        no_of_subnets[router.country].append(net_address)
        total_no_of_subnets += 1
      relay_countries[router.country]["total_relays"] += 1
      if relay_countries[router.country].has_key(router.bandwidth):
        relay_countries[router.country][router.bandwidth] += 1
      else:
        relay_countries[router.country][router.bandwidth] = 1 
    else:
      bw_countries[router.country] = router.bandwidth
      no_of_subnets[router.country] = [get_net_address(router.ip)]
      total_no_of_subnets += 1
      relay_countries[router.country] = {router.bandwidth : 1}
      relay_countries[router.country]["total_relays"] = 1         
       
  if total_bw == 0:
    return
  total_prob = math.factorial(total_no_of_subnets) / (math.factorial(total_no_of_subnets - 2) * 2) #total no of /16 subnets in the world
  guard_exit_same_country = {"valid_after" : valid_after} # probability that guard and exit nodes are in the same country
   
  for country in no_of_subnets.keys():
	  if len(no_of_subnets[country]) > 1:
		  guard_exit_same_country[country] = (math.factorial(len(no_of_subnets[country])) / (math.factorial(len(no_of_subnets[country]) - 2) * 2)) / total_prob 

  #filter routers based on family
  for router in routers:
    if router.family:
      family = []
      for member in router.family:
        if member in map_fingerprint_routers.keys():
          family.append(map_fingerprint_routers[member])
        elif member in map_nick_routers.keys():
          family.append(map_nick_routers[member])
      if family and check_family([router] + family):
        family_routers.append(set([router] + family)) 
   
  final = []

  #get unique set of family routers
  for family in family_routers:
  	if family not in final:
  		final.append(family)
  final_family = [list(f) for f in final]
  family_total_bw = 0
  family_controlled_bw = []

  #adding the bandwidth of all relays in a family for calculating the entropy of nodes based on family
  for member in final_family:
   	#print [f.fingerprint for f in member]
    family_bandwidth = 0
    for f in member: 
      family_bandwidth += f.bandwidth
    family_controlled_bw.append(family_bandwidth)
    family_total_bw += family_bandwidth
  entropy_family = 0.0		

  for member in family_controlled_bw:
    p = float(member) / float(family_total_bw)
    if p != 0:
      entropy_family += -(p * math.log(p,2))
  maximum_entropy = math.log(len(family_controlled_bw),2)
    
  #cutoff bandwidth is the X% of a country's total bandwidth.I have sorted the relays in each countries based on their bandwidth    
  #i am finding out the how much % of relays in each country can control 50% of each country's total bandwidth
    
  xy_percentage = {"valid_after" : valid_after}
  for country in relay_countries.keys():
    cutoff_bandwidth = bw_countries[country] * (int(x_bandwidth) / 100)
    no_of_routers = 0
    temp_bandwidth_cutoff = 0
    total_relays = relay_countries[country]["total_relays"]
    del relay_countries[country]["total_relays"]
    for key in sorted(relay_countries[country], reverse = True):
      if temp_bandwidth_cutoff < cutoff_bandwidth:
        temp_bandwidth_cutoff += relay_countries[country][key] * key
        no_of_routers += relay_countries[country][key]
      else:
        xy_percentage[country] = float(no_of_routers)/total_relays * 100
        break 
   
  return (xy_percentage, guard_exit_same_country, ",".join([valid_after,str(entropy_family), str(maximum_entropy)]))
    
def parse_args():
  usage = "Usage - python pyentropy.py [options]"
  parser = OptionParser(usage)
    
  parser.add_option("-g", "--geoip", dest="gi_db", default="GeoIP.dat", 
                      help="Input GeoIP database")
  parser.add_option("-a", "--as", dest="as_db", default="GeoIPASNum.dat",
                      help="Input AS GeoIP database")
  parser.add_option("-s", "--server_desc", dest="server_desc",
                      default="data/relay-descriptors/server-descriptors/", help="Server descriptors directory")
  parser.add_option("-o", "--output", dest="output", default="entropy.csv",
                      help="Output filename")
  parser.add_option("-c", "--consensus", dest="consensus", default="in/consensus",
                      help="Input consensus dir")
    
  (options, args) = parser.parse_args()
    
  return options

if __name__ == "__main__":
  options = parse_args()
  gi_db = pygeoip.GeoIP(options.gi_db)
  as_db = pygeoip.GeoIP(options.as_db)
  print "\npercentage of routers that control X% of each country's total bandwidth\n"
  x_bandwidth = raw_input("Please enter the value for X%") 
  with open("xy_percentage.json","w") as f1, open("guard_exit.json","w") as f2, open("entropy_family.csv","w") as f3:
    for file_name in os.listdir(options.consensus):
      xy_percentage, guard_exit_same_country, entropy_family = run(os.path.join(options.consensus, file_name), x_bandwidth)
      json.dump(xy_percentage, f1)
      json.dump(guard_exit_same_country, f2)
      f1.write("\n")
      f2.write("\n")	
      f3.write(entropy_family+"\n")
	      
             
