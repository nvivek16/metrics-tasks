from stem.descriptor.server_descriptor import RelayDescriptor, BridgeDescriptor
import sys
import math
import os
import pygeoip
import StringIO
import stem.descriptor

from binascii import b2a_hex, a2b_base64, a2b_hex


class Router:
    def __init__(self, gi_db, as_db):
        self.bandwidth = None
        self.advertised_bw = None
        self.country = None
        self.gi_db = gi_db
        self.as_db = as_db
        self.as_no = None
        self.is_exit = None
        self.is_guard = None
        self.family = None
	self.fingerprint = None
	self.nickname = None
	self.ip = None
    
    def add_router_info(self, values, server_desc):
           hex_digest = b2a_hex(a2b_base64(values[2]+"="))
           self.advertised_bw, self.family, self.fingerprint, self.nickname = self.get_advertised_bw(hex_digest, server_desc)
           self.ip = values[5]
           self.country = self.gi_db.country_code_by_addr(self.ip)
           self.as_no = self.get_as_details(self.ip)

    def add_weights(self, values):
           self.bandwidth = int(values[0].split('=')[1])

    def add_flags(self, values):
           if "Exit" in values and not "BadExit" in values:
               self.is_exit = True
           if "Guard" in values:
               self.is_guard = True
 
    def get_as_details(self, ip):
        try:
            value = self.as_db.org_by_addr(str(ip)).split()
            return value[0]
        except:
            return ""
    
    def get_advertised_bw(self, hex_digest, server_desc):
        try:
            with open(server_desc+hex_digest) as f:
                data = f.read()
                
            desc_iter = stem.descriptor.server_descriptor._parse_file(StringIO.StringIO(data))
            desc_entries = list(desc_iter)
            desc = desc_entries[0]
            return (min(desc.average_bandwidth, desc.burst_bandwidth, desc.observed_bandwidth),desc.family,desc.fingerprint.upper(),desc.nickname)
        except TypeError as e:
	    print e
            return (0,[None, None, None])

def parse_bw_weights(values):
    data = {}
    try:
        for value in values:
            key, value = value.split("=")
            data[key] = float(value) / 10000
        return data
    except:
        return None

def parse_consensus(file_name, gi_db, as_db, server_desc):
    routers = []
    with open(file_name, 'r') as f:
        for line in f.readlines():
            key = line.split()[0]
            values = line.split()[1:]
            if key =='r':
                router = Router(gi_db, as_db)
                routers.append(router)
                router.add_router_info(values, server_desc)
            elif key == 's':
                router.add_flags(values)
            elif key == 'w':
                router.add_weights(values)
            elif key == 'valid-after':
                valid_after = ' '.join(values)
            elif key == 'bandwidth-weights':
                data = parse_bw_weights(values)
                try: 
                    Wed = data['Wed']
                    Wee = data['Wee']
                    Wgd = data['Wgd']
                    Wgg = data['Wgg']
                except:
                    pass
    return (routers, valid_after)
