#!/usr/bin/env python 

import os
import sys
import shutil 
import subprocess
import argparse
import yaml

def make_racoon_header( file_obj = sys.stdout ):
  file_obj.write( '# Racoon IKE daemon configuration file.\n#\n' )
  file_obj.write( 'log notify;\n' )
  file_obj.write( 'path certificate "/etc/racoon/certs";\n\n' )


def make_racoon_remote( file_obj, host_ip, host_name, peer_ip, peer_name ):
  file_obj.write( 'remote %s\n{\n' % peer_ip )
  file_obj.write( '  exchange_mode main;\n' )
  file_obj.write( '  lifetime time 12 hour;\n' )
  file_obj.write( '  certificate_type plain_rsa "%s";\n' % host_name )
  file_obj.write( '  peers_certfile plain_rsa "%s.pub";\n' % peer_name )
  file_obj.write( '  verify_cert off;\n' )
  file_obj.write( '  proposal {\n' )
  file_obj.write( '    encryption_algorithm 3des;\n' )
  file_obj.write( '    hash_algorithm sha256;\n' )
  file_obj.write( '    authentication_method rsasig;\n' )
  file_obj.write( '    dh_group modp1024;\n' )
  file_obj.write( '  }\n' )
  file_obj.write( '  generate_policy off;\n' )
  file_obj.write( '}\n\n' )


def make_racoon_sainfo( file_obj ):
  file_obj.write( 'sainfo anonymous\n' )
  file_obj.write( '{\n' )
  file_obj.write( '	pfs_group modp1024;\n' )
  file_obj.write( '	encryption_algorithm 3des;\n' )
  file_obj.write( '	authentication_algorithm hmac_sha256;\n' )
  file_obj.write( '	compression_algorithm deflate;\n' )
  file_obj.write( '}\n' )


def make_setkey_header( file_obj ):
  file_obj.write( '#!/usr/sbin/setkey -f\n#\n\n' )
  file_obj.write( 'flush;\n' )
  file_obj.write( 'spdflush;\n\n' )


def make_setkey_spd( file_obj, host_ip, peer_ip, val ):
  file_obj.write( 'spdadd %s %s any -P %s ipsec\n' % ( host_ip, peer_ip, val ) )
  file_obj.write( '\tesp/transport//require\n' )
  file_obj.write( '\tah/transport//require;\n\n' )


def make_iptables_rules( file_obj, allowed_ip_addresses ):
  file_obj.write( '*filter\n' )
  file_obj.write( ':INPUT DROP [0:0]\n' )
  file_obj.write( ':FORWARD DROP [0:0]\n' )
  file_obj.write( ':OUTPUT ACCEPT [0:0]\n' )
  file_obj.write( '-A INPUT -i lo -j ACCEPT\n' )
  for ip in allowed_ip_addresses:
      file_obj.write( '-A INPUT -s %s -j ACCEPT\n' % ip )
  file_obj.write( 'COMMIT\n' )

def make_iptablesload_script( filename ):
  if not os.path.exists( os.path.dirname( filename ) ): 
    os.makedirs( os.path.dirname( filename ) )
  with open( filename, "w" ) as file_obj:
    file_obj.write( '#!/bin/sh\n' )
    file_obj.write( 'iptables-restore < /etc/iptables.rules\n' )
    file_obj.write( 'exit 0\n' )



def make_racoon_conf( filename, host_name, hosts ):
  """ hosts is a dict of {hostname: ip_address}
  """
  if not os.path.exists( os.path.dirname( filename ) ): 
    os.makedirs( os.path.dirname( filename ) )
  with open( filename, "w" ) as f:
    make_racoon_header( f )
    peers = set( hosts.keys() ) - set( [host_name] )
    h = hosts[host_name]
    for peer_name in peers:
      p = hosts[peer_name]
      make_racoon_remote( f, h["ip_address"], host_name, p["ip_address"], peer_name )
    make_racoon_sainfo( f )



def make_setkey_conf( filename, host_name, hosts ):
  if not os.path.exists( os.path.dirname( filename ) ): 
    os.makedirs( os.path.dirname( filename ) )
  with open( filename, "w" ) as f:
    make_setkey_header( f )
    peers = set( hosts.keys() ) - set( [host_name] )
    h = hosts[host_name]
    for peer_name in peers:
      p = hosts[peer_name]
      make_setkey_spd( f, h["ip_address"], p["ip_address"], 'out' )
      make_setkey_spd( f, p["ip_address"], h["ip_address"], 'in' )
    


def make_iptables_conf( filename, host_name, hosts, allowed_ip_addresses ):
  if not os.path.exists( os.path.dirname( filename ) ): 
    os.makedirs( os.path.dirname( filename ) )
  with open( filename, "w" ) as f:
    peers = set( hosts.keys() ) - set( [host_name] )
    peer_ip_addresses = list( hosts[p]["ip_address"] for p in peers ) 
    make_iptables_rules( f, allowed_ip_addresses + peer_ip_addresses )
    
 
def make_config( doc, hostname, allowed_ip_addresses = [] ):
  if hostname in doc.keys():
    racoon_conf = '/etc/racoon/racoon.conf'
    print( 'Writing to %s' % racoon_conf )
    make_racoon_conf( racoon_conf, hostname, doc )

    setkey_conf = '/etc/ipsec-tools.conf'
    print( 'Writing to %s' % setkey_conf )
    make_setkey_conf( setkey_conf, hostname, doc )



def make_iptables_config( doc, hostname, allowed_ip_addresses = [] ):
  if hostname in doc.keys():
    iptables_conf = '/etc/iptables.rules'
    print( 'Writing to %s' % iptables_conf )
    make_iptables_conf( iptables_conf, hostname, doc, allowed_ip_addresses )

    iptablesload_script = '/etc/network/if-pre-up.d/iptablesload'
    print( 'Writing to %s' % iptablesload_script )
    make_iptablesload_script( iptablesload_script )


def convert_yaml( doc, filename ):
  doc2 = dict()
  for h in doc.keys():
    doc2[h] = {"ip_address":doc[h], "host_name": h}
  with open( filename, "w" ) as f:
    f.write( yaml.dump( doc2, default_flow_style = False ) )
  return doc2



if __name__ == "__main__":
  parser = argparse.ArgumentParser( description = "Tool to create IPSec and iptables configuration files" )
  parser.add_argument( "-A", default = ["10.0.2.2"], nargs = "*",
      metavar = "IP_ADDRESSES", dest = "allowed_ip_addresses",
      help = "Allowed IP addresses" )
  parser.add_argument( "hostname", metavar = "HOSTNAME", help = "hostname" )
  parser.add_argument( "input", metavar = "IPSEC", help = "IPSec configuration as a YAML string" )
  args = parser.parse_args()

  with open( args.input ) as istream:
    doc1 = yaml.load( istream )
    doc2 = convert_yaml( doc1, "/home/vagrant/ipsec.yaml" )

  make_config( doc2, hostname = args.hostname)
  make_iptables_config( doc2, hostname = args.hostname, allowed_ip_addresses = args.allowed_ip_addresses )




