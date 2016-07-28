#!/usr/bin/env python 

import os
import sys
import shutil 
import subprocess
import argparse
import glob
#import yaml

def get_ip_address( folder, output_file ):
  """ Gather ip address from yaml files into a single YAML file
  """
  if not os.path.exists( os.path.dirname( output_file ) ):
    os.makedirs( os.path.dirname( output_file ) )

  with open( output_file, "w" ) as ostream:
    for f in glob.glob( "%s/*.yaml" % folder ):
      print( "Loading %s" % f )
      with open( f, "r") as istream:
        for line in istream.readlines():
          ostream.write( line )


if __name__ == "__main__":
  parser = argparse.ArgumentParser( description = "Tool to create ip_addresses.yaml file" )
  parser.add_argument( "folder", metavar = "CONFIG", default = "config/ip_address",
      help = "Configuration folder" )
  parser.add_argument( "-o", "--output", metavar = "OUTPUT", default = "config/ip_addresses.yaml",
      help = "Output YAML configuration file" )
  args = parser.parse_args()

  get_ip_address( args.folder, args.output )

