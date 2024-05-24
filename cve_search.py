#!/usr/bin/env python3
"""
This script will search the RHT CVE database
Return the RHSA and other information
"""

import argparse
import re
import sys
import requests

ARGS = None

def process_arguments():
  """
  Process the command line arguments
  """
  global ARGS
  parser = argparse.ArgumentParser(formatter_class = argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument(
            "--cve", type = str,
            help = "CVE number to search for",
            default = 'CVE-2023-0286',
            required = False)
  parser.add_argument(
            "--debug", action = "store_true",
            help = "Enable Debug",
            default = False,
            required = False)
  ARGS = parser.parse_args()

def get_cve( cve = "", debug = False):
  """
  Inputs:
    cve: a CVE identifier
    debug: True/False
  Returns:
    json data    
  """
  url = "https://access.redhat.com/hydra/rest/securitydata/cve/"
  if debug:
    print(f"Retrieving information about {cve}")
#Example GET /cve/<CVE>.json
  query = url+cve
  if debug:
    print(f"Query url {query}")

  r = requests.get(query, timeout=30)

  if r.status_code != 200:
    print(f'ERROR: Invalid request; returned {r.status_code} for the following '
          'query:\n{query}')
    sys.exit(1)

  if not r.json():
    print('No data returned with the following query:')
    print(query)
    sys.exit(0)

  return r.json()

def main():
  """
  Here is the main entry point
  """
  match_str = "^Red Hat Enterprise Linux [789]$"
  process_arguments()

  if ARGS.cve:
    ret_str = get_cve( cve = ARGS.cve, debug = ARGS.debug )
    #print(f"{ret_str}")
    #print(ret_str["statement"])
    if ret_str["affected_release"]:
      print("release;package;advisory")
      for release in ret_str["affected_release"]:
        if re.search(match_str, release["product_name"]):
          print(f"{release["product_name"]};{release["package"]};{release["advisory"]}")
      print("no;more;entries")
    else:
      print(f"No impacts for {ARGS.cve}")


  sys.exit(0)

if __name__ == "__main__":
  main()
