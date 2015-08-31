# Replace with your session ID for tickets.events.ccc.de
SESSIONID=""
url='https://access.redhat.com/security/cve/'
cves=['CVE-2012-2150']

# Imports
import sys
import argparse
from datetime import date
import fileinput
if (sys.version_info > (3, 0)):
  import urllib.request
else:
  import urllib
import re
import time

def main():
  description='''Queries the RedHat advisories to see if CVEs apply'''
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument('cve', metavar='cve', type=str, help='CVEs to check against', nargs="?" )
  args = parser.parse_args()

  if args.cve:
    cves=[x.strip() for x in args.cve.split(",")]
  else:
    # Read from stdin
    cves=[]
    for line in fileinput.input(): cves.append(line.strip())

  try:
    for cve in cves:
      cve=cve.upper()
      if re.match("CVE-\d\d\d\d-\d\d\d\d\d?", cve):
        search=cve
      elif re.match("\d\d\d\d-\d\d\d\d\d?", cve):
        search="CVE-%s"%cve
      elif re.match("\d\d\d\d\d?", cve):
        search="CVE-%s-%s"%(date.today().year, cve)
      try:
        if (sys.version_info > (3, 0)):
          f = str(urllib.request.urlopen(url+search).read(),"utf-8")
        else:
          f = urllib.urlopen(url+search).read()
        if "<th>Impact:</th>" in f:
          print("[+] %s - Applicable"%search)
        elif '<h1>CVE not found</h1>' in f:
          print("[-] %s - N/A"%search)
      except KeyboardInterrupt:
        sys.exit(0)
  except IOError:
    print("Could not fetch the info. Are you connected to the Internet?")
