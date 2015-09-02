#!/usr/bin/env python3
#
# Script that automatically checks the RedHat security advisories to see if a CVE applies
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

url='https://access.redhat.com/security/cve/'

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

def getContentOf(data, key, keyEncapsulation, valueEncapsulation):
  lookFor="<%s>%s</%s>"%(keyEncapsulation, key, keyEncapsulation)
  start=data[data.index(lookFor)+len(lookFor):]
  value=start[:start.index("</%s>"%valueEncapsulation)].replace("<%s>"%valueEncapsulation, "")
  return value.strip()

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
          impact=getContentOf(f, "Impact:", "th", "td")
          impact=impact[impact.index(">")+1:]
          impact=impact[:impact.index("<")]
          print("[+] %s - %s"%(search, impact))
          if "<h2>Statement</h2>" in f:
            print(" * %s"%getContentOf(f, "Statement", "h2", "p").replace("<br />", "\n * "))
        elif '<h1>CVE not found</h1>' in f:
          print("[-] %s - N/A"%search)
      except KeyboardInterrupt:
        sys.exit(0)
  except IOError:
    print("Could not fetch the info. Are you connected to the Internet?")
