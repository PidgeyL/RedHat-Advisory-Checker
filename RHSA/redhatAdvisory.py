#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tool to query the RedHat Security Advisories to see if CVEs apply
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Variables
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
  k = value.rfind(">")
  value = value[k+1:]
  return value.strip()

def fetchURL(cve):
  if (sys.version_info > (3, 0)):
    return str(urllib.request.urlopen(url+cve).read(),"utf-8")
  else:
    return urllib.urlopen(url+cve).read()

def main():
  description='''Queries the RedHat advisories to see if CVEs apply'''
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument('cve', metavar='cve', type=str, help='CVEs to check against', nargs="?" )
  args = parser.parse_args()

  # Get CVEs
  if args.cve:
    cves=[x.strip() for x in args.cve.split(",")]
  else:
    # Read from stdin
    cves=[]
    for line in fileinput.input(): cves.append(line.strip())
  # Process CVEs
  try:
    for cve in cves:
      cve=cve.upper()
      # Check CVE & autofill
      if re.match("CVE-\d\d\d\d-\d\d\d\d\d?", cve): search=cve
      elif re.match("\d\d\d\d-\d\d\d\d\d?", cve):   search="CVE-%s"%cve
      elif re.match("\d\d\d\d\d?", cve):            search="CVE-%s-%s"%(date.today().year, cve)
      else:
        print("Invalid CVE: " + cve)
        continue
      # Fetch & parse
      try:
        f = fetchURL(search)
        if "<th>impact:</th>" in f.lower():         print("[+] %s - %s"%(search, getContentOf(f, "Impact:", "th", "td")))
        elif "<dt>impact:</dt>" in f.lower():       print("[+] %s - %s"%(search, getContentOf(f, "Impact:", "dt", "span")))
        # Statements
        if "<h2>statement</h2>" in f.lower():       print(" * %s"%getContentOf(f, "Statement", "h2", "p").replace("<br />", "\n * "))
        elif '<h1>cve not found</h1>' in f.lower(): print("[-] %s - N/A"%search)
        elif '<title>page not found' in f.lower():  print("[-] %s - N/A"%search)
      except urllib.error.HTTPError as err:
        if err.code == 404:
          print("[-] %s - N/A"%search)
        else:
          print("Fetch error: %s"%err)
  except KeyboardInterrupt:
    print("Process interrupted by user")
    sys.exit(0)
  except IOError as e:
    print("Could not fetch the info. Are you connected to the Internet?")
