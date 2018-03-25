#!/usr/bin/env python3
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Try REDOS attack on Python3

import sys
import json
import re

def main():
  # Arg parsing.
  if len(sys.argv) != 2:
    print("Error, usage: {} query-file.json".format(sys.argv[0]))
    sys.exit(1)

  queryFile = sys.argv[1]

  with open(queryFile, 'r') as FH:
    obj = json.load(FH)

  # Prepare a regexp
  regexp = re.compile(obj['pattern'])

  # Compose queryString
  queryString = ''
  for pumpPair in obj['evilInput']['pumpPairs']:
    queryString += pumpPair['prefix']
    for i in range(1, 1 + int(obj['nPumps'])):
      queryString += pumpPair['pump']
  queryString += obj['evilInput']['suffix']

  # Try a match
  log("matching: pattern /{}/ nPumps {} queryString {}".format(obj['pattern'], obj['nPumps'], queryString))
  matchResult = regexp.match(queryString)

  # Print result
  obj['inputLength'] = len(queryString)
  obj['matched'] = 1 if matchResult else 0
  sys.stdout.write(json.dumps(obj) + '\n')

def log(msg):
  sys.stderr.write(msg + '\n')

############

main()
