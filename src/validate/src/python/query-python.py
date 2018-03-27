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

  # Try a match
  log("matching: pattern /{}/ input: length {}".format(obj['pattern'], len(obj['input'])))
  matchResult = regexp.match(obj['input'])

  # Print result
  obj['inputLength'] = len(obj['input'])
  obj['matched'] = 1 if matchResult else 0
  sys.stdout.write(json.dumps(obj) + '\n')

def log(msg):
  sys.stderr.write(msg + '\n')

############

main()
