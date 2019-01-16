#!/usr/bin/env python3
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test regex in Python

import sys
import json
import re

def main():
  # Arg parsing.
  if len(sys.argv) != 2:
    print("Error, usage: {} query-file.json".format(sys.argv[0]))
    sys.exit(1)

  queryFile = sys.argv[1]

  with open(queryFile, 'r', encoding='utf-8') as FH:
    cont = FH.read()
    log("Contents of {}: {}".format(queryFile, cont))
    obj = json.loads(cont)

  # Prepare a regexp
  try:
    regexp = re.compile(obj['pattern'])
    obj['validPattern'] = True

    # Try a match
    log("matching: pattern /{}/ input: length {}".format(obj['pattern'], len(obj['input'])))
    #matchResult = regexp.match(obj['input']) # Full-match semantics -- better case
    matchResult = regexp.search(obj['input']) # Partial-match semantics -- worse case

    # Print result
    obj['inputLength'] = len(obj['input'])
    obj['matched'] = 1 if matchResult else 0
    if matchResult:
      obj['matched'] = 1
      obj['matchContents'] = {
        'matchedString': matchResult.group(0),
        'captureGroups': [g if g is not None else "" for g in matchResult.groups()]
      }
    else:
      obj['matched'] = 0
      obj['matchContents'] = {}
  except BaseException as e:
    log('Exception: ' + str(e))
    obj['validPattern'] = False
  sys.stdout.write(json.dumps(obj) + '\n')

def log(msg):
  sys.stderr.write(msg + '\n')

############

main()
