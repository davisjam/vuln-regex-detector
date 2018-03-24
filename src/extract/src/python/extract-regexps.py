# Author: Jamie Davis <davisjam@vt.edu>
# Description: Extract regexps from a python file
# Implementation: AST traversal
#
# Invocation: AST processing is baked into the python interpreter,
#               but we may be working with repositories based on python2 or python3.
#             One version may yield syntax errors in the other.
#             For example, 'print "foo"' works in python2 but not in python3.
#
#             Therefore, invoke first as 'python2 extract-regexps.py'.
#             On syntax errors, invoke as 'python3 extract-regexps.py'
# 
# Resources:
#   Python re docs: https://docs.python.org/3/library/re.html
#   Python AST docs: https://docs.python.org/2/library/ast.html
#   AST how-to:  https://suhas.org/function-call-ast-python/
#   JSON: https://docs.python.org/3/library/json.html
#
# Limitations:
#   Detects imports of the module 're' as "import re" and "import re as X"
#   However, will not find regexps if the caller uses "from re import *"
#     and then calls the imported methods directly.
#
# Dependencies:
#   Must define ECOSYSTEM_REGEXP_PROJECT_ROOT
#
# Output:
#   Prints a JSON object with keys: filename regexps[]
#     filename is the path provided
#     regexps is an array of objects, each with keys: funcName pattern flags
#       funcName is the re module function being invoked
#       pattern and flags are each either a string or 'DYNAMIC-{PATTERN|FLAGS}'
#       If the regexp invocation cannot have flags, the flags string will be 'FLAGLESS' instead

import os
import subprocess
import sys
import json
import ast
import re

# If you import re, these are the methods you might call on it.
regexpFuncNames = ['compile', 'search', 'match', 'fullmatch', 'split', 'findall', 'finditer', 'sub', 'subn', 'escape']
regexpFlagNames = ['DEBUG',
                   'I', 'IGNORECASE',
                   'L', 'LOCALE',
                   'M', 'MULTILINE',
                   'S', 'DOTALL',
                   'U', 'UNICODE',
                   'X', 'VERBOSE'
                  ]

# Signatures:
#  compile(pattern, flags=0)
#  search(pattern, string, flags=0)
#  match(pattern, string, flags=0)
#  fullmatch(pattern, string, flags=0)
#  split(pattern, string, maxsplit=0, flags=0)
#  findall(pattern, string, flags=0)
#  finditer(pattern, string, flags=0)
#  sub(pattern, repl, string, count=0, flags=0)
#  subn(pattern, repl, string, count=0, flags=0)
#  escape(pattern)

func_to_hasFlags = { 'compile': 1,
                     'search': 1,
                     'match': 1,
                     'fullmatch': 1,
                     'split': 1,
                     'findall': 1,
                     'finditer': 1,
                     'sub': 1,
                     'subn': 1
                   }

# Find flags by checking this position in args, then by looking in the keywords array
func_to_flagsIndex = { 'compile': 1,
                          'search': 2,
                          'match': 2,
                          'fullmatch': 2,
                          'split': 3,
                          'findall': 2,
                          'finditer': 2,
                          'sub': 4,
                          'subn': 4
                        }

def log (msg):
  sys.stderr.write('{}\n'.format(msg))

class RegexpInstance():
  funcName = ''
  pattern = ''
  flags = ''

  def __init__(self, funcName_, pattern_, flags_):
    self.funcName = funcName_
    self.pattern = pattern_
    self.flags = flags_

  def getFuncName(self):
    return self.funcName

  def getPattern(self):
    return self.pattern

  def getFlags(self):
    return self.flags

# Walk an AST rooted at a node corresponding to regexp flags
class ASTWalkerForFlags(ast.NodeVisitor):
  flags = list()
  dynamic = False
  reAliases = list()

  def __init__(self, reAliases):
    self.flags = list()
    self.dynamic = False
    self.reAliases = reAliases

  # Programmer API
  def wasDynamic(self):
    return self.dynamic

  def getFlags(self):
    return self.flags

  # AST interface

  # All Attributes should describe 're.X'
  def visit_Attribute(self, node):
    try:
      # Is this an Attribute of the form x.y, where x is an re alias and y is an re pattern flag?
      moduleName = node.value.id
      flagName = node.attr
      if moduleName in self.reAliases and flagName in regexpFlagNames:
        log('ASTWalkerForFlags: flagName {}'.format(flagName))
        self.flags.append(flagName)
      else:
        log('ASTWalkerForFlags: inappropriate Attribute {}.{}'.format(moduleName, flagName))
        self.dynamic = True
    except:
      self.dynamic = True

  def visit_Num(self, node):
    log('ASTWalkerForFlags: got num {}'.format(node.n))
    self.flags.append('{}'.format(node.n))

  # All Names should be 're'
  def visit_Name(self, node):
    # Must be Name node of an Attribute, where name is an re alias
    try:
      # Is this an Attribute of the form x.y, where x is an re alias and y is an re pattern flag?
      moduleName = node.id
      if moduleName in self.reAliases:
        pass
      else:
        log('ASTWalkerForFlags: Name: unexpected moduleName {}'.format(moduleName))
        self.dynamic = True
    except Exception as e:
      log('ASTWalkerForFlags: bad Name: {}'.format(e))
      self.dynamic = True

    # Recurse just in case
    ast.NodeVisitor.generic_visit(self, node)

  # BinOps are fine
  def visit_BinOp(self, node):
    # Recurse
    ast.NodeVisitor.generic_visit(self, node)

  # Load context is fine, we get it from BinOp
  def visit_Load(self, node):
    # Recurse just in case
    ast.NodeVisitor.generic_visit(self, node)

  # BitOrs are fine
  def visit_BitOr(self, node):
    # Recurse
    ast.NodeVisitor.generic_visit(self, node)

  # Any other nodes imply some kind of dynamic determination of the flags
  def generic_visit(self, node):
    log('ASTWalkerForFlags: Got an unexpected node, this is dynamic: {}'.format(ast.dump(node)))
    self.dynamic = True

# Walk full AST for regexps
class ASTWalkerForRegexps(ast.NodeVisitor):
  reAliases = list()
  regexps = list()

  def __init__(self):
    self.reAliases = list()
    self.regexps = list()

  def getRegexps(self):
    return self.regexps

  # ImportFrom: Detect missed aliases for re functions
  def visit_ImportFrom(self, node):
    if node.module == 're':
      log('Potentially-missed regexps: ImportFrom re: {}'.format(ast.dump(node)))

  # Import: Detect aliases for the re module
  def visit_Import(self, node):
    try:
      for alias in node.names:
        if alias.name == 're':
          if alias.asname == None:
            name = alias.name
          else:
            name = alias.asname

          log('New alias for re: {}'.format(name))
          self.reAliases.append(name)
    except:
      pass

  def visit_Call(self, node):
    try:
      # Is this a call of the form x.y, where x is an re alias and y is a regexpFuncName ? 
      funcID = node.func.value.id
      funcName = node.func.attr
      if funcID in self.reAliases and funcName in regexpFuncNames:
        log('Got an RE: {}.{}'.format(funcID, funcName))
        log(ast.dump(node))

        # Get pattern
        if type(node.args[0]) is ast.Str:
          log('Pattern is static')
          pattern = node.args[0].s
        else:
          log('Pattern is dynamic')
          pattern = 'DYNAMIC-PATTERN'

        # Get flags
        funcCanHaveFlags = False
        dynamicFlags = False
        flagNames = []
        if func_to_hasFlags.get(funcName): # escape has no flags
          funcCanHaveFlags = True
          flagsNode = False

          # Positional check
          flagIx = func_to_flagsIndex.get(funcName)
          if flagIx < len(node.args):
            log('Flags provided to {} using positional argument'.format(funcName))
            flagsNode = node.args[flagIx]
          else:
            # Keywords check
            log('Flags not provided to {} using positional argument; flagIx {} length of args {}'.format(funcName, flagIx, len(node.args)))
            for kw in node.keywords:
              if kw.arg == 'flags':
                log('Flags provided using keywords')
                flagsNode = kw.value
                break

          # Did we find flags in positional or keywords?
          if flagsNode:
            flagWalker = ASTWalkerForFlags(self.reAliases)
            flagWalker.visit(flagsNode)
            if flagWalker.wasDynamic():
              dynamicFlags = True
            else:
              flagNames = flagWalker.getFlags()
        else:
          log('{} does not have a flags field'.format(funcName))
          funcCanHaveFlags = False

        if funcCanHaveFlags:
          if dynamicFlags:
            flagsString = 'DYNAMIC-FLAGS'
          else:
            flagsString = '|'.join(flagNames)
        else:
          flagsString = 'FLAGLESS'

        logStr = 'funcName <{}>, pattern <{}>, flags <{}>'.format(funcName, pattern, flagsString)
        log(logStr)
        #sys.stdout.write(logStr + '\n')
        self.regexps.append(RegexpInstance(funcName, pattern, flagsString))
    except Exception as e:
      log('DEBUG: ASTWalkerForRegexps: visit_Call exception: {}'.format(e))

    # Recurse
    ast.NodeVisitor.generic_visit(self, node)

def main():
  # Usage
  if len(sys.argv) != 2:
    log('Usage: {} python-file.py'.format(sys.argv[0]))
    sys.exit(1)

  # Check for dependencies
  if (not os.environ.get('ECOSYSTEM_REGEXP_PROJECT_ROOT')):
    log('Error, must define env var ECOSYSTEM_REGEXP_PROJECT_ROOT')
    sys.exit(1)

  sourcefile = sys.argv[1]

  # Read file and prep an AST.
  try:
    with open(sourcefile, 'r') as FH:
      content = FH.read()
      root = ast.parse(content, sourcefile)
  
      walker = ASTWalkerForRegexps()
      walker.visit(root)
  
      fileInfo = { 'filename': sourcefile,
                   'regexps': [regexp.__dict__ for regexp in walker.getRegexps()]
                 }
      sys.stdout.write(json.dumps(fileInfo) + '\n')
  except Exception as e:
    # Easy-to-parse to stdout
    errMsg = 'Something went wrong, perhaps try with a different Python interpreter'
    sys.stdout.write(errMsg + '\n')
    
    # More verbose to stderr
    log(errMsg)
    log(e)
    
    # Byee
    sys.exit(1)

main()
