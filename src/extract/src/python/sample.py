# Test input for extract-regexps.py
import foo

from re import *

import re
import re as RE_ALONE

import foo, re as RE, bar

# Misc. non-re calls
data = open('file')                     # a function call
foo.bar(arg=data)                       # a function call
foo.bar(arg=foo.meow(foo.z(arg=data)))  # three function calls
foo.woof(foo.x.y(arg=data))             # two function calls

# regexpFuncNames, but not from an re alias
compile('pattern')
bar.compile('pattern')

# regexp call from an alias of re
RE.compile('staticPattern')
RE.compile('staticPattern', re.IGNORECASE)
RE.compile('staticPattern', dynamicFlags)
RE.compile(dynamicPattern)
RE.compile(dynamicPattern, re.IGNORECASE)
RE.compile(dynamicPattern, dynamicFlags)

### "normal" calls of all possibilities

# compile
re.compile(xyz)
re.compile('[a-z]+')
re.compile('[a-z]+', re.IGNORECASE)
re.compile('[a-z]+', flags=re.IGNORECASE)

## search
re.search('a', 'b')
re.search('a', 'b', re.IGNORECASE)
re.search('a', 'b', flags=re.IGNORECASE)

## match
re.match('a', 'b')
re.match('a', 'b', re.IGNORECASE)
re.match('a', 'b', flags=re.IGNORECASE)

## fullmatch
re.fullmatch('a', 'b')
re.fullmatch('a', 'b', re.IGNORECASE)
re.fullmatch('a', 'b', flags=re.IGNORECASE)

## split
re.split('a', 'b')
re.split('a', 'b', 1)
re.split('a', 'b', 1, re.IGNORECASE)
re.split('a', 'b', flags=re.IGNORECASE)

## findall
re.findall('a', 'b')
re.findall('a', 'b', re.IGNORECASE)
re.findall('a', 'b', flags=re.IGNORECASE)

## finditer
re.finditer('a', 'b')
re.finditer('a', 'b', re.IGNORECASE)
re.finditer('a', 'b', flags=re.IGNORECASE)

## sub
re.sub('a', 'b', 'c')
re.sub('a', 'b', 'c', 0)
re.sub('a', 'b', 'c', 0, re.IGNORECASE)
re.sub('a', 'b', 'c', count=0)
re.sub('a', 'b', 'c', count=0, flags=re.IGNORECASE)
re.sub('a', 'b', 'c', flags=re.IGNORECASE)
re.sub('a', 'b', 'c', flags=0)

## subn
re.subn('a', 'b', 'c')
re.subn('a', 'b', 'c', 0)
re.subn('a', 'b', 'c', 0, re.IGNORECASE)
re.subn('a', 'b', 'c', flags=re.IGNORECASE)
re.subn('a', 'b', 'c', count=0, flags=re.IGNORECASE)

## escape
re.escape('a')

# Goofy verbose (X) example from python docs
re.compile(r"""\d +  # the integral part
                   \.    # the decimal point
                   \d *  # some fractional digits""", re.X)

# Try with lots of flags
re.compile('[a-z]+', re.IGNORECASE|re.MULTILINE)
re.compile('[a-z]+', re.IGNORECASE|re.MULTILINE|re.DOTALL)

# More complex calls
## Nesting -- should be <nestedOnce, 'DYNAMIC-FLAGS'> and <nestedTwice, ''>
foo(re.match('nestedOnce', 'b', re.IGNORECASE if re.match('nestedTwice', 'd') else re.IGNORECASE))
## Partially-dynamic flags
re.compile('partiallyDynamicFlags-[a-z]+', re.IGNORECASE | foo(re.MULTILINE))
## Numeric flags
re.subn('a', 'b', flags=0)
re.subn('a', 'b', flags=0|re.IGNORECASE)
