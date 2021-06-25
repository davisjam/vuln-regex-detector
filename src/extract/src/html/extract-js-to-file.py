#!/usr/bin/env python3
# Description: This file takes in a html file from extract-regexes.pl, finds all the script 
# tags, and combine the JS in them into a temporary js file. It then sends the path of the
# temporary js file back to extract-regexes.pl to let it pipeline the js file to the javascript
# extractor. After extract-regexes.pl finishes extracting, The temporary JS file will be 
# deleted by extract-regexes.pl. 

from bs4 import BeautifulSoup
import sys

file_path = sys.argv[1]
with open(file_path) as fp:
    soup = BeautifulSoup(fp, 'html.parser')

js_from_html = ''
for script in soup.find_all('script'):
    js_from_html += script.string

# create temp-js-content.js based on the location of extract-regexes.pl
with open('./src/html/temp-js-content.js', 'w') as fp:
    fp.write(js_from_html)

# return the path to the temp-js-content.js based on the location of extract-regexes.pl
print('./src/html/temp-js-content.js', end = '')