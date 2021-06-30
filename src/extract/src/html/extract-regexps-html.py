#!/usr/bin/env python3
# Description: This file takes in a html file from extract-regexes.pl, finds all the script 
# tags, and combine the JS in them into a temporary js file. It then sends the path of the
# temporary js file back to extract-regexes.pl to let it pipeline the js file to the javascript
# extractor. After extract-regexes.pl finishes extracting, The temporary JS file will be 
# deleted by extract-regexes.pl. 

from bs4 import BeautifulSoup
import sys
import subprocess
import json

file_path = sys.argv[1]
with open(file_path) as fp:
    soup = BeautifulSoup(fp, 'html.parser')

js_from_html = ''
for script in soup.find_all('script'):
    js_from_html += script.string

# create temp-js-content.js based on the location of extract-regexes.pl
with open('./src/html/temp-js-content.js', 'w') as fp:
    fp.write(js_from_html)

# hardcoded js extractor location
output = subprocess.run(['./src/javascript/extract-regexps.js', './src/html/temp-js-content.js'], capture_output=True, text=True)
output_json = json.loads(output.stdout)
output_json['file'] = file_path
return_string = json.dumps(output_json)
print(return_string, end = '')

# delete the temp js file
subprocess.run(['rm', './src/html/temp-js-content.js'])