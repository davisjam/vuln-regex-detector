#!/usr/bin/env node
// Author: Jamie Davis <davisjam@vt.edu>
// Description: Test regex in Node.js

var fs = require('fs');

// Arg parsing.
var queryFile = process.argv[2];
if (!queryFile) {
  console.log(`Error, usage: ${process.argv[1]} query-file.json`);
  process.exit(1);
}

// Load query from file.
var query = JSON.parse(fs.readFileSync(queryFile, 'utf-8'));

// Check query is valid.
var validQuery = true;
var requiredQueryKeys = ['pattern', 'input'];
requiredQueryKeys.forEach((k) => {
  if (typeof(query[k]) === 'undefined') {
    validQuery = false;
  }
});
if (!validQuery) {
  console.error(`Error, invalid query. Need keys ${JSON.stringify(requiredQueryKeys)}. Got ${JSON.stringify(query)}`);
  process.exit(1);
}

// Try to match string against pattern.
var result = query;
console.error(`matching: pattern /${query.pattern}/ inputStr: len ${query.input.length}`);
try {
	var re = new RegExp(query.pattern);
	result.validPattern = true;
	result.inputLength = query.input.length;

	var matched = query.input.match(re); // Partial-match semantics
	result.matched = matched ? 1 : 0;
	if (matched) {
		result.matchContents = {
			'matchedString': matched[0],
			'captureGroups': matched.slice(1).map(g => {
        // Convert unused groups (null) to empty captures ("") for cross-language consistency
        if (g == null) { 
          return '';
        } else {
          return g;
        }
      }),
		};
	}
	delete result.input; // TODO Sometimes too long for Perl?
} catch (e) {
	result.validPattern = false;
}

console.log(JSON.stringify(result));

process.exit(0);
