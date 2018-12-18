#!/usr/bin/env node
// Author: Jamie Davis <davisjam@vt.edu>
// Description: Try REDOS attack on Node.js

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
	var matched = query.input.match(re);
	result.inputLength = query.input.length;
	result.matched = matched ? 1 : 0;
} catch (e) {
	result.validPattern = false;
}

console.log(JSON.stringify(result));

process.exit(0);
