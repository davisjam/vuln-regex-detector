#!/usr/bin/env node
// TODO compress
// TODO https

'use strict';

// Globals.
const PATTERN_VULNERABLE = 'VULNERABLE';
const PATTERN_SAFE       = 'SAFE';
const PATTERN_UNKNOWN    = 'UNKNOWN';
const PATTERN_INVALID    = 'INVALID';

const REQUEST_LOOKUP = "LOOKUP";
const REQUEST_UPDATE = "UPDATE";

const REQUEST_TYPE_TO_PATH = {};
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP] = '/api/lookup';
REQUEST_TYPE_TO_PATH[REQUEST_UPDATE] = '/api/update';

// Modules.
const fs = require('fs');
const http = require('http');

// Config.
if (!process.env.VULN_REGEX_DETECTOR_ROOT) {
	die(`Error, you must define VULN_REGEX_DETECTOR_ROOT`);
}
const configFile = `${process.env.VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json`;
const config = JSON.parse(fs.readFileSync(configFile));

if (!config.useCache) {
	die('Config says do not use cache');
}

// Args.
if (process.argv.length != 3) {
	die(`Usage: ${process.argv[1]} queryFile`);
}
const queryFile = process.argv[2];

// Check queryFile/query for validity.
const query = JSON.parse(fs.readFileSync(queryFile));

const requiredFields = ['pattern', 'language', 'requestType'];
requiredFields.forEach((f) => {
	if (!query[f]) {
		die(`Invalid queryFile ${queryFile}: Missing requiredField ${f}`);
	}
});

if (query.requestType === REQUEST_UPDATE) {
	const requiredFields = ['result'];
	requiredFields.forEach((f) => {
		if (!query[f]) {
			die(`Invalid queryFile ${queryFile} with requestType ${query.requestType}: Missing requiredField ${f}`);
		}
	});
}

// Prep request.
const postData = JSON.stringify(query);
const postOptions = {
  hostname: config.server,
  port: config.port,
  path: REQUEST_TYPE_TO_PATH[query.requestType],
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData),
  },
};

log(`postOptions:\n${JSON.stringify(postOptions)}`);
log(`${query.requestType} ${JSON.stringify(REQUEST_TYPE_TO_PATH)}`);

const req = http.request(postOptions, (res) => {
	log(`STATUS: ${res.statusCode}`);
	log(`HEADERS: ${JSON.stringify(res.headers)}`);
	res.setEncoding('utf8');

	let response = '';
	res.on('data', (chunk) => {
		log(`BODY: ${chunk}`);
		response += chunk;
	});

	res.on('end', () => {
		log(`No more data in response:\n${response}`);
		const fullResponse = JSON.parse(response);		
		query.result = fullResponse.result;
		console.log(JSON.stringify(query));
	});
});

req.on('error', (e) => {
  die(`Error, problem with request: ${e.message}`);
});

// Write data to request body.
log(`Writing to req:\n${postData}`);
req.write(postData);
req.end();

/////////////////////

function die(msg) {
	log(msg);
	process.exit(1);
}

function log(msg) {
	console.error(msg);
}
