#!/usr/bin/env node
// TODO privacy policy

'use strict';

// Globals.
const PATTERN_VULNERABLE = 'VULNERABLE';

const REQUEST_LOOKUP      = 'LOOKUP';
const REQUEST_LOOKUP_ONLY = 'LOOKUP_ONLY'; // Will only make a lookup, won't be submitting an UPDATE later.
const REQUEST_UPDATE      = 'UPDATE';

const REQUEST_TYPE_TO_PATH = {};
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP]      = '/api/lookup';
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP_ONLY] = '/api/lookup';
REQUEST_TYPE_TO_PATH[REQUEST_UPDATE]      = '/api/update';

// Modules.
const fs    = require('fs');
const https = require('https');

// Config.
if (!process.env.VULN_REGEX_DETECTOR_ROOT) {
	die(`Error, you must define VULN_REGEX_DETECTOR_ROOT`);
}

// config is determined by (1) VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE, or (2) location in dir tree.
let configFile;
if (process.env.VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE) {
	configFile = process.env.VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE;
} else {
	configFile = `${process.env.VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json`;
}
const config = JSON.parse(fs.readFileSync(configFile));

if (!config.clientConfig.useCache) {
	die('Config says do not use cache');
}

// Args.
if (process.argv.length !== 3) {
	console.error(`Usage: ${process.argv[1]} queryFile`);
	process.exit(1);
}
const queryFile = process.argv[2];

// Check queryFile/query for validity.
const query = JSON.parse(fs.readFileSync(queryFile));

const requiredFields = ['pattern', 'language', 'requestType'];
requiredFields.forEach((f) => {
	if (!query.hasOwnProperty(f) || query[f] === null) {
		die(`Invalid queryFile ${queryFile}: Missing requiredField ${f}`);
	}
});

if (query.requestType === REQUEST_UPDATE) {
	let requiredFields = ['result'];
	if (query.result === PATTERN_VULNERABLE) {
		requiredFields.push('evilInput');
	}

	requiredFields.forEach((f) => {
		if (!query.hasOwnProperty(f)) {
			die(`Invalid queryFile ${queryFile}: Missing requiredField ${f}`);
		}
	});
}

// Prep request.
const postData = JSON.stringify(query);
const postOptions = {
	hostname: config.clientConfig.cacheServer,
	port: config.clientConfig.cachePort,
	path: REQUEST_TYPE_TO_PATH[query.requestType],
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
		'Content-Length': Buffer.byteLength(postData)
	}
};

log(`postOptions:\n${JSON.stringify(postOptions)}`);
log(`${query.requestType} ${JSON.stringify(REQUEST_TYPE_TO_PATH)}`);

const req = https.request(postOptions, (res) => {
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

/* Helpers. */

function die (msg) {
	log(msg);
	process.exit(1);
}

function log (msg) {
	console.error(new Date().toISOString() + `: ${msg}`);
}
