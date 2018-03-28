#!/usr/bin/env node
// TODO compress
// TODO https

'use strict';

// Globals.
const PATTERN_VULNERABLE = 'VULNERABLE';
const PATTERN_SAFE       = 'SAFE';
const PATTERN_INVALID    = 'INVALID';

const REQUEST_LOOKUP = "LOOKUP";
const REQUEST_UPDATE = "UPDATE";

const REQUEST_TYPE_TO_PATH = {}; 
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP] = '/api/lookup';
REQUEST_TYPE_TO_PATH[REQUEST_UPDATE] = '/api/update';

// Modules.
const express = require('express'),
      bodyParser = require('body-parser'),
			fs = require('fs');

// Config.
if (!process.env.VULN_REGEX_DETECTOR_ROOT) {
	die(`Error, you must define VULN_REGEX_DETECTOR_ROOT`);
}
const configFile = `${process.env.VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json`;
const config = JSON.parse(fs.readFileSync(configFile));

let app = express();

// create application/json parser
let jsonParser = bodyParser.json()

app.post(REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP], jsonParser, function (req, res) {
	logQuery(req.body);
	log('Got POST to /api/lookup');
	res.setHeader('Content-Type', 'application/json');
	res.send(JSON.stringify({ result: isVulnerable(req.body) }));
})

app.post(REQUEST_TYPE_TO_PATH[REQUEST_UPDATE], jsonParser, function (req, res) {
	logQuery(req.body);
	log('Got POST to /api/update');
	reportResult(req.body);
	res.setHeader('Content-Type', 'application/json');
	res.send(JSON.stringify({ result: 'Thank you!' }));
})

app.listen(config.port, function () {
	log(`Listening on port ${config.port}`);
})

/////////////////////

function isVulnerable(query) {
	if (!query || !query.pattern || !query.language)
		return PATTERN_INVALID;

	// TODO Query storage.
	return PATTERN_SAFE;
}

function reportResult(result) {
	return;
}

function logQuery(req) {
	log(JSON.stringify(req));
	return;
}

function die(msg) {
	log(msg);
	process.exit(1);
}

function log(msg) {
	console.error(msg);
}
