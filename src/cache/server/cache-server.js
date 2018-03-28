#!/usr/bin/env node
// TODO compress
// TODO https
// TODO persistent storage

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

// key: pattern
// value: object with keys: language, value PATTERN_X
let vulns = {};

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

function isVulnerable(body) {
	if (!body || !body.pattern || !body.language)
		return PATTERN_INVALID;

	if (vulns[body.pattern] && vulns[body.pattern][body.language]) {
		return vulns[body.pattern][body.language];
	}
	else {
		return PATTERN_UNKNOWN;
	}
}

function reportResult(body) {
	// Reject invalid reports.
	if (!body || !body.pattern || !body.language || !body.result)
		return;
	if (body.result !== PATTERN_VULNERABLE && body.result !== PATTERN_SAFE) {
		return;
	}

	// New pattern?
	if (!vulns[body.pattern]) {
		vulns[body.pattern] = {};
	}

	// New {pattern, language} pair?
	if (vulns[body.pattern][body.language]) {
		return;
	}
	else {
		log(`New result: { /${body.pattern}/, ${body.language} is ${body.result}`)
		vulns[body.pattern][body.language] = body.result;
	}

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
