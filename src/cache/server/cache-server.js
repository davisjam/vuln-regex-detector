#!/usr/bin/env node
// TODO compress
// TODO privacy policy
// TODO store proposed results in a separate table, distinct from trusted results

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
const https       = require('https');
const express     = require('express');
const bodyParser  = require('body-parser');
const fs          = require('fs');
const MongoClient = require('mongodb').MongoClient;

// Connection URL
const dbUrl = 'mongodb://localhost:27017';

// DB names
const dbName = 'regexCache'; // DB
const collectionName = 'cache_2'; // Table

// Config.
if (!process.env.VULN_REGEX_DETECTOR_ROOT) {
	die(`Error, you must define VULN_REGEX_DETECTOR_ROOT`);
}
const configFile = `${process.env.VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json`;
const config = JSON.parse(fs.readFileSync(configFile));

// Server keys.
const privateKeyFile = config.credentials.key.replace("VULN_REGEX_DETECTOR_ROOT", process.env.VULN_REGEX_DETECTOR_ROOT);
const privateKey = fs.readFileSync(privateKeyFile, 'utf8');
const certificateFile = config.credentials.cert.replace("VULN_REGEX_DETECTOR_ROOT", process.env.VULN_REGEX_DETECTOR_ROOT);
const certificate = fs.readFileSync(certificateFile, 'utf8');
const credentials = {key: privateKey, cert: certificate};

const app = express();
const httpsServer = https.createServer(credentials, app);

// create application/json parser
let jsonParser = bodyParser.json()

app.post(REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP], jsonParser, function (req, res) {
	logQuery(req.body);
	log('Got POST to /api/lookup');
	res.setHeader('Content-Type', 'application/json');
	isVulnerable(req.body)
		.then((result) => {
			res.send(JSON.stringify({ result: result }));
		});
})

app.post(REQUEST_TYPE_TO_PATH[REQUEST_UPDATE], jsonParser, function (req, res) {
	logQuery(req.body);
	log('Got POST to /api/update');
	reportResult(req.body);
	res.setHeader('Content-Type', 'application/json');
	res.send(JSON.stringify({ result: 'Thank you!' }));
})

httpsServer.listen(config.port, function () {
	log(`Listening on port ${config.port}`);
})

/////////////////////

function createID(pattern, language) {
	return `/${pattern}/:${language}`;
}

function isVulnerable(body) {
	if (!body || !body.pattern || !body.language)
		return PATTERN_INVALID;

	return MongoClient.connect(dbUrl)
		.then((client) => {
			const db = client.db(dbName);
			log(`isVulnerable: connected, now querying DB for { ${body.pattern}, ${body.language} }`);
			return collectionLookup(db.collection(collectionName), {pattern: body.pattern, language: body.language});
		})
		.catch((e) => {
			log(`isVulnerable: db error: ${e}`);
			return Promise.resolve(PATTERN_UNKNOWN);
		});
}

// Helper for isVulnerable.
function collectionLookup(collection, query) {
	return collection.find({_id: createID(query.pattern, query.language)}, {result: 1}).toArray()
		.then((items) => {
			if (items.length === 0) {
				log(`collectionLookup ${query.pattern}-${query.language}: no results`);
				return Promise.resolve(PATTERN_UNKNOWN);
			}
			else if (items.length === 1) {
				log(`collectionLookup ${query.pattern}-${query.language}: result: ${items[0].result}`);
				return Promise.resolve(items[0].result);
			}
			else {
				log(`collectionLookup unexpected multiple match: ${JSON.stringify(items)}`);
				return Promise.resolve(PATTERN_UNKNOWN);
			}
		})
		.catch((e) => {
			log(`collectionLookup error: ${e}`);
			return Promise.resolve(PATTERN_UNKNOWN);
		});
}

function reportResult(body) {
	// Reject invalid reports.
	if (!body || !body.pattern || !body.language || !body.result)
		return;
	if (body.result !== PATTERN_VULNERABLE && body.result !== PATTERN_SAFE) {
		return;
	}

	return MongoClient.connect(dbUrl)
		.then((client) => {
			const db = client.db(dbName);
			log(`reportResult: connected, now updating DB for {${body.pattern}, ${body.language}} with ${body.result}`);
			return collectionUpdate(db.collection(collectionName), {pattern: body.pattern, language: body.language, result: body.result});
		})
		.catch((e) => {
			log(`isVulnerable: db error: ${e}`);
			return Promise.resolve(PATTERN_UNKNOWN);
		});

	return;
}

// Helper for reportResult.
function collectionUpdate(collection, result) {
	return collection.insert({_id: createID(result.pattern, result.language), result: result.result})
		.catch((e) => {
			// May fail due to concurrent update on the same value.
			log(`collectionUpdate: error: ${e}`);
			return Promise.resolve(PATTERN_INVALID);
		});
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
