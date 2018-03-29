#!/usr/bin/env node
// TODO privacy policy
// TODO log queries
//
// TODO Am I supposed to close DB connections after I query?
//      If I remove the ' || body[f] === null', I get weird interactions
//      between cache-server.js and validate-vulns.js.

'use strict';

// Globals.
const PATTERN_VULNERABLE = 'VULNERABLE';
const PATTERN_SAFE       = 'SAFE';
const PATTERN_UNKNOWN    = 'UNKNOWN';
const PATTERN_INVALID    = 'INVALID';

const REQUEST_LOOKUP      = "LOOKUP";
const REQUEST_LOOKUP_ONLY = "LOOKUP_ONLY"; // Will only make a lookup, won't be submitting an UPDATE later.
const REQUEST_UPDATE      = "UPDATE";

const REQUEST_TYPE_TO_PATH = {}; 
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP] = '/api/lookup';
REQUEST_TYPE_TO_PATH[REQUEST_UPDATE] = '/api/update';

// Modules.
const https       = require('https');
const express     = require('express');
const bodyParser  = require('body-parser');
const fs          = require('fs');
const MongoClient = require('mongodb').MongoClient;

// Config.
if (!process.env.VULN_REGEX_DETECTOR_ROOT) {
	die(`Error, you must define VULN_REGEX_DETECTOR_ROOT`);
}
const configFile = `${process.env.VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json`;
const config = JSON.parse(fs.readFileSync(configFile));

// DB info -- convenient shorthand.
const dbUrl = `mongodb://${config.serverConfig.dbConfig.dbServer}:${config.serverConfig.dbConfig.dbPort}`;
const dbName = config.serverConfig.dbConfig.dbName;
const dbLookupCollectionName = config.serverConfig.dbConfig.dbLookupCollection;
const dbUploadCollectionName = config.serverConfig.dbConfig.dbUploadCollection;

// Server keys.
const privateKeyFile = config.serverConfig.serverCredentials.key.replace("VULN_REGEX_DETECTOR_ROOT", process.env.VULN_REGEX_DETECTOR_ROOT);
const privateKey = fs.readFileSync(privateKeyFile, 'utf8');

const certificateFile = config.serverConfig.serverCredentials.cert.replace("VULN_REGEX_DETECTOR_ROOT", process.env.VULN_REGEX_DETECTOR_ROOT);
const certificate = fs.readFileSync(certificateFile, 'utf8');

const credentials = {key: privateKey, cert: certificate};

const app = express();
const httpsServer = https.createServer(credentials, app);

// create application/json parser
let jsonParser = bodyParser.json()

app.post(REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP], jsonParser, function (req, res) {
	logQuery(req.body);
	log('Got POST to /api/lookup');
	isVulnerable(req.body)
		.then((result) => {
			// Send response.
			res.setHeader('Content-Type', 'application/json');
			res.send(JSON.stringify({ result: result }));
			res.end();

			// On valid queries that we can't answer...
			if (result === PATTERN_UNKNOWN) {
				// If the client will not be computing result themselves:
				//   Add to our list so validate will get us the answer later.
				if (req.body.hasOwnProperty('requestType') && req.body.requestType === REQUEST_LOOKUP_ONLY) {
					req.body.result = PATTERN_UNKNOWN;
					log(`Client says ${req.body.requestType}, so calling reportResult with ${JSON.stringify(req.body)}`);
					reportResult(req.body);
				}
			}
		});
})

app.post(REQUEST_TYPE_TO_PATH[REQUEST_UPDATE], jsonParser, function (req, res) {
	logQuery(req.body);
	log('Got POST to /api/update');
	reportResult(req.body)
		.then((result) => {
			console.log(result);
			log(`Update resulted in ${result} from ${JSON.stringify(req.body)}.`);

			res.setHeader('Content-Type', 'application/json');
			res.send(JSON.stringify({ result: 'Thank you!' }));
			res.end();
		});
})

httpsServer.listen(config.serverConfig.serverPort, function () {
	log(`Listening on port ${config.serverConfig.serverPort}`);
})

/////////////////////

function createID(pattern, language) {
	return `/${pattern}/:${language}`;
}

// Returns a Promise that resolves to:
//   PATTERN_INVALID: invalid query
//   PATTERN_UNKNOWN: unknown pattern/language combination
//   doc: found it, returns the doc from the DB
function isVulnerable(body) {
	// Reject invalid queries
	if (!body) {
		return Promise.resolve(PATTERN_INVALID);
	}
	let isInvalid = false;
	['pattern', 'language'].forEach((f) => {
		if (!body.hasOwnProperty(f) || body[f] === null) {
			isInvalid = true;
		}
	});
	if (isInvalid) {
		return Promise.resolve(PATTERN_INVALID);
	}

	return MongoClient.connect(dbUrl)
		.then((client) => {
			const db = client.db(dbName);
			log(`isVulnerable: connected, now querying DB for { ${body.pattern}, ${body.language} }`);
			return collectionLookup(db.collection(dbLookupCollectionName), {pattern: body.pattern, language: body.language});
		})
		.catch((e) => {
			log(`isVulnerable: db error: ${e}`);
			return Promise.resolve(PATTERN_UNKNOWN);
		});
}

// Helper for isVulnerable.
// Returns a Promise that resolves to one of the PATTERN_X results.
function collectionLookup(collection, query) {
	return collection.find({_id: createID(query.pattern, query.language)}, {result: 1}).toArray()
		.then((docs) => {
			if (docs.length === 0) {
				log(`collectionLookup ${createID(query.pattern,query.language)}: no results`);
				return Promise.resolve(PATTERN_UNKNOWN);
			}
			else if (docs.length === 1) {
				log(`collectionLookup ${query.pattern}-${query.language}: result: ${docs[0].result}`);
				return Promise.resolve(docs[0]);
			}
			else {
				log(`collectionLookup unexpected multiple match: ${JSON.stringify(docs)}`);
				return Promise.resolve(PATTERN_UNKNOWN);
			}
		})
		.catch((e) => {
			log(`collectionLookup error: ${e}`);
			return Promise.resolve(PATTERN_UNKNOWN);
		});
}

// Returns a Promise that resolves to one of the PATTERN_X results.
function reportResult(body) {
	// Reject invalid reports.
	if (!body) {
		log(`reportResult: no body`);
		return Promise.resolve(PATTERN_INVALID);
	}

	// Required fields.
	let isInvalid = false;
	['pattern', 'language', 'result'].forEach((f) => {
		if (!body.hasOwnProperty(f) || body[f] === null) {
			isInvalid = true;
		}
	});
	if (isInvalid) {
		log(`reportResult: invalid: ${JSON.stringify(body)}`);
		return Promise.resolve(PATTERN_INVALID);
	}

	// Supported results.
	if (body.result === PATTERN_UNKNOWN || body.result === PATTERN_SAFE || body.result === PATTERN_VULNERABLE) {
	}
	else {
		log(`reportResult: invalid result ${body.result}`);
		return Promise.resolve(PATTERN_INVALID);
	}

	// Vulnerable must include proof.
	if (body.result === PATTERN_VULNERABLE && !body.hasOwnProperty('evilInput')) {
		log(`reportResult: ${body.result} but no evilInput`);
		return Promise.resolve(PATTERN_INVALID);
	}

	// Malicious client could spam us with already-solved requests.
	// Check if we know the answer already.
	return isVulnerable(body)
		.then((result) => {
			if (result !== PATTERN_UNKNOWN) {
				log(`reportResult: already known. Malicious client, or racing clients?`);
				return Promise.resolve(result);
			}
			// New pattern, add to dbUploadCollectionName.
			log(`reportResult: new result, updating dbUploadCollectionName`);
			return MongoClient.connect(dbUrl)
				.then((client) => {
					const db = client.db(dbName);
					log(`reportResult: connected, now updating DB for {${body.pattern}, ${body.language}} with ${body.result}`);
					return collectionUpdate(db.collection(dbUploadCollectionName), {pattern: body.pattern, language: body.language, result: body.result, evilInput: body.evilInput});
				})
				.catch((e) => {
					log(`isVulnerable: db error: ${e}`);
					return Promise.resolve(PATTERN_UNKNOWN);
				});
	});
}

// Helper for reportResult.
function collectionUpdate(collection, result) {
	result._id = createID(result.pattern, result.language);
	return collection.insertOne(result)
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
