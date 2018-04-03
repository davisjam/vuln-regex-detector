#!/usr/bin/env node
// TODO privacy policy
// TODO log queries better than to the console?

'use strict';

// Globals.
const PATTERN_VULNERABLE = 'VULNERABLE';
const PATTERN_SAFE       = 'SAFE';
const PATTERN_UNKNOWN    = 'UNKNOWN';
const PATTERN_INVALID    = 'INVALID';

const REQUEST_LOOKUP      = 'LOOKUP';
const REQUEST_LOOKUP_ONLY = 'LOOKUP_ONLY'; // Will only make a lookup, won't be submitting an UPDATE later.
const REQUEST_UPDATE      = 'UPDATE';

const REQUEST_TYPE_TO_PATH = {};
// The LOOKUP/_ONLY requests use the same path.
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP]      = '/api/lookup';
REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP_ONLY] = REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP];
REQUEST_TYPE_TO_PATH[REQUEST_UPDATE]      = '/api/update';

// Modules.
const https       = require('https');
const express     = require('express');
const bodyParser  = require('body-parser');
const fs          = require('fs');
const MongoClient = require('mongodb').MongoClient;
const jsonStringify = require('json-stringify-safe');

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

// DB info -- convenient shorthand.
const dbUrl = `mongodb://${config.serverConfig.dbConfig.dbServer}:${config.serverConfig.dbConfig.dbPort}`;
const dbName = config.serverConfig.dbConfig.dbName;
const dbLookupCollectionName = config.serverConfig.dbConfig.dbLookupCollection;
const dbUploadCollectionName = config.serverConfig.dbConfig.dbUploadCollection;

// Server keys.
const privateKeyFile = config.serverConfig.serverCredentials.key.replace('VULN_REGEX_DETECTOR_ROOT', process.env.VULN_REGEX_DETECTOR_ROOT);
const privateKey = fs.readFileSync(privateKeyFile, 'utf8');

const certificateFile = config.serverConfig.serverCredentials.cert.replace('VULN_REGEX_DETECTOR_ROOT', process.env.VULN_REGEX_DETECTOR_ROOT);
const certificate = fs.readFileSync(certificateFile, 'utf8');

const credentials = {key: privateKey, cert: certificate};

const app = express();
const httpsServer = https.createServer(credentials, app);

// create application/json parser
let jsonParser = bodyParser.json();

// Logging
app.all('*', (req, res, next) => {
	log(`New request:\n  remoteAddress: ${jsonStringify(req.connection.remoteAddress)}\n  headers: ${jsonStringify(req.headers)}\n  body: ${jsonStringify(req.body)}`);
	next();
});

app.post(REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP], jsonParser, function (req, res) {
	log(`Got POST to ${REQUEST_TYPE_TO_PATH[REQUEST_LOOKUP]}`);

	isVulnerable(req.body)
		.then((result) => {
			// Send response.
			res.setHeader('Content-Type', 'application/json');
			res.send(jsonStringify({ result: result }));
			res.end();

			// On valid queries that we can't answer...
			if (result === PATTERN_UNKNOWN) {
				// If the client will not be computing result themselves:
				//   Add to our list so validate will get us the answer later.
				if (req.body.hasOwnProperty('requestType') && req.body.requestType === REQUEST_LOOKUP_ONLY) {
					req.body.result = PATTERN_UNKNOWN;
					log(`Client says ${req.body.requestType}, so calling reportResult with ${jsonStringify(req.body)}`);
					reportResult(req.body);
				}
			}
		});
});

app.post(REQUEST_TYPE_TO_PATH[REQUEST_UPDATE], jsonParser, function (req, res) {
	log(`Got POST to ${REQUEST_TYPE_TO_PATH[REQUEST_UPDATE]}`);

	// Client can be told immediately.
	res.setHeader('Content-Type', 'application/json');
	res.send(jsonStringify({ result: 'Thank you!' }));
	res.end();

	// In the background...
	reportResult(req.body)
		.then((result) => {
			console.log(result);
			log(`Update resulted in ${result} from ${jsonStringify(req.body)}.`);
		});
});

httpsServer.listen(config.serverConfig.serverPort, function () {
	log(`Listening on port ${config.serverConfig.serverPort}`);
});

/* Helpers. */

function createID (pattern, language) {
	return `/${pattern}/:${language}`;
}

// Returns a Promise that resolves to:
//   PATTERN_INVALID: invalid query
//   PATTERN_UNKNOWN: unknown pattern/language combination
//   doc: found it, returns the doc from the DB
function isVulnerable (body) {
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

	log(`isVulnerable: Connecting to ${dbUrl}`);
	return MongoClient.connect(dbUrl)
		.then((client) => {
			log(`isVulnerable: Connected`);

			const db = client.db(dbName);
			log(`isVulnerable: Got db ${dbName}`);

			return collectionLookup(db.collection(dbLookupCollectionName), {pattern: body.pattern, language: body.language})
				.then((result) => {
					client.close();
					return result;
				})
				.catch((e) => {
					log(`isVulnerable: db error: ${e}`);
					client.close();
					return Promise.resolve(PATTERN_UNKNOWN);
				});
		})
		.catch((e) => {
			log(`isVulnerable: db error: ${e}`);
			return Promise.resolve(PATTERN_UNKNOWN);
		});
}

// Helper for isVulnerable.
// Returns a Promise that resolves to one of the PATTERN_X results.
function collectionLookup (collection, query) {
	const id = createID(query.pattern, query.language);
	log(`collectionLookup: querying for ${id}`);
	return collection.find({_id: id}, {result: 1}).toArray()
		.then(
			(docs) => {
				log(`collectionLookup: Got ${docs.length} docs`);
				if (docs.length === 0) {
					log(`collectionLookup ${createID(query.pattern, query.language)}: no results`);
					return Promise.resolve(PATTERN_UNKNOWN);
				} else if (docs.length === 1) {
					log(`collectionLookup ${query.pattern}-${query.language}: result: ${docs[0].result}`);
					return Promise.resolve(docs[0]);
				} else {
					log(`collectionLookup unexpected multiple match: ${jsonStringify(docs)}`);
					return Promise.resolve(PATTERN_UNKNOWN);
				}
			},
			(e) => {
				log(`collectionLookup error: ${e}`);
				return Promise.resolve(PATTERN_UNKNOWN);
			}
		);
}

// Returns a Promise that resolves to one of the PATTERN_X results.
function reportResult (body) {
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
		log(`reportResult: invalid: ${jsonStringify(body)}`);
		return Promise.resolve(PATTERN_INVALID);
	}

	// Supported results.
	if (body.result === PATTERN_UNKNOWN || body.result === PATTERN_SAFE || body.result === PATTERN_VULNERABLE) {
	} else {
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
					return collectionUpdate(db.collection(dbUploadCollectionName), {pattern: body.pattern, language: body.language, result: body.result, evilInput: body.evilInput})
						.then((result) => {
							client.close();
							return result;
						})
						.catch((e) => {
							log(`reportResult: db error: ${e}`);
							client.close();
							return Promise.resolve(PATTERN_UNKNOWN);
						});
				})
				.catch((e) => {
					log(`reportResult: db error: ${e}`);
					return Promise.resolve(PATTERN_UNKNOWN);
				});
		});
}

// Helper for reportResult.
function collectionUpdate (collection, result) {
	result._id = createID(result.pattern, result.language);
	return collection.insertOne(result)
		.catch((e) => {
			// May fail due to concurrent update on the same value.
			log(`collectionUpdate: error: ${e}`);
			return Promise.resolve(PATTERN_INVALID);
		});
}

function die (msg) {
	log(msg);
	process.exit(1);
}

function log (msg) {
	console.error(new Date().toISOString() + `: ${msg}`);
}
