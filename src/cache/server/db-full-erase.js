#!/usr/bin/env node
/**
 * Wipe the DB trusted/untrusted tables.
 * Useful if they have been corrupted by faulty cache-server.js or validate-uploads.js implementations.
 * NOTE: Only use in testing. Running this will throw away a lot of computation in production.
 */

'use strict';

// Modules.
const fs            = require('fs');
const MongoClient   = require('mongodb').MongoClient;

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

// Connect to DB.
log(`Connecting to DB ${dbUrl}`);
MongoClient.connect(dbUrl)
	.then((client) => {
		log(`Connected`);
		// Get collection.
		const db = client.db(dbName);

		const uploadCollection = db.collection(dbUploadCollectionName);
		const lookupCollection = db.collection(dbLookupCollectionName);

		return uploadCollection.drop()
			.then((result) => {
				log(`Deleted uploadCollection`);
				return lookupCollection.drop()
					.then((result) => {
						log(`Deleted lookupCollection`);
						return client.close();
					});
			})
			.catch((e) => {
				log(`Delete error: ${JSON.stringify(e)}`);
				return client.close();
			});
	})
	.catch((e) => {
		log(`db error: ${e}`);
		return Promise.resolve(false);
	});

/* Helpers. */

function log (msg) {
	console.error(new Date().toISOString() + `: ${msg}`);
}

function die (msg) {
	log(msg);
	process.exit(1);
}
