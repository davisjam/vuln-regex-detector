#!/usr/bin/env node
/**
 * Move the DB trusted:SAFE to untrusted.
 * They will be re-tested by validate-uploads.js in its next visit.
 *
 * trusted:VULNERABLE comes with proof, so these results are sound.
 * But if the server's validation process has changed, then the trusted:SAFE results may have changed.
 */

'use strict';

// Modules.
const fs            = require('fs');
const MongoClient   = require('mongodb').MongoClient;

// Globals
const PATTERN_SAFE = 'SAFE';

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

		const lookupCollection = db.collection(dbLookupCollectionName);
		const uploadCollection = db.collection(dbUploadCollectionName);

		return lookupCollection.find({ result: PATTERN_SAFE }).toArray()
				.then((docs) => {
					docs.forEach((doc) => {
						log(`doc ${JSON.stringify(doc)}`);
						insertDoc(uploadCollection, doc);
						deleteDoc(lookupCollection, doc);
					});
					log(`Closing client`);
					return client.close();
				})
			.catch((e) => {
				log(`Error: ${JSON.stringify(e)}`);
				return client.close();
			});
	})
	.catch((e) => {
		log(`DB error: ${JSON.stringify(e)}`);
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

function insertDoc (collection, doc) {
	log(`insertDoc: Inserting ${doc._id}: ${JSON.stringify(doc)}`);
	return collection.findOneAndReplace({_id: doc._id}, doc, {upsert: true});
}

function deleteDoc (collection, doc) {
	log(`deleteDoc: Deleting ${doc._id}`);
	return collection.deleteOne({_id: doc._id});
}
