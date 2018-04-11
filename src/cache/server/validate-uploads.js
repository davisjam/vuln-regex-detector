#!/usr/bin/env node
/* cache-server.js places uploaded data into dbUploadCollectionName.
 * Since a malicious client could upload false reports,
 *   we don't immediately place them in dbLookupCollectionName.
 * This program:
 *  1. Traverses dbUploadCollectionName
 *  2. Validates the results
 *  3. Updates dbLookupCollectionName (NB: vuln trumps safe so we may modify existing reports)
 *  4. Wipes dbUploadCollectionName
 *
 * Suitable for use as a cron job on the server where the mongoDB instance lives.
 *
 * Due to the possible expense with large batches, use flock in your crontab.
 *   https://ma.ttias.be/prevent-cronjobs-from-overlapping-in-linux/
 */

'use strict';

// Globals.
const PATTERN_VULNERABLE = 'VULNERABLE';
const PATTERN_SAFE       = 'SAFE';
const PATTERN_UNKNOWN    = 'UNKNOWN';

// Modules.
const fs            = require('fs');
const childProcess = require('child_process');
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

		log(`Handling each doc in ${dbUploadCollectionName}`);
		let pending = []; // Pending promises for DB updates resulting from scan of docs.
		return uploadCollection.find().forEach((doc) => {
			// Test each doc.
			log(`Got doc: ${JSON.stringify(doc)}`);

			let isInvalid = false;
			['pattern', 'language', 'result'].forEach((f) => {
				if (!doc.hasOwnProperty(f)) {
					log(`Invalid doc: missing ${f}`);
					isInvalid = true;
				}
			});
			if (isInvalid) {
				log(`Invalid doc: missing required fields`);
				pending.push(deleteDoc(uploadCollection, doc));
				return;
			}

			// OK, now we have a report of PATTERN_{UNKNOWN, SAFE, VULNERABLE}.
			// Run UNKNOWN/SAFE through check-regex.pl.
			// Run VULNERABLE through validate-vuln.pl.
			// No matter the outcome, doc should be removed from uploadCollection.
			//
			// validateSafe and validateVuln are hideously blocking, but whatcha gonna do?
			// Could parallelize to multiple cores using childProcess.exec instead of childProcess.execSync.
			const deleteUploadDoc = function () { return deleteDoc(uploadCollection, doc); };

			if (doc.result === PATTERN_UNKNOWN || doc.result === PATTERN_SAFE) {
				// No proof, so we have to run check-regex.pl to confirm.
				// Then we have ground truth so we can update the DB either way.
				// Useful to know, however, whether the client "lied" to us.
				//
				// TODO it's possible for discovered vulnerabilities to be overwritten here.
				// Scenario:
				//   - A discovers vuln with large time budget and uploads.
				//   - We confirm, removing it from uploadCollection.
				//   - B fails with short time budget and uploads.
				//   - We fail with short time budget, *overwriting* the previous finding.
				const accurateDoc = determineSafety(doc);

				// On error, just delete.
				if (!accurateDoc) {
					log(`Extreme failure while determining safety`);
					pending.push(deleteDoc(uploadCollection, doc));
					return;
				}

				// Otherwise, log whether client was correct and update the tables.
				if (doc.result === PATTERN_SAFE) {
					if (accurateDoc === PATTERN_SAFE) {
						log(`Truly safe`);
					} else {
						log(`Not truly safe -- FALSE REPORT`);
					}
				}
				const pendingPromise = insertDoc(lookupCollection, accurateDoc)
					.then(deleteUploadDoc, deleteUploadDoc);
				pending.push(pendingPromise);
			} else if (doc.result === PATTERN_VULNERABLE) {
				// Must have evilInput: proof of vulnerability.
				// If they are using our cache-client.js they always have this.
				if (!doc.hasOwnProperty('evilInput')) {
					log(`${doc.result}: missing evilInput`);
					pending.push(deleteUploadDoc());
					return;
				}

				const isVulnerable = validateVuln(doc);
				if (isVulnerable) {
					log(`Truly vuln`);
					const pendingPromise = insertDoc(lookupCollection, doc)
						.then(deleteUploadDoc, deleteUploadDoc);
					pending.push(pendingPromise);
				} else {
					log(`Not truly vuln -- FALSE REPORT`);
					pending.push(deleteUploadDoc());
				}
			} else {
				log(`Unsupported result type ${doc.result}`);
				pending.push(deleteUploadDoc());
			}

			return '';
		},
		// CB when all docs have been tested.
		(error) => {
			log(`Awaiting ${pending.length} promises (error ${error})`);
			// Could be MongoClient errors. Ignore.
			const pendingAllResolve = pending.map(reflect);
			const allPending = Promise.all(pendingAllResolve);
			allPending.then((result) => {
				log(`Done`);
				return client.close();
			})
				.catch((e) => {
					log(`db error: ${JSON.stringify(e)}`);
					return client.close();
				});
		});
	})
	.catch((e) => {
		log(`db error: ${e}`);
		return Promise.resolve(false);
	});

/* Helpers. */

function reflect (promise) {
	const resolved = (v) => { return { v: v, status: 'resolved' }; };
	const rejected = (e) => { return { e: e, status: 'rejected' }; };
	return promise
		.then(resolved, rejected);
}

function log (msg) {
	console.error(new Date().toISOString() + `: ${msg}`);
}

function die (msg) {
	log(msg);
	process.exit(1);
}

function insertDoc (collection, doc) {
	log(`insertDoc: Inserting ${doc._id}: ${JSON.stringify(doc)}`);
	// If document already exists, overwrite it.
	// This addresses cases where evilInput is discovered after
	// an initial conclusion of SAFE, e.g. after the introduction
	// of a new detector.
	return collection.findOneAndReplace({_id: doc._id}, doc, {upsert: true});
}

function deleteDoc (collection, doc) {
	log(`deleteDoc: Deleting ${doc._id}`);
	return collection.deleteOne({_id: doc._id});
}

// Return true if doc is truthful (describes a vulnerable regex), else false.
function validateVuln (doc) {
	log(`validateVuln: doc ${JSON.stringify(doc)}`);
	const validateVulnQuery = { pattern: doc.pattern, language: doc.language, evilInput: doc.evilInput, nPumps: 250000, timeLimit: 1 };

	const tmpFile = `/tmp/validate-uploads-${process.pid}.json`;
	fs.writeFileSync(tmpFile, JSON.stringify(validateVulnQuery));

	try {
		const cmd = `${process.env.VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl ${tmpFile} 2>/dev/null`;
		const stdout = childProcess.execSync(cmd, {encoding: 'utf8'});
		const result = JSON.parse(stdout);
		log(JSON.stringify(result));
		return result.timedOut === 1;
	} catch (e) {
		log(`Error: ${JSON.stringify(e)}`);
		return false;
	} finally {
		fs.unlinkSync(tmpFile);
	}
}

// Given an untrusted doc, query check-regex.pl.
// Return a trusted doc or undefined.
// Timeouts are treated as safe -- prefer false negatives to false positives.
function determineSafety (doc) {
	log(`determineSafety: doc ${JSON.stringify(doc)}`);

	const tmpFile = `/tmp/validate-uploads-${process.pid}.json`;
	try {
		// Create query for check-regex.
		const checkRegexQuery = {
			pattern: doc.pattern,
			validateVuln_language: doc.language,
			validateVuln_nPumps: 250000,
			validateVuln_timeLimit: 1,
			useCache: 0 // Using the cache would be somewhat circular.
		};
		log(`checkRegex query: ${JSON.stringify(checkRegexQuery)}`);
		fs.writeFileSync(tmpFile, JSON.stringify(checkRegexQuery));

		// Run query.
		const cmd = `${process.env.VULN_REGEX_DETECTOR_ROOT}/bin/check-regex.pl ${tmpFile} 2>/dev/null`;
		log(`determineSafety: cmd ${cmd}`);
		const stdout = childProcess.execSync(cmd, {encoding: 'utf8'});
		const result = JSON.parse(stdout);
		log(`determineSafety: result ${JSON.stringify(result)}`);

		// Interpret result.
		if (result.isVulnerable && result.validateReport.timedOut) { // Vulnerable: detector plus validation
			log(`Vulnerable!`);
			return {
				_id: doc._id,
				pattern: doc.pattern,
				language: doc.language,
				result: PATTERN_VULNERABLE,
				evilInput: result.validateReport.evilInput
			};
		} else {
			// Detectors timed out or said it was safe.
			// NB This permits false 'SAFE' reports into the database.
			log(`Not vulnerable (or analysis timed out).`);
			return {
				_id: doc._id,
				pattern: doc.pattern,
				language: doc.language,
				result: PATTERN_SAFE
			};
		}
	} catch (e) {
		log(`Error: ${JSON.stringify(e)}`);
		return undefined;
	} finally {
		fs.unlinkSync(tmpFile);
	}
}
