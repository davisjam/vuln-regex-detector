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
const PATTERN_INVALID    = 'INVALID';

// Modules.
const fs            = require('fs');
const child_process = require('child_process');
const MongoClient   = require('mongodb').MongoClient;

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

// Connect to DB.
MongoClient.connect(dbUrl)
.then((client) => {
	// Get collection.
	const db = client.db(dbName);

	const uploadCollection = db.collection(dbUploadCollectionName);
	const lookupCollection = db.collection(dbLookupCollectionName);

	// Pending promises for DB updates resulting from scan of docs.
	log(`Connected, now handling each doc`);
	let pending = [];
	return uploadCollection.find().forEach((doc) => {
		// Test each doc.
		log(JSON.stringify(doc));

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

		// OK, now we have a report of PATTERN_SAFE or PATTERN_VULNERABLE.
		// Run SAFE through check-regex.pl.
		// Run VULNERABLE through validate-vuln.pl.
		// No matter the outcome, doc should be removed from uploadCollection.
		//
		// validateSafe and validateVuln are hideously blocking, but whatcha gonna do?
		// Could parallelize to multiple cores using child_process.exec instead of child_process.execSync.
		const deleteUploadDoc = function() { return deleteDoc(uploadCollection, doc); };

		if (doc.result === PATTERN_SAFE) {
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
			if (accurateDoc.result === PATTERN_SAFE) {
				log(`Truly safe`);
			}
			else {
				log(`Not truly safe -- FALSE REPORT`);
			}
			pending.push(insertDoc(lookupCollection, accurateDoc)
									 .then(deleteUploadDoc, deleteUploadDoc));
		}
		else if (doc.result === PATTERN_VULNERABLE) {
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
				pending.push(insertDoc(lookupCollection, doc)
					           .then(deleteUploadDoc, deleteUploadDoc));
				return;
			}
			else {
				log(`Not truly vuln -- FALSE REPORT`);
				pending.push(deleteUploadDoc());
				return;
			}
		}
		else {
			log(`Unsupported result type ${doc.result}`);
			pending.push(deleteUploadDoc());
			return;
		}

	}, (error, obj) => {
		log(`Awaiting ${pending.length} promises (error ${error})`);
		// Could be MongoClient errors. Ignore.
		const pendingAllResolve = pending.map(reflect);
		const allPending = Promise.all(pendingAllResolve);
		allPending.then((result) => {
			log(`Done`);
			return client.close();
		});
	});
})
.catch((e) => {
	log(`db error: ${e}`);
	return Promise.resolve(false);
});

//////////////////////////////////////

function reflect(promise){
	return promise.then(
		function(v){ return {v:v, status: "resolved" }},
		function(e){ return {e:e, status: "rejected" }}
	);
}

function log(msg) {
	console.error(msg);
}

function insertDoc(collection, doc) {
	log(`insertDoc: Inserting ${doc._id}: ${JSON.stringify(doc)}`);
	// If document already exists, overwrite it.
	// This addresses cases where evilInput is discovered after
	// an initial conclusion of SAFE, e.g. after the introduction
	// of a new detector.
	return collection.findOneAndReplace({_id: doc._id}, doc, {upsert: true});
	//return collection.insert(doc);
}

function deleteDoc(collection, doc) {
	log(`deleteDoc: Deleting ${doc._id}`);
	return collection.deleteOne({_id: doc._id});
}

// Return true if doc is truthful (describes a vulnerable regex), else false.
function validateVuln(doc) {
	const validateVulnQuery = { pattern: doc.pattern, language: doc.language, evilInput: doc.evilInput, nPumps: 250000, timeLimit: 1 };

	const tmpFile = `/tmp/validate-uploads-${process.pid}.json`;
	fs.writeFileSync(tmpFile, JSON.stringify(validateVulnQuery));

	try {
		const stdout = child_process.execSync(`${process.env.VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl ${tmpFile} 2>/dev/null`, {encoding: 'utf8'});
		const result = JSON.parse(stdout);
		log(JSON.stringify(result));
		return result.timedOut === 1;
	} catch (e) {
		log(`Error: ${JSON.stringify(e)}`);
		return false;
	} finally {
		fs.unlinkSync(tmpFile);
	}

	return false;
}

// Given an untrusted doc, query check-regex.pl.
// Return a trusted doc.
// Timeouts are treated as safe -- prefer false negatives to false positives.
function determineSafety(doc) {
	const checkRegexQuery = { pattern: doc.pattern, validateVuln_language: doc.language, validateVuln_nPumps: 250000, validateVuln_timeLimit: 1 };

	const tmpFile = `/tmp/validate-uploads-${process.pid}.json`;
	fs.writeFileSync(tmpFile, JSON.stringify(checkRegexQuery));

	const safeDoc = { _id: doc._id, pattern: doc.pattern, language: doc.language, result: PATTERN_SAFE };
	try {
		const stdout = child_process.execSync(`${process.env.VULN_REGEX_DETECTOR_ROOT}/bin/check-regex.pl ${tmpFile} 2>/dev/null`, {encoding: 'utf8'});
		const result = JSON.parse(stdout);
		log(JSON.stringify(result));
		if (result.isVulnerable && result.validateReport.timedOut) {
			log(`Vulnerable! Client lied.`);
			return {
				_id: doc._id,
				pattern: doc.pattern,
				language: doc.language,
				result: PATTERN_VULNERABLE,
				evilInput: result.validateReport.evilInput
			};
		}
	} catch (e) {
		log(`Error: ${JSON.stringify(e)}`);
		return safeDoc;
	} finally {
		fs.unlinkSync(tmpFile);
	}

	return safeDoc;
}
