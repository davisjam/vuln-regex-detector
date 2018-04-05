'use strict';

/**********
 * Dependencies.
 **********/

/* I/O. */
const https = require('https');
const syncRequest = require('sync-request');

/* Persistent cache. */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

/* Misc. */
const os = require('os');

/**********
 * Globals.
 **********/

const REQUEST_LOOKUP_ONLY = 'LOOKUP_ONLY'; // Will only make a lookup, won't be submitting an UPDATE later.

const RESPONSE_VULNERABLE = 'VULNERABLE';
const RESPONSE_SAFE = 'SAFE';
const RESPONSE_UNKNOWN = 'UNKNOWN';
const RESPONSE_INVALID = 'INVALID';

const DEFAULT_CONFIG = {
	hostname: 'toybox.cs.vt.edu',
	port: 8000
};

/* Logging. */
const LOGGING = false;

/* Cache config. */
const CACHE_TYPES = {
	none: 'none',
	memory: 'memory',
	persistent: 'persistent'
};
const CACHE_TYPE = CACHE_TYPES.persistent;

/**********
 * Functions.
 **********/

/**
 * @param regex: RegExp or string (e.g. /re/ or 're')
 * @param config: object with fields: hostname port
 *   default: 'toybox.cs.vt.edu', '8000'
 *
 * returns a Promise fulfilled with a response or rejected with RESPONSE_INVALID.
 */
function checkRegex (regex, config) {
	let _pattern;
	let _config;

	/* Handle args. */
	try {
		[_pattern, _config] = handleArgs(regex, config);
	} catch (e) {
		return Promise.reject(RESPONSE_INVALID);
	}
	log(`Input OK. _pattern /${_pattern}/ _config ${JSON.stringify(_config)}`);

	let postObject = generatePostObject(_pattern);
	let postBuffer = JSON.stringify(postObject);
	let postHeaders = generatePostHeaders(_config, Buffer.byteLength(postBuffer));

	// Wrapper so we can return a Promise.
	function promiseResult (options, data) {
		log(`promiseResult: data ${data}`);
		return new Promise((resolve, reject) => {
			/* Check cache to avoid I/O. */
			const cacheHit = checkCache(_pattern);
			if (cacheHit !== RESPONSE_UNKNOWN) {
				log(`Cache hit: ${cacheHit}`);
				return resolve(cacheHit);
			}

			const req = https.request(options, (res) => {
				res.setEncoding('utf8');

				let response = '';
				res.on('data', (chunk) => {
					log(`Got data`);
					response += chunk;
				});

				res.on('end', () => {
					log(`end: I got ${JSON.stringify(response)}`);

					const result = serverResponseToRESPONSE(response);
					log(`end: result ${result}`);
					updateCache(postObject.pattern, result);

					if (result === RESPONSE_INVALID) {
						return reject(result);
					} else {
						return resolve(result);
					}
				});
			});

			req.on('error', (e) => {
				log(`Error: ${e}`);
				return reject(RESPONSE_INVALID);
			});

			// Write data to request body.
			log(`Writing to req:\n${data}`);
			req.write(data);
			req.end();
		});
	}

	return promiseResult(postHeaders, postBuffer);
}

/**
 * @param regex: RegExp or string (e.g. /re/ or 're')
 * @param config: object with fields: hostname port
 *   default: 'toybox.cs.vt.edu', '8000'
 *
 * returns synchronous result: RESPONSE_X
 *
 * Since this makes a synchronous HTTP query it will be slow.
 */
function checkRegexSync (regex, config) {
	let _pattern;
	let _config;

	/* Handle args. */
	try {
		[_pattern, _config] = handleArgs(regex, config);
	} catch (e) {
		return RESPONSE_INVALID;
	}
	log(`Input OK. _pattern /${_pattern}/ _config ${JSON.stringify(_config)}`);

	/* Check cache to avoid I/O. */
	const cacheHit = checkCache(_pattern);
	if (cacheHit !== RESPONSE_UNKNOWN) {
		log(`Cache hit: ${cacheHit}`);
		return cacheHit;
	}

	let postObject = generatePostObject(_pattern);
	let postBuffer = JSON.stringify(postObject);
	let postHeaders = generatePostHeaders(_config, Buffer.byteLength(postBuffer));
	let url = `https://${postHeaders.hostname}:${postHeaders.port}${postHeaders.path}`;

	try {
		log(`sending syncRequest: method ${postHeaders.method} url ${url} headers ${JSON.stringify(postHeaders.headers)} body ${postBuffer}`);

		/* Send request. */
		const response = syncRequest(postHeaders.method, url, {
			headers: postHeaders.headers,
			body: postBuffer
		});

		/* Extract body as JSON. */
		let responseBody;
		try {
			responseBody = response.getBody('utf8');
		} catch (e) {
			log(`checkRegexSync: Unparseable response ${JSON.stringify(response)}`);
			return RESPONSE_INVALID;
		}
		log(`checkRegexSync: I got ${responseBody}`);

		/* Convert to a RESPONSE_X value. */
		const result = serverResponseToRESPONSE(responseBody);
		updateCache(postObject.pattern, result);

		return result;
	} catch (e) {
		log(`syncRequest threw: ${JSON.stringify(e)}`);
		return RESPONSE_INVALID;
	}
}

/**********
 * Helpers.
 **********/

/**
 * @param regex: Input to checkRegex, etc.
 * @param config: Input to checkRegex, etc.
 *
 * Returns: [pattern, config] or throws exception
 */
function handleArgs (regex, config) {
	let _pattern;
	if (regex) {
		if (typeof regex === 'string') {
			_pattern = regex;
		} else {
			try {
				_pattern = regex.source;
			} catch (e) {
				log(`Invalid regex:`);
				log(regex);
			}
		}
	} else {
		log(`Invalid regex: none provided`);
	}
	if (!_pattern) {
		let errObj = { msg: 'Invalid args' };
		throw errObj;
	}

	// config
	let _config;
	if (config && config.hasOwnProperty('hostname') && config.hasOwnProperty('port')) {
		_config = config;
	} else {
		_config = DEFAULT_CONFIG;
	}

	return [_pattern, _config];
}

/* Return object to be sent over the wire as JSON. */
function generatePostObject (pattern) {
	const postObject = {
		pattern: pattern,
		language: 'javascript',
		requestType: REQUEST_LOOKUP_ONLY
	};

	return postObject;
}

/* Return headers for the POST request. */
function generatePostHeaders (config, payloadSize) {
	const postHeaders = {
		hostname: config.hostname,
		port: config.port,
		path: '/api/lookup',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': payloadSize
		}
	};

	return postHeaders;
}

/* response: raw response from server */
function serverResponseToRESPONSE (response) {
	try {
		const obj = JSON.parse(response);
		if (obj.result === RESPONSE_UNKNOWN) {
			return RESPONSE_UNKNOWN;
		} else {
			return obj.result.result;
		}
	} catch (e) {
		return RESPONSE_INVALID;
	}
}

/**********
 * Cache.
 *
 * The cache in use is controlled by CACHE_TYPE.
 * If CACHE_TYPE is 'none' then APIs behave appropriately.
 * The cache is implemented using a key-value interface.
 *
 * Cache accesses are synchronous.
 * If CACHE_TYPE is 'memory' that's fine.
 * If CACHE_TYPE is 'persistent' then there are some performance concerns.
 * TODO Address this with sync and async versions of the APIs.
 **********/

function useCache () {
	return CACHE_TYPE !== CACHE_TYPES.none;
}

function updateCache (pattern, response) {
	if (!useCache()) {
		return;
	}

	return kvPut(pattern, response);
}

/* Returns RESPONSE_{VULNERABLE|SAFE} on hit, else RESPONSE_UNKNOWN on miss or disabled. */
function checkCache (pattern) {
	if (!useCache()) {
		return RESPONSE_UNKNOWN;
	}

	return kvGet(pattern);
}

function kvPut (key, value) {
	/* Only cache VULNERABLE|SAFE responses. */
	if (value !== RESPONSE_VULNERABLE && value !== RESPONSE_SAFE) {
		return;
	}

	/* Put in the appropriate cache. */
	switch (CACHE_TYPE) {
	case CACHE_TYPES.memory:
		return kvPutMemory(key, value);
	case CACHE_TYPES.persistent:
		return kvPutPersistent(key, value);
	default:
		return RESPONSE_UNKNOWN;
	}
}

function kvGet (key) {
	/* Get from the appropriate cache. */
	switch (CACHE_TYPE) {
	case CACHE_TYPES.memory:
		return kvGetMemory(key);
	case CACHE_TYPES.persistent:
		return kvGetPersistent(key);
	default:
		return RESPONSE_UNKNOWN;
	}
}

/* Persistent KV. */

const PERSISTENT_CACHE_DIR = path.join(os.tmpdir(), 'vuln-regex-detector-client-persistentCache');
log(`PERSISTENT_CACHE_DIR ${PERSISTENT_CACHE_DIR}`);

let kvPersistentInitialized = false;
let kvPersistentCouldNotInitialize = false;

/* Returns true if initialized, false on initialization failure. */
function initializeKVPersistent () {
	/* Tried before? */
	if (kvPersistentInitialized) {
		return true;
	}
	if (kvPersistentCouldNotInitialize) {
		return false;
	}

	/* First time through. */

	/* First try a mkdir. Dir might exist already. */
	try {
		fs.mkdirSync(PERSISTENT_CACHE_DIR);
	} catch (e) {
	}

	/* If we have a dir now, we're happy. */
	try {
		const stats = fs.lstatSync(PERSISTENT_CACHE_DIR);
		if (stats.isDirectory()) {
			kvPersistentInitialized = true;
			return true;
		} else {
			kvPersistentCouldNotInitialize = true;
			return false;
		}
	} catch (e) {
		/* Hmm. */
		kvPersistentCouldNotInitialize = true;
		return false;
	}
}

function kvPersistentFname (key) {
	/* Need something we can safely use as a file name.
	 * Keys are patterns and might contain /'s or \'s.
	 *
	 * Using a hash might give us false reports on collisions, but this is
	 * exceedingly unlikely in typical use cases (a few hundred regexes tops). */
	const hash = crypto.createHash('md5').update(key).digest('hex');
	const fname = path.join(PERSISTENT_CACHE_DIR, `${hash}.json`);
	return fname;
}

function kvPutPersistent (key, value) {
	if (!initializeKVPersistent()) {
		log(`kvPutPersistent: could not initialize`);
		return;
	}

	try {
		/* This must be atomic in case of concurrent put and get from different processes.
		 * Hence the use of a tmp file and rename. */
		const fname = kvPersistentFname(key);
		const tmpFname = `${fname}-${process.pid}-tmp`;
		log(`kvPutPersistent: putting result in ${fname}`);
		fs.writeFileSync(tmpFname, JSON.stringify({key: key, value: value}));
		fs.renameSync(tmpFname, fname);
	} catch (e) {
		/* Ignore failures. */
	}
}

function kvGetPersistent (key) {
	if (!initializeKVPersistent()) {
		return RESPONSE_UNKNOWN;
	}

	try {
		const fname = kvPersistentFname(key);
		log(`kvGetPersistent: getting result from ${fname}`);
		const cont = JSON.parse(fs.readFileSync(fname));
		return cont.value;
	} catch (e) {
		return RESPONSE_UNKNOWN;
	}
}

/* Memory (volatile) KV. */

/* Map pattern to RESPONSE_VULNERABLE or RESPONSE_SAFE in case of duplicate queries.
 * We do not cache RESPONSE_UNKNOWN or RESPONSE_INVALID responses since these might change. */
let memoryPattern2response = {};

function kvPutMemory (key, value) {
	if (!memoryPattern2response.hasOwnProperty(key)) {
		memoryPattern2response[key] = value;
	}
}

function kvGetMemory (key) {
	const hit = memoryPattern2response[key];
	if (hit) {
		log(`kvGetMemory: hit: ${key} -> ${hit}`);
		return hit;
	} else {
		return RESPONSE_UNKNOWN;
	}
}

/**********
 * Utilities.
 **********/

function log (msg) {
	if (LOGGING) {
		console.error(msg);
	}
}

/**********
 * Exports.
 **********/

module.exports = {
	test: checkRegex,
	testSync: checkRegexSync,
	responses: {
		vulnerable: RESPONSE_VULNERABLE,
		safe: RESPONSE_SAFE,
		unknown: RESPONSE_UNKNOWN,
		invalid: RESPONSE_INVALID
	}
};
