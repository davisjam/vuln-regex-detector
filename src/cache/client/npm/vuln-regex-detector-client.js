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

/* Logging. */
const LOGGING = false;

/* Cache. */
const CACHE_TYPES = {
	persistent: 'persistent',
	memory: 'memory',
	none: 'none'
};

const CACHE_VERSION = '2'; // Cache updated to version 2 to permit an expiration time on cache entries.
// This required an invalidation of previous entries that would never expire and not be in the proper format.

/* Cache: memory. */

/* Default config. */
const defaultServerConfig = {
	hostname: 'toybox.cs.vt.edu',
	port: 8000
};

const defaultCacheConfig = {
	type: CACHE_TYPES.persistent,
	persistentDir: path.join(os.tmpdir(), 'vuln-regex-detector-client-persistentCache'),
	expirationTime: 60 * 60 * 24 * 7 // 7 days in seconds
};

/**********
 * Functions.
 **********/

/**
 * @param regex: RegExp or string (e.g. /re/ or 're')
 * @param [config]: provide a config object like this:
 *  {
 *    server: {
 *      hostname: 'toybox.cs.vt.edu',
 *      port: 8000
 *    },
 *    cache: {
 *      type: cacheTypes.persistent,
 *      [persistentDir]: '/tmp/vuln-regex-detector-client-persistentCache'
 *    }
 *  }
 *
 * Config defaults if not provided:
 *   server: indicated in the example. This is a research server at Virginia Tech.
 *   cache: 'persistent' with persistentDir in a subdir of os.tmpdir().
 *
 * @returns Promise fulfilled with responses.X or rejected with responses.invalid.
 */
function checkRegex (_regex, _config) {
	let pattern;
	let config;

	/* Handle args. */
	try {
		[pattern, config] = handleArgs(_regex, _config);
	} catch (e) {
		return Promise.reject(RESPONSE_INVALID);
	}
	log(`Input OK. pattern /${pattern}/ config ${JSON.stringify(config)}`);

	let postObject = generatePostObject(pattern);
	let postBuffer = JSON.stringify(postObject);
	let postHeaders = generatePostHeaders(config, Buffer.byteLength(postBuffer));

	// Wrapper so we can return a Promise.
	function promiseResult (options, data) {
		log(`promiseResult: data ${data}`);
		return new Promise((resolve, reject) => {
			/* Check cache to avoid I/O. */
			const cacheHit = checkCache(config, pattern);
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
					updateCache(config, postObject.pattern, result);

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
 * @param regex: see checkRegex API
 * @param [config]: see checkRegex API
 *
 * @returns synchronous result: RESPONSE_X
 *
 * Since this makes a synchronous HTTP query it will be slow.
 */
function checkRegexSync (_regex, _config) {
	let pattern;
	let config;

	/* Handle args. */
	try {
		[pattern, config] = handleArgs(_regex, _config);
	} catch (e) {
		log(e);
		log(`Invalid input: _regex ${JSON.stringify(_regex)} _config ${JSON.stringify(_config)}`);
		return RESPONSE_INVALID;
	}
	log(`Input OK. pattern /${pattern}/ config ${JSON.stringify(config)}`);

	/* Check cache to avoid I/O. */
	const cacheHit = checkCache(config, pattern);
	if (cacheHit !== RESPONSE_UNKNOWN) {
		log(`Cache hit: ${cacheHit}`);
		return cacheHit;
	}

	let postObject = generatePostObject(pattern);
	let postBuffer = JSON.stringify(postObject);
	let postHeaders = generatePostHeaders(config, Buffer.byteLength(postBuffer));
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
		updateCache(config, postObject.pattern, result);

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
 * @returns: [pattern, config] or throws exception
 */
function handleArgs (_regex, _config) {
	/* Identify regex pattern. */
	let pattern;
	if (_regex) {
		if (typeof _regex === 'string') {
			pattern = _regex;
		} else {
			try {
				pattern = _regex.source;
			} catch (e) {
				log(`Invalid regex:`);
				log(_regex);
			}
		}
	} else {
		log(`Invalid regex: none provided`);
	}
	if (!pattern) {
		let errObj = { msg: 'Invalid args' };
		throw errObj;
	}

	/* Identify config. Accept a variety of flavors and fall back to defaults as needed. */
	let config = {};
	if (!_config) {
		config.server = defaultServerConfig;
		config.cache = defaultCacheConfig;
	} else {
		config.server = handleServerConfig(_config.server);
		config.cache = handleCacheConfig(_config.cache);
	}

	return [pattern, config];
}

/* Helper for handleArgs: config.server. */
function handleServerConfig (serverConfig) {
	if (!serverConfig) {
		return defaultServerConfig;
	} else if (!serverConfig.hasOwnProperty('hostname') || !serverConfig.hasOwnProperty('port')) {
		return defaultServerConfig;
	}

	return serverConfig;
}

/* Helper for handleArgs: config.cache. */
function handleCacheConfig (cacheConfig) {
	if (!cacheConfig) {
		return defaultCacheConfig;
	}

	// Must have valid type.
	if (!cacheConfig.hasOwnProperty('type') || !CACHE_TYPES.hasOwnProperty(cacheConfig.type)) {
		cacheConfig.type = CACHE_TYPES.persistent;
	}

	// If type is persistent, need persistentDir.
	if (cacheConfig.type === CACHE_TYPES.persistent && !cacheConfig.hasOwnProperty('persistentDir')) {
		cacheConfig.persistentDir = defaultCacheConfig.persistentDir;
	}

	// expirationTime must be an integer value
	if (!cacheConfig.hasOwnProperty('expirationTime') || !Number.isInteger(cacheConfig.expirationTime)) {
		cacheConfig.expirationTime = defaultCacheConfig.expirationTime;
	}

	return cacheConfig;
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
		hostname: config.server.hostname,
		port: config.server.port,
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

function useCache (config) {
	return config.cache.type !== CACHE_TYPES.none;
}

function updateCache (config, pattern, response) {
	if (!useCache(config)) {
		return;
	}

	/* Only cache VULNERABLE|SAFE responses. */
	if (response !== RESPONSE_VULNERABLE && response !== RESPONSE_SAFE) {
		return;
	}

	/* This entry will expire config.expirationTime seconds from now. */
	const expirationTimeInMilliseconds = 1000 * config.cache.expirationTime;
	const expiryDate = new Date(Date.now() + expirationTimeInMilliseconds);
	const wrappedResponse = {
		response: response,
		validUntil: expiryDate.toISOString()
	};

	return kvPut(config, pattern, wrappedResponse);
}

/* Returns RESPONSE_{VULNERABLE|SAFE} on hit, else RESPONSE_UNKNOWN on miss or disabled. */
function checkCache (config, pattern) {
	if (!useCache(config)) {
		return RESPONSE_UNKNOWN;
	}

	const valueRetrieved = kvGet(config, pattern);
	if (valueRetrieved === RESPONSE_UNKNOWN) {
		return RESPONSE_UNKNOWN;
	}
	/* Check if the cache entry has expired. */
	const lastValidDate = new Date(valueRetrieved.validUntil);
	if (lastValidDate <= Date.now()) {
		/* The cache entry has expired. */
		return RESPONSE_UNKNOWN;
	}
	return valueRetrieved.response;
}

function kvPut (config, key, value) {
	/* Put in the appropriate cache. */
	switch (config.cache.type) {
	case CACHE_TYPES.persistent:
		return kvPutPersistent(config, key, value);
	case CACHE_TYPES.memory:
		return kvPutMemory(key, value);
	default:
		return RESPONSE_UNKNOWN;
	}
}

function kvGet (config, key) {
	/* Get from the appropriate cache. */
	switch (config.cache.type) {
	case CACHE_TYPES.persistent:
		return kvGetPersistent(config, key);
	case CACHE_TYPES.memory:
		return kvGetMemory(key);
	default:
		return RESPONSE_UNKNOWN;
	}
}

/* Persistent KV. */

/* Returns true if initialized, false on initialization failure. */
function initializeKVPersistent (config) {
	/* NB Makes FS syscalls each time in case config changes during lifetime.
	 * Could cache the set of initialized dirs if this is a performance issue. */

	/* First try a mkdir. Dir might exist already. */
	try {
		fs.mkdirSync(config.cache.persistentDir);
	} catch (e) {
	}

	/* If we have a dir now, we're happy.
	 * This also works if persistentDir is a symlink. */
	try {
		const stats = fs.lstatSync(config.cache.persistentDir);
		if (stats.isDirectory()) {
			return true;
		} else {
			return false;
		}
	} catch (e) {
		/* Hmm. */
		return false;
	}
}

function kvPersistentFname (config, key) {
	/* Need something we can safely use as a file name.
	 * Keys are patterns and might contain /'s or \'s.
	 *
	 * Using a hash might give us false reports on collisions, but this is
	 * exceedingly unlikely in typical use cases (a few hundred regexes tops). */
	const hash = crypto.createHash('md5').update(key).digest('hex');
	const fname = path.join(config.cache.persistentDir, `${hash}-v${CACHE_VERSION}.json`);
	return fname;
}

function kvPutPersistent (config, key, value) {
	if (!initializeKVPersistent(config)) {
		log(`kvPutPersistent: could not initialize`);
		return;
	}

	try {
		/* This must be atomic in case of concurrent put and get from different processes.
		 * Hence the use of a tmp file and rename. */
		const fname = kvPersistentFname(config, key);
		const tmpFname = `${fname}-${process.pid}-tmp`;
		log(`kvPutPersistent: putting result in ${fname}`);
		fs.writeFileSync(tmpFname, JSON.stringify({key: key, value: value}));
		fs.renameSync(tmpFname, fname);
	} catch (e) {
		/* Ignore failures. */
	}
}

function kvGetPersistent (config, key) {
	if (!initializeKVPersistent(config)) {
		return RESPONSE_UNKNOWN;
	}

	try {
		const fname = kvPersistentFname(config, key);
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
let pattern2response = {};

function kvPutMemory (key, value) {
	pattern2response[key] = value;
}

function kvGetMemory (key) {
	const hit = pattern2response[key];
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
	/* Core APIs. */
	test: checkRegex,
	testSync: checkRegexSync,

	/* Config. */
	defaultServerConfig: defaultServerConfig, // makes testing easier
	defaultCacheConfig: defaultCacheConfig, // makes testing easier
	cacheTypes: {
		persistent: CACHE_TYPES.persistent,
		memory: CACHE_TYPES.memory,
		none: CACHE_TYPES.none
	},

	/* Interpreting API responses. */
	responses: {
		vulnerable: RESPONSE_VULNERABLE,
		safe: RESPONSE_SAFE,
		unknown: RESPONSE_UNKNOWN,
		invalid: RESPONSE_INVALID
	}
};
