'use strict';

/* Dependencies. */
const https = require('https');
const syncRequest = require('sync-request');

/* Globals. */
const REQUEST_LOOKUP_ONLY = 'LOOKUP_ONLY'; // Will only make a lookup, won't be submitting an UPDATE later.

const RESPONSE_VULNERABLE = 'VULNERABLE';
const RESPONSE_SAFE = 'SAFE';
const RESPONSE_UNKNOWN = 'UNKNOWN';
const RESPONSE_INVALID = 'INVALID';

const DEFAULT_CONFIG = {
	hostname: 'toybox.cs.vt.edu',
	port: 8000
};

const LOGGING = false;
const USE_CACHE = true;

/* Map pattern to RESPONSE_VULNERABLE or RESPONSE_SAFE in case of duplicate queries.
 * We do not cache RESPONSE_UNKNOWN or RESPONSE_INVALID responses since these might change. */
let patternCache = {};

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
			if (USE_CACHE) {
				/* Check cache to avoid I/O. */
				const cacheHit = checkCache(_pattern);
				if (cacheHit !== RESPONSE_UNKNOWN) {
					log(`Cache hit: ${cacheHit}`);
					return resolve(cacheHit);
				}
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
					if (USE_CACHE) {
						updateCache(postObject.pattern, result);
					}

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

	if (USE_CACHE) {
		/* Check cache to avoid I/O. */
		const cacheHit = checkCache(_pattern);
		if (cacheHit !== RESPONSE_UNKNOWN) {
			log(`Cache hit: ${cacheHit}`);
			return cacheHit;
		}
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
		if (USE_CACHE) {
			updateCache(postObject.pattern, result);
		}

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
 **********/

function updateCache (pattern, response) {
	if (!USE_CACHE) {
		return;
	}

	/* Only cache VULNERABLE|SAFE responses. */
	if (response !== RESPONSE_VULNERABLE && response !== RESPONSE_SAFE) {
		return;
	}

	if (!patternCache.hasOwnProperty(pattern)) {
		patternCache[pattern] = response;
	}
}

/* Returns RESPONSE_{VULNERABLE|SAFE} on hit, else RESPONSE_UNKNOWN. */
function checkCache (pattern) {
	if (!USE_CACHE) {
		return RESPONSE_UNKNOWN;
	}

	const hit = patternCache[pattern];
	if (hit) {
		log(`checkCache: pattern ${pattern}: hit in patternCache\n  ${JSON.stringify(patternCache)}`);
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
