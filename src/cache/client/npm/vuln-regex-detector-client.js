'use strict';

/* Dependencies. */
const https = require('https');

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

const LOGGING = true;

/**
 * @regex: RegExp or string (e.g. /re/ or 're')
 * @config: object with fields: hostname port
 *   default: 'toybox.cs.vt.edu', '8000'
 */
function checkRegex (regex, config) {
	let _pattern;
	let _config;

	/* Validate args. */
	// regex
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
		return Promise.reject(RESPONSE_INVALID);
	}

	// config
	if (config && config.hasOwnProperty('hostname') && config.hasOwnProperty('port')) {
		_config = config;
	} else {
		_config = DEFAULT_CONFIG;
	}

	log(`Input OK. _pattern /${_pattern}/ _config ${JSON.stringify(_config)}`);

	// Prep POST request.
	const postObj = {
		pattern: _pattern,
		language: 'javascript',
		requestType: REQUEST_LOOKUP_ONLY
	};
	const postData = JSON.stringify(postObj);

	const postOptions = {
		hostname: _config.hostname,
		port: _config.port,
		path: '/api/lookup',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength(postData)
		}
	};

	process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // TODO.

	// Wrapper so we can return a Promise.
	function promiseResult (options, data) {
		log(`promiseResult: data ${JSON.stringify(data)}`);
		return new Promise(function (resolve, reject) {
			const req = https.request(options, (res) => {
				log(`Hello in res`);
				res.setEncoding('utf8');

				let response = '';
				res.on('data', (chunk) => {
					log(`Got data`);
					response += chunk;
				});

				res.on('end', () => {
					const fullResponse = JSON.parse(response);
					log(`end: I got ${JSON.stringify(fullResponse)}`);

					let resolveWith;
					if (fullResponse.result === RESPONSE_UNKNOWN) {
						resolveWith = RESPONSE_UNKNOWN;
					} else {
						resolveWith = fullResponse.result.result;
					}
					log(`end: resolving with ${resolveWith}`);
					resolve(resolveWith);
				});
			});

			req.on('error', (e) => {
				log(`Error: ${e}`);
				reject(e);
			});

			// Write data to request body.
			log(`Writing to req:\n${data}`);
			req.write(data);
			req.end();
		});
	}

	return promiseResult(postOptions, postData);
}

/* Helpers. */
function log (msg) {
	if (LOGGING) {
		console.error(msg);
	}
}

/* Public. */

module.exports = {
	test: checkRegex,
	responses: {
		vulnerable: RESPONSE_VULNERABLE,
		safe: RESPONSE_SAFE,
		unknown: RESPONSE_UNKNOWN,
		invalid: RESPONSE_INVALID
	}
};
