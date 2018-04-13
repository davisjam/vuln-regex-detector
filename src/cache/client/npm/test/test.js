/* eslint-env node, mocha */

const vulnRegexDetector = require('..');
const assert = require('assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const remove = require('remove');

// Outcome must be SAFE or UNKNOWN
function assertIsSafeOrUnknown (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.safe ||
		vulnRegexDetector.responses.unknown;
	assert.ok(isOK, `outcome ${outcome} should be safe|unknown`);
}

// Outcome must be VULNERABLE or UNKNOWN
function assertIsVulnerableOrUnknown (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.vulnerable ||
		outcome === vulnRegexDetector.responses.unknown;
	assert.ok(isOK, `outcome ${outcome} should be vulnerable|unknown`);
}

// High-level: must be a non-"INVALID" response
function assertIsOK (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.vulnerable ||
		outcome === vulnRegexDetector.responses.safe ||
		outcome === vulnRegexDetector.responses.unknown;
	assert.ok(isOK, `outcome ${outcome} should be vulnerable|safe|unknown`);
}

// High-level: must be an "INVALID" response
function assertIsInvalid (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.invalid;
	assert.ok(isOK, `outcome ${outcome} should be invalid`);
}

describe('vulnRegexDetector', () => {
	describe('checkRegex', () => {
		describe('input format', () => {
			it('should accept regexes as strings', () => {
				return vulnRegexDetector.test('abc')
					.then(assertIsOK, assertIsOK);
			});

			it('should accept regexes as RegExps', () => {
				return vulnRegexDetector.test(/abc/)
					.then(assertIsOK, assertIsOK);
			});

			it('should reject an undefined regex', () => {
				return vulnRegexDetector.test(undefined)
					.then(assertIsInvalid, assertIsInvalid);
			});

			it('should reject a random object', () => {
				return vulnRegexDetector.test({foo: 1})
					.then(assertIsInvalid, assertIsInvalid);
			});

			it('should accept config', () => {
				return vulnRegexDetector.test('abc', { server: { hostname: vulnRegexDetector.defaultServerConfig.hostname, port: 8000 } })
					.then(assertIsOK, assertIsOK);
			});
		});

		describe('outcome validity', () => {
			it('should label safe as such: simple', () => {
				return vulnRegexDetector.test('abc')
					.then(assertIsSafeOrUnknown, assertIsSafeOrUnknown);
			});

			it('should label safe as such: non-vulnerable star height', () => {
				return vulnRegexDetector.test('(ab+)+$')
					.then(assertIsSafeOrUnknown, assertIsSafeOrUnknown);
			});

			it('should label vulnerable as such: star height', () => {
				return vulnRegexDetector.test('(a+)+$')
					.then(assertIsVulnerableOrUnknown, assertIsVulnerableOrUnknown);
			});

			it('should label vulnerable as such: QOD', () => {
				return vulnRegexDetector.test(/(\d|\w)+$/)
					.then(assertIsVulnerableOrUnknown, assertIsVulnerableOrUnknown);
			});

			it('should label vulnerable as such: QOA', () => {
				return vulnRegexDetector.test(/.*a.*a.*a.*a$/)
					.then(assertIsVulnerableOrUnknown, assertIsVulnerableOrUnknown);
			});
		});

		describe('invalid config', () => {
			it('should reject an invalid host', () => {
				let invalidConfig = {
					server: {
						hostname: 'no such host',
						port: 1
					},
					cache: {
						type: vulnRegexDetector.cacheTypes.none // Otherwise the default persistent cache will save us!
					}
				};
				return vulnRegexDetector.test('abcde', invalidConfig)
					.then((response) => {
						assert.ok(false, `Invalid config ${JSON.stringify(invalidConfig)} should not have resolved (with ${response})`);
					}, (err) => {
						assert.ok(err === vulnRegexDetector.responses.invalid, `Invalid config rejected, but with ${err}`);
					});
			});

			it('should reject an invalid port', () => {
				let invalidConfig = {
					server: {
						hostname: vulnRegexDetector.defaultServerConfig.hostname,
						port: 22
					},
					cache: {
						type: vulnRegexDetector.cacheTypes.none // Otherwise the default persistent cache will save us!
					}
				};
				return vulnRegexDetector.test('abcde', invalidConfig)
					.then((response) => {
						assert.ok(false, `Invalid config ${JSON.stringify(invalidConfig)} should not have resolved (with ${response})`);
					}, (err) => {
						assert.ok(err === vulnRegexDetector.responses.invalid, `Invalid config rejected, but with ${err}`);
					});
			});
		});
	});

	describe('checkRegexSync', () => {
		describe('input format', () => {
			it('should accept regexes as strings', () => {
				assertIsOK(vulnRegexDetector.testSync('abc'));
			});

			it('should accept regexes as RegExps', () => {
				assertIsOK(vulnRegexDetector.testSync(/abc/));
			});

			it('should reject an undefined regex', () => {
				assertIsInvalid(vulnRegexDetector.testSync(undefined));
			});

			it('should reject a random object', () => {
				assertIsInvalid(vulnRegexDetector.testSync({foo: 1}));
			});

			it('should accept config', () => {
				assertIsOK(vulnRegexDetector.testSync('abc', { server: { hostname: vulnRegexDetector.defaultServerConfig.hostname, port: 8000 } }));
			});
		});

		describe('outcome validity', () => {
			it('should label safe as such: simple', () => {
				assertIsSafeOrUnknown(vulnRegexDetector.testSync('abc'));
			});

			it('should label safe as such: non-vulnerable star height', () => {
				assertIsSafeOrUnknown(vulnRegexDetector.testSync('(ab+)+$'));
			});

			it('should label vulnerable as such: star height', () => {
				assertIsVulnerableOrUnknown(vulnRegexDetector.testSync('(a+)+$'));
			});

			it('should label vulnerable as such: QOD', () => {
				assertIsVulnerableOrUnknown(vulnRegexDetector.testSync(/(\d|\w)+$/));
			});

			it('should label vulnerable as such: QOA', () => {
				assertIsVulnerableOrUnknown(vulnRegexDetector.testSync(/.*a.*a.*a.*a$/));
			});
		});

		describe('invalid config', () => {
			it('should reject an invalid host', () => {
				let invalidConfig = {
					server: {
						hostname: 'no such host',
						port: 1
					},
					cache: {
						type: vulnRegexDetector.cacheTypes.none // Otherwise the default persistent cache will save us!
					}
				};
				const response = vulnRegexDetector.testSync('abcde', invalidConfig);
				assert.ok(response === vulnRegexDetector.responses.invalid, `Invalid config ${JSON.stringify(invalidConfig)} returned ${response}`);
			});

			it('should reject an invalid port', () => {
				let invalidConfig = {
					server: {
						hostname: vulnRegexDetector.defaultServerConfig.hostname,
						port: 22
					},
					cache: {
						type: vulnRegexDetector.cacheTypes.none // Otherwise the default persistent cache will save us!
					}
				};
				const response = vulnRegexDetector.testSync('abcde', invalidConfig);
				assert.ok(response === vulnRegexDetector.responses.invalid, `Invalid config ${JSON.stringify(invalidConfig)} returned ${response}`);
			});
		});

		describe('cache', () => {
			const testCacheExpiryPersistentDir = path.join(os.tmpdir(), 'vuln-regex-detector-TEST-cache-expiration-time');
			afterEach('remove testCacheExpiryPersistentDir to set up a clean state for subsequent tests', () => {
				try {
					remove.removeSync(testCacheExpiryPersistentDir);
				} catch (err) {
					// The only expected error is ENOENT from when the cache directory does not exist
					if (err.code !== 'ENOENT') throw err;
				}
			});
			describe('persistent', () => {
				it('should hit cache instead of failing when config.server is invalid', () => {
					const pattern = 'abc';
					// Make sync query to prime local persistent cache.
					let validConfig = { cache: { type: vulnRegexDetector.cacheTypes.persistent } };
					const response1 = vulnRegexDetector.testSync(pattern, validConfig);
					assert.ok(response1 === vulnRegexDetector.responses.safe, `Error, unexpected response for sync query: ${response1}`);

					let invalidConfig = {
						server: {
							hostname: 'no such host',
							port: 1
						},
						cache: {
							type: vulnRegexDetector.cacheTypes.persistent
						}
					};
					const response2 = vulnRegexDetector.testSync(pattern, invalidConfig);
					assert.ok(response2 === vulnRegexDetector.responses.safe, `Query failed: response ${response2}, probably due to my invalid config.server (so cache failed)`);
				});

				it('honors persistentDir', () => {
					const pattern = 'abc';
					const persistentDir = path.join(os.tmpdir(), `vuln-regex-detector-TEST-${process.pid}`);
					const cacheConfig = {
						type: vulnRegexDetector.cacheTypes.persistent,
						persistentDir: persistentDir
					};

					function persistentDirExists () {
						try {
							return fs.statSync(persistentDir).isDirectory();
						} catch (e) {
							return false;
						}
					}

					if (persistentDirExists()) {
						remove.removeSync(persistentDir);
					}

					// Make sync query to prime local persistent cache.
					const response1 = vulnRegexDetector.testSync(pattern, { cache: cacheConfig });
					assert.ok(response1 === vulnRegexDetector.responses.safe, `Error, unexpected response for sync query: ${response1}`);
					assert.ok(persistentDirExists(), `Error, persistentDir ${persistentDir} does not exist after sync query`);

					// Now an invalid config should work.
					let invalidConfig = {
						server: {
							hostname: 'no such host',
							port: 1
						},
						cache: cacheConfig
					};
					const response2 = vulnRegexDetector.testSync(pattern, invalidConfig);
					assert.ok(response2 === vulnRegexDetector.responses.safe, `Query failed: response ${response2}, probably due to my invalid config.server (so cache failed)`);

					// Clean up.
					remove.removeSync(persistentDir);

					// Now a query with an invalid config should fail.
					const response3 = vulnRegexDetector.testSync(pattern, invalidConfig);
					assert.ok(response3 === vulnRegexDetector.responses.invalid, `Query succeeded? response ${response3}`);
				});
				it('should not return an expired cache value', () => {
					const pattern = 'abc';
					const cacheConfig = {
						type: vulnRegexDetector.cacheTypes.persistent,
						persistentDir: testCacheExpiryPersistentDir,
						expirationTime: -1
					};
					// Make sync query to prime local persistent cache, but use negative cache value to ensure expiration.
					let validConfig = { cache: cacheConfig };
					const response1 = vulnRegexDetector.testSync(pattern, validConfig);
					assert.ok(response1 === vulnRegexDetector.responses.safe, `Error, unexpected response for sync query: ${response1}`);

					let invalidConfig = {
						server: {
							hostname: 'no such host',
							port: 1
						},
						cache: cacheConfig
					};
					const response2 = vulnRegexDetector.testSync(pattern, invalidConfig);
					assert.ok(response2 === vulnRegexDetector.responses.invalid, `Query succeeded? response ${response2}. Unless 'no such host' is a valid hostname we must have a cache hit on an expired entry`);
				});
			});

			describe('memory', () => {
				it('should hit cache instead of failing when config.server is invalid', () => {
					const pattern = 'abc';
					// Make sync query to prime local persistent cache.
					let validConfig = { cache: { type: vulnRegexDetector.cacheTypes.memory } };
					const response1 = vulnRegexDetector.testSync(pattern, validConfig);
					assert.ok(response1 === vulnRegexDetector.responses.safe, `Error, unexpected response for sync query: ${response1}`);

					let invalidConfig = {
						server: {
							hostname: 'no such host',
							port: 1
						},
						cache: {
							type: vulnRegexDetector.cacheTypes.memory
						}
					};
					const response2 = vulnRegexDetector.testSync(pattern, invalidConfig);
					assert.ok(response2 === vulnRegexDetector.responses.safe, `Query failed: response ${response2}, probably due to my invalid config.server (so cache failed)`);
				});
				it('should not return an expired cache value', () => {
					const pattern = 'abcde';
					const cacheConfig = {
						type: vulnRegexDetector.cacheTypes.memory,
						expirationTime: -1
					};
					// Make sync query to prime local in-memory cache, but use negative cache value to ensure expiration.
					let validConfig = { cache: cacheConfig };
					const response1 = vulnRegexDetector.testSync(pattern, validConfig);
					assert.ok(response1 === vulnRegexDetector.responses.safe, `Error, unexpected response for sync query: ${response1}`);

					let invalidConfig = {
						server: {
							hostname: 'no such host',
							port: 1
						},
						cache: cacheConfig
					};
					const response2 = vulnRegexDetector.testSync(pattern, invalidConfig);
					assert.ok(response2 === vulnRegexDetector.responses.invalid, `Query succeeded? response ${response2}. Unless 'no such host' is a valid hostname we must have a cache hit on an expired entry`);
				});
			});
		});
	});

	describe('defaultServerConfig', () => {
		it('has hostname', () => {
			return assert.ok(vulnRegexDetector.defaultServerConfig.hostname, 'Missing hostname');
		});

		it('has port', () => {
			return assert.ok(vulnRegexDetector.defaultServerConfig.port, 'Missing port');
		});
	});

	describe('defaultCacheConfig', () => {
		it('has type', () => {
			return assert.ok(vulnRegexDetector.defaultCacheConfig.type, 'Missing type');
		});
	});

	describe('cacheTypes', () => {
		it('has persistent', () => {
			return assert.ok(vulnRegexDetector.cacheTypes.persistent, 'Missing persistent');
		});

		it('has memory', () => {
			return assert.ok(vulnRegexDetector.cacheTypes.memory, 'Missing memory');
		});

		it('has none', () => {
			return assert.ok(vulnRegexDetector.cacheTypes.none, 'Missing none');
		});
	});

	describe('responses', () => {
		it('has vulnerable', () => {
			return assert.ok(vulnRegexDetector.responses.vulnerable, 'Missing vulnerable');
		});

		it('has safe', () => {
			return assert.ok(vulnRegexDetector.responses.safe, 'Missing safe');
		});

		it('has unknown', () => {
			return assert.ok(vulnRegexDetector.responses.unknown, 'Missing unknown');
		});

		it('has invalid', () => {
			return assert.ok(vulnRegexDetector.responses.invalid, 'Missing invalid');
		});
	});
});
