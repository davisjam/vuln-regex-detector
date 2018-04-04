/* eslint-env node, mocha */

const vulnRegexDetector = require('..');
const assert = require('assert');

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
				return vulnRegexDetector.test('abc', { hostname: 'toybox.cs.vt.edu', port: 8000 })
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
				return vulnRegexDetector.test('abcde', { hostname: 'no such host', port: 8000 })
					.then((response) => {
						assert.ok(false, `Invalid config should not have resolved (with ${response})`);
					}, (err) => {
						assert.ok(err === vulnRegexDetector.responses.invalid, `Invalid config rejected, but with ${err}`);
					});
			});

			it('should reject an invalid port', () => {
				return vulnRegexDetector.test('abcde', { hostname: 'toybox.cs.vt.edu', port: 22 })
					.then((response) => {
						assert.ok(false, `Invalid config should not have resolved (with ${response})`);
					}, (err) => {
						assert.ok(err === vulnRegexDetector.responses.invalid, `Invalid config rejected, but with ${err}`);
					});
			});
		});
	});

	describe('checkRegexSync', () => {
		describe('input format', () => {
			it('should accept regexes as strings', () => {
				return assertIsOK(vulnRegexDetector.testSync('abc'));
			});

			it('should accept regexes as RegExps', () => {
				return assertIsOK(vulnRegexDetector.testSync(/abc/));
			});

			it('should reject an undefined regex', () => {
				return assertIsInvalid(vulnRegexDetector.testSync(undefined));
			});

			it('should reject a random object', () => {
				return assertIsInvalid(vulnRegexDetector.testSync({foo: 1}));
			});

			it('should accept config', () => {
				return assertIsOK(vulnRegexDetector.testSync('abc', { hostname: 'toybox.cs.vt.edu', port: 8000 }));
			});
		});

		describe('outcome validity', () => {
			it('should label safe as such: simple', () => {
				return assertIsSafeOrUnknown(vulnRegexDetector.testSync('abc'));
			});

			it('should label safe as such: non-vulnerable star height', () => {
				return assertIsSafeOrUnknown(vulnRegexDetector.testSync('(ab+)+$'));
			});

			it('should label vulnerable as such: star height', () => {
				return assertIsVulnerableOrUnknown(vulnRegexDetector.testSync('(a+)+$'));
			});

			it('should label vulnerable as such: QOD', () => {
				return assertIsVulnerableOrUnknown(vulnRegexDetector.testSync(/(\d|\w)+$/));
			});

			it('should label vulnerable as such: QOA', () => {
				return assertIsVulnerableOrUnknown(vulnRegexDetector.testSync(/.*a.*a.*a.*a$/));
			});
		});

		describe('invalid config', () => {
			it('should reject an invalid host', () => {
				const response = vulnRegexDetector.testSync('abcde', { hostname: 'no such host', port: 8000 });
				assert.ok(response === vulnRegexDetector.responses.invalid, `Invalid config returned ${response}`);
			});

			it('should reject an invalid port', () => {
				const response = vulnRegexDetector.testSync('abcde', { hostname: 'toybox.cs.vt.edu', port: 22 });
				assert.ok(response === vulnRegexDetector.responses.invalid, `Invalid config returned ${response}`);
			});
		});

		describe('cache', () => {
			it('should hit cache on successive duplicate queries', () => {
				for (let i = 0; i < 10; i++) {
					assertIsSafeOrUnknown(vulnRegexDetector.testSync('abc'));
				}
			});
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
