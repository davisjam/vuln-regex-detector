/* eslint-env node, mocha */

const vulnRegexDetector = require('..');
const assert = require('assert');

// Outcome must be SAFE or UNKNOWN
function assertIsSafeOrUnknown (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.safe ||
		vulnRegexDetector.responses.unknown;
	console.log(`outcome: ${outcome} isOK ${isOK}`);
	assert.ok(isOK, `outcome ${outcome} should be safe|unknown`);
}

// Outcome must be VULNERABLE or UNKNOWN
function assertIsVulnerableOrUnknown (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.vulnerable ||
		outcome === vulnRegexDetector.responses.unknown;
	console.log(`outcome: ${outcome} isOK ${isOK}`);
	assert.ok(isOK, `outcome ${outcome} should be vulnerable|unknown`);
}

// High-level: must be a non-"INVALID" response
function assertIsOK (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.vulnerable ||
		outcome === vulnRegexDetector.responses.safe ||
		outcome === vulnRegexDetector.responses.unknown;
	console.log(`outcome: ${outcome} isOK ${isOK}`);
	assert.ok(isOK, `outcome ${outcome} should be vulnerable|safe|unknown`);
}

// High-level: must be an "INVALID" response
function assertIsInvalid (outcome) {
	const isOK = outcome === vulnRegexDetector.responses.invalid;
	console.log(`outcome: ${outcome} isOK ${isOK}`);
	assert.ok(isOK, `outcome ${outcome} should be invalid`);
}

describe('vulnRegexDetector', () => {
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
});
