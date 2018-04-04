/**
 * @fileoverview Catch vulnerable regexes.
 * @author Jamie Davis
 */
'use strict';

// ------------------------------------------------------------------------------
// Requirements
// ------------------------------------------------------------------------------

const rule = require('../../../lib/rules/no-vuln-regex');
const RuleTester = require('eslint').RuleTester;

// ------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------

const ruleTester = new RuleTester();
ruleTester.run('no-vuln-regex', rule, {
	valid: [
		'/abc/',
		'/(ab+)+$/',
		'/\\d+a\\d+/',
		'var foo = /regex/',
		'var foo = new RegExp("regex")',
		// This is a false negative. The regex is vulnerable but the static analysis is inadequate.
		'new RegExp("(a+)" + "+$")'
	],

	invalid: [
		{
			code: '/(a+)+$/',
			errors: [{
				messageId: 'unsafeRegexPattern',
				data: {
					pattern: '(a+)+$'
				}
			}]
		},
		{
			code: 'new RegExp(".*a.*a.*a.*a$")',
			errors: [{
				messageId: 'unsafeRegexPattern',
				data: {
					pattern: '.*a.*a.*a.*a$'
				}
			}]
		},
		{
			code: '/(a|a)+$/',
			errors: [{
				messageId: 'unsafeRegexPattern',
				data: {
					pattern: '(a|a)+$'
				}
			}]
		}
	]
});
