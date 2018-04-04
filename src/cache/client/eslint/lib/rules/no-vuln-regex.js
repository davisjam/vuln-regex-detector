/**
 * @fileoverview Catch vulnerable regexes.
 * @author Jamie Davis
 */
'use strict';

const vulnRegexDetector = require('vuln-regex-detector');

// ------------------------------------------------------------------------------
// Rule Definition
// ------------------------------------------------------------------------------

module.exports = {
	meta: {
		docs: {
			description: 'Catch vulnerable regexes.',
			category: 'Security',
			recommended: true,
			url: 'https://github.com/davisjam/vuln-regex-detector'
		},
		fixable: null,
		schema: [],
		messages: {
			unsafeRegexPattern: 'Regex pattern vulnerable to catastrophic backtracking: {{pattern}}'
		}
	},

	create: function (context) {
		/**
		* Get the regex expression
		* @param {ASTNode} node node to evaluate
		* @returns {RegExp|null} Regex if found else null
		* @private
		*
		* Credit: https://github.com/eslint/eslint/blob/master/lib/rules/no-control-regex.js
		*/
		function getRegExpPattern (node) {
			if (node.regex) {
				return node.regex.pattern;
			}
			if (typeof node.value === 'string' &&
				(node.parent.type === 'NewExpression' || node.parent.type === 'CallExpression') &&
				node.parent.callee.type === 'Identifier' &&
				node.parent.callee.name === 'RegExp' &&
				node.parent.arguments[0] === node
			) {
				return node.value;
			}

			return null;
		}

		return {
			Literal (node) {
				const pattern = getRegExpPattern(node);

				if (pattern) {
					const response = vulnRegexDetector.testSync(pattern);
					if (response === vulnRegexDetector.responses.vulnerable) {
						const report = {
							node,
							messageId: 'unsafeRegexPattern',
							data: {
								pattern: pattern
							}
						};
						context.report(report);
					} else {
					}
				}
			}
		};
	}
};
