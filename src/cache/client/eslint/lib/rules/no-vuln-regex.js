/**
 * @fileoverview Catch vulnerable regexes.
 * @author Jamie Davis
 */
'use strict';

const vulnRegexDetector = require('vuln-regex-detector');
// const vulnRegexDetector = require('../../../npm/');

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
					let serverConfig = vulnRegexDetector.defaultServerConfig;
					if (process.env.ESLINT_PLUGIN_NO_VULN_REGEX_HOSTNAME && process.env.ESLINT_PLUGIN_NO_VULN_REGEX_PORT) {
						serverConfig = {
							hostname: process.env.ESLINT_PLUGIN_NO_VULN_REGEX_HOSTNAME,
							port: process.env.ESLINT_PLUGIN_NO_VULN_REGEX_PORT
						};
					};

					let cacheConfig = vulnRegexDetector.defaultCacheConfig;
					if (process.env.ESLINT_PLUGIN_NO_VULN_REGEX_PERSISTENT_DIR) {
						cacheConfig = {
							type: vulnRegexDetector.cacheTypes.persistent,
							persistentDir: process.env.ESLINT_PLUGIN_NO_VULN_REGEX_PERSISTENT_DIR
						};
					};

					const config = {
						server: serverConfig,
						cache: cacheConfig
					};

					const response = vulnRegexDetector.testSync(pattern, config);
					if (response === vulnRegexDetector.responses.vulnerable) {
						const report = {
							node,
							messageId: 'unsafeRegexPattern',
							data: {
								pattern: pattern
							}
						};
						context.report(report);
					}
				}
			}
		};
	}
};
