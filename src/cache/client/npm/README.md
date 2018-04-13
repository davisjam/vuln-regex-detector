# Summary

In JavaScript, regular expressions (regexes) can be "vulnerable": susceptible to [catastrophic backtracking](https://www.regular-expressions.info/catastrophic.html).
If your application is used on the client side, this can be a performance issue.
On the server side, this can expose you to Regular Expression Denial of Service ([REDOS](https://en.wikipedia.org/wiki/ReDoS)).

This module lets you check a regex for vulnerability.

# Example

```javascript
const vulnRegexDetector = require('vuln-regex-detector');

const regex = /(a+)+$/; // RegExp
const pattern = regex.source; // String

const cacheConfig = {
	type: vulnRegexDetector.cacheTypes.persistent
};
const config = {
	cache: cacheConfig
};

/* This runs synchronously so it's expensive.
 * It uses a persistent cache, so subsequent queries in this process or another one
 * can be resolved locally. */
const result = vulnRegexDetector.testSync(regex, config);
console.log(`I got ${result}`);

vulnRegexDetector.test(pattern, config)
	.then((result) => {
		if (result === vulnRegexDetector.responses.vulnerable) {
			console.log('Regex is vulnerable');
		} else if (result === vulnRegexDetector.responses.safe) {
			console.log('Regex is safe');
		} else {
			console.log('Not sure if regex is safe or not');
		}
	});
```

# API

The module exports:
- functions `test` and `testSync` for making queries
- macro `cacheTypes` for use specifying config.cache
- a set of responses `responses` for interpreting results

## test

```javascript
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
 *      [persistentDir]: '/tmp/vuln-regex-detector-client-persistentCache',
 *      [expirationTime]: 60 * 60 * 24 * 7 // 7 days in seconds
 *    }
 *  }
 *
 * Config defaults if not provided:
 *   server: indicated in the example. This is a research server at Virginia Tech.
 *   cache: 'persistent' with persistentDir in a subdir of os.tmpdir() and an expirationTime of 7 days.
 *
 * @returns Promise fulfilled with responses.X or rejected with responses.invalid.
 */
vulnRegexDetector.test (regex, config)
```

## testSync

```javascript
/**
 * @param regex: see checkRegex API
 * @param [config]: see checkRegex API
 *
 * @returns synchronous result: responses.X
 *
 * Since this makes a synchronous HTTP query it will be slow.
 */
vulnRegexDetector.testSync (regex, config)
```

NB: This API makes synchronous HTTP queries, which can be slow. You should not use it in server software.
On an AWS micro instance this API can be called about 200 times per minute.

This API is intended for use in CI contexts where performance is less critical.
For use in CI, see [this module](https://www.npmjs.com/package/eslint-plugin-vuln-regex-detector).
If your application defines many regexes dynamically you might want to write your own CI stage.

## responses

If fulfilled, the returned Promise gets one of the following values:
- `responses.vulnerable`
- `responses.safe`
- `responses.unknown`

If rejected, the returned Promise gets the value:
- `responses.invalid`

# Implementation details

This module queries a server hosted at Virginia Tech.
When you use it, your regex will be shipped (via HTTPS) to the server and tested there.

If the regex has not been seen before, the server will respond "unknown" and test it in the background.
The server cannot test synchronously because testing is expensive (potentially minutes) and there might be a long line.

If the server has not seen the regex before, it should have an answer if you query it again in a few minutes.

If you cannot connect to the server or your query is malformed, you'll get the answer "invalid".

## Optimizations

This module maintains a persistent local cache stored in `os.tmpdir()` to reduce the number of HTTP queries.
The length of time that a result will be stored in the cache before another HTTP query is required is governed by the expirationTime parameter.

## Privacy

By using this module you are consenting to send us your regexes.
If your code is not open-source then feel free to host your own service.
See [here](https://github.com/davisjam/vuln-regex-detector) for details, and specify your service's hostname and port in `config` when you call the API.

We may:
- store them
- analyze properties of your queries
- release the regexes as a public dataset for future researchers

The IP address of any client querying our server will be anonymized.

# Related projects

1. https://github.com/olivo/redos-detector
2. https://github.com/substack/safe-regex
3. https://github.com/google/re2

## How is this module different from safe-regex?

1. This module guarantees *no false positives*. If it reports a vulnerable regex, then there is an attack string that produces catastrophic backtracking in JavaScript (Node.js). If you're curious, you can obtain this attack string by using the `check-regex.pl` tool in [this repo](https://github.com/davisjam/vuln-regex-detector).
2. This module guarantees *far fewer false negatives*. `safe-regex` uses a heuristic called star height which will miss a lot of regexes that are actually dangerous. `safe-regex` misses about 90% of vulnerabilities by my estimate.

# Contributing

Issues and PRs welcome.

# License

MIT
