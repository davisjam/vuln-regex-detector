# Summary

In JavaScript, regular expressions (regexes) can be "vulnerable": susceptible to [catastrophic backtracking](https://www.regular-expressions.info/catastrophic.html).
If your application is used on the client side, this can be a performance issue.
On the server side, this can expose you to Regular Expression Denial of Service ([REDOS](https://en.wikipedia.org/wiki/ReDoS)).

This module lets you check a regex for vulnerability.

# Example

```javascript
const vulnRegexDetector = require('vuln-regex-detector');

vulnRegexDetector.test('(a+)+$')
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
- functions `test` and `testSync`
- a set of responses `responses`

## test

```javascript
/**
 * @regex: RegExp or string (e.g. /re/ or 're')
 * @config: object with fields: hostname port
 *   default: 'toybox.cs.vt.edu', '8000'
 *
 * returns a Promise fulfilled with a vulnerable/safe/unknown or rejected with invalid.
 */
vulnRegexDetector.test (regex, config)
```

## testSync

```javascript
/**
 * @regex: RegExp or string (e.g. /re/ or 're')
 * @config: object with fields: hostname port
 *   default: 'toybox.cs.vt.edu', '8000'
 *
 * returns with vulnerable/safe/unknown/invalid.
 */
vulnRegexDetector.testSync (regex, config)
```

NB: This API makes synchronous HTTP queries, which can be slow. You should probably not use it.

## responses

If fulfilled, the returned Promise gets one of the following values:
- `responses.vulnerable`
- `responses.safe`
- `responses.unknown`

If rejected, the returned Promise gets the value:
- `responses.invalid`

# Implementation

This module queries a server hosted at Virginia Tech.
When you use it, your regex will be shipped (via HTTPS) to the server and tested there.

If the regex has not been seen before, the server will respond "unknown" and test it in the background.
The server cannot test synchronously because testing is expensive (potentially minutes) and there might be a long line.

If the server has not seen the regex before, it should have an answer if you query it again in a few minutes.

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

# License

MIT
