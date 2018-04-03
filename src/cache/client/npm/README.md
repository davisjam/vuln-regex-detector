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
- a function `test`
- a set of responses `responses`

## test

```javascript
/**
 * @regex: RegExp or string (e.g. /re/ or 're')
 * @config: object with fields: hostname port
 *   default: 'toybox.cs.vt.edu', '8000'
 *
 * returns a Promise fulfilled with a response or rejected with RESPONSE_INVALID or an error.
 */
vulnRegexDetector.test (regex, config)
```

## responses

If fulfilled, the returned Promise takes on one of the following values:
- `responses.vulnerable`
- `responses.safe`
- `responses.unknown`

If rejected, the returned Promise might be:
- `responses.invalid`

# Implementation

This module queries a server hosted at Virginia Tech.
When you use it, your regex will be shipped (via HTTPS) to the server and tested there.
If the regex has not been seen before, the server will respond "UNKNOWN" and test it in the background.
The server cannot test synchronously because testing is expensive (potentially minutes) and there might be a long line.

## Privacy

By using this module you are consenting to send us your regexes.
If your code is not open-source then you can host your own service.
See [here](https://github.com/davisjam/vuln-regex-detector) for details, and provide your config when you call the API.

We may:
- store them
- analyze properties of your queries
- release the regexes as a public dataset for future researchers

The IP address of any client querying our server will be anonymized.

# License

MIT
