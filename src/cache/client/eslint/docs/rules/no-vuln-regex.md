# Catch vulnerable regexes. (no-vuln-regex)

Identify vulnerable regexes in your code.
This plugin uses [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector), which queries a remote server for help.

If the server has not seen the regex before then the regex will not be flagged.
If the server later discovers it to be vulnerable, a subsequent eslint pass will report it as vulnerable.

## Rule Details

This rule aims to identify vulnerable regexes in your code.

Examples of **incorrect** code for this rule:

```js
/(a+)+$/;   // star height
/(a|a)+$/;  // QOD
/.*a.*a$/;  // QOA
/\s*#?\s*/; // QOA from [Python core lib](https://github.com/python/cpython/pull/5955)
```

Examples of **correct** code for this rule:

```js
/abc/
/(ab+)+$/
/^\s*(#\s*)?$/
```

## When Not To Use It

This rule sends regexes to a remote server over HTTPS.
Since regexes are part of your source code, if your software is not open-source, you might not want to use this rule.

## Further Reading

- https://github.com/davisjam/vuln-regex-detector
- https://github.com/substack/safe-regex
- https://github.com/google/re2
- https://snyk.io/blog/redos-and-catastrophic-backtracking/
- https://en.wikipedia.org/wiki/ReDoS
