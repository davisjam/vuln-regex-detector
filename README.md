# Summary

This project provides tools to scan your projects for vulnerable regexes.
These are regexes that could lead to [catastrophic backtracking](https://www.regular-expressions.info/catastrophic.html).

# Getting started

1. Set the environment variable `VULN_REGEX_DETECTOR_ROOT` to wherever you cloned the repo.
2. Run the `configure` script to install dependencies and build the detectors.
3. Use the scripts in `bin`. See their [README](https://github.com/davisjam/vuln-regex-detector/blob/master/bin/README.md) for details.

# How it works

Scanning a project has three phases:

1. Regex extraction
2. Vulnerability detection
3. Vulnerability validation

## Regex extraction

In this phase regexes are statically extracted from the project's source code.
See [here](https://github.com/davisjam/vuln-regex-detector/blob/master/src/extract/README.md) for more details.

## Vulnerability detection

In this phase the regexes are tested for vulnerability.
See [here](https://github.com/davisjam/vuln-regex-detector/blob/master/src/detect/README.md) for more details.

## Vulnerability validation

In this phase the results of the vulnerability tests are validated.

The vulnerability detectors are not always correct.
Happily, each emits evil input it believes will trigger catastrophic backtracking.
We have *vulnerability validators* to check their recommendation in the language(s) in which you will use the regexes.

# Caveats

In brief, let's review how the analysis works:

1. Identify all statically-declared regexes used anywhere in your source code.
2. Ask detectors what they think about each regex.
3. For any regexes that any detectors flagged as vulnerable, validate in the appropriate language.

Here are the shortcomings of the analysis.

1. **Regex extraction**: It is *static*. If you dynamically define regexes (e.g. `new Regex(patternAsAVariable)`) we do not know about it.
2. **Regex extraction**: It is *input agnostic*, so it detects vulnerable regexes whether or not they are currently exploitable. As long as a vulnerable regex is only used on trusted input, it will not be exploited. If a vulnerable regex is only used in test code, then it is not currently a problem. Judge for yourself how comfortable you feel about keeping non-exploitable vulnerable regexes in your code.
3. **Vulnerability detection**: It is *detector dependent*. All of the detectors have their flaws, and none has received careful testing. Thanks to the validation stage we only report truly vulnerable regexes (high precision/no false positives), but there may be unreported vulnerabilities (risk of low recall/false negatives) e.g. due to bugs or timeouts in the detection phase.

# Supported OSes

The configuration code works on Ubuntu 16.
Everything else should work on any Linux.
Open an issue if you want other distros/OSes and we can discuss.

# Contributing

Contributions welcome!
- If you find a bug, please open an issue.
- If you want to add a feature, open an issue to discuss first and to "claim the territory".

## Enhancing the scan

If you want to enhance the scan, here are the instructions.

1. If you want to add support for a new language, here are the instructions for [regex extraction](https://github.com/davisjam/vuln-regex-detector/blob/master/src/extract/README.md#how-do-i-add-a-new-extractor) and for [vulnerability validation](https://github.com/davisjam/vuln-regex-detector/blob/master/src/validate/README.md#how-do-i-add-a-new-validator).
2. If you want to add a new vulnerability detector, see the [instructions](https://github.com/davisjam/vuln-regex-detector/blob/master/src/detect/README.md#how-do-i-add-a-new-detector).

# Related projects

1. https://github.com/olivo/redos-detector
2. https://github.com/substack/safe-regex
3. https://github.com/google/re2
