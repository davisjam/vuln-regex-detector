# Summary

This project provides tools to scan your projects for "vulnerable regexes".
These are regexes that could lead to [catastrophic backtracking](https://www.regular-expressions.info/catastrophic.html).

# Getting started

TODO.

# How it works

Scanning a project has three phases:

1. Regex extraction
2. Vulnerability detection
3. Vulnerability validation

## Regex extraction

TODO.

## Vulnerability detection

TODO.

We use ...

1.
2.
3.

## Vulnerability validation

The vulnerability detectors are not always correct.
Happily, each emits evil input it believes will trigger catastrophic backtracking.
We have *vulnerability validators* to check their recommendation in the language(s) in which you will use the regexes.

# Supported OSes

This code works on Ubuntu 16.
Open an issue if you want other OSes and we can discuss.

# Contributing

Contributions welcome!
- If you find a bug, please open an issue.
- If you want to add a feature, open an issue to discuss first and to "claim the territory".

## Enhancing the scan

If you want to enhance the scan, here are the instructions.

1. If you want to add support for a new language, here are the instructions for [regex extraction](https://github.com/davisjam/vuln-regex-detector/blob/master/src/extract/README.md#how-do-i-add-a-new-extractor) and for [vulnerability validation](https://github.com/davisjam/vuln-regex-detector/blob/master/src/validate/README.md#how-do-i-add-a-new-validator).
2. If you want to add a new vulnerability detector, see the [instructions](https://github.com/davisjam/vuln-regex-detector/blob/master/src/detect/README.md).
