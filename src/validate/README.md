# Summary

This directory contains validators for different programming languages (viz. their regex engines).

The `check-regex-support.pl` driver accepts (in JSON):
- 'language' (of interest)
- 'pattern' (regex pattern)
- ['input'] (string) -- by default we use "a"

It prints a summary in JSON to STDOUT, including the match behavior.

The `validate-vuln.pl` driver accepts (in JSON):
- 'language' (of interest)
- 'pattern' (regex)
- 'evilInput' (evil input formula)
- 'nPumps' (number of pumps)
- 'timeLimit' (time limit in seconds)

and feeds this into the validator for the appropriate language.
It prints a summary in JSON to STDOUT.

See usage message for details.

# How does a validator work?

A validator tests a particular language (regex engine).

Each validator is a standalone program that accepts a regex pattern and a string.
It builds a regex from this pattern and tests it against the string.

# Why is validation necessary?

1. Detector might assume behavior of a regex engine that is true in some implementations but not in the regex engine of your language(s).
2. Detector might be buggy.

# How do I add a new validator?

It's easy!

1. Identify a not-yet-supported programming language.
2. Accept as input a file name whose contents are a JSON object with keys `pattern` and `input`.
3. Build a regex and match it against the string.
4. Exit.

If your program hangs on evil input, the driver will time it out and report it.
