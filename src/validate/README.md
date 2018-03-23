# Summary

This directory contains validators for different programming languages (viz. their regex engines).

There is one master driver that accepts:
- language(s) of interest
- regex
- evil input formula
- number of pumps
- timeout

and feeds this into the validator for the appropriate languages.
It prints a summary in JSON to STDOUT.

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
2. Accept as input a file name whose contents are a JSON object with keys 'regex' and 'string'.
3. Build a regex and match it against the string.
4. Exit.

If your program hangs on evil input, the master driver will time it out and report it.
