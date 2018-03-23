# Summary

This directory contains programs to extract the *statically declared regexes* from a program
written any of the supported languages.

It also contains a driver that accepts:
- program name
- [language]

If language is not specified, the driver attempts to discover the correct language.

See usage message for details.

# How does an extractor work?

The most straightforward way to write an extractor is:
1. Load the source code of the program.
2. Build an [AST](https://en.wikipedia.org/wiki/Abstract_syntax_tree).
3. Walk the AST looking for regex declaration nodes.
4. Collect the patterns.
5. Print.

If no AST generator is available, you can also extract regexes with a custom "parser" that targets the use of regexes.

# How do I add a new extractor?

It's easy!

1. Identify a not-yet-supported programming language.
2. Accept as input a file name whose contents are a JSON object with key `sourcePath`.
3. Statically extract all regexes in the file named `sourcePath`. If a regex is dynamically defined then use the special value "DYNAMIC-PATTERN".
4. Emit (to STDOUT) in JSON an object with:
    - key `couldParse` (0 or 1)
    - if `couldParse`, a key `regexes` with value an array whose elements are regex instances: objects with keys: `regex`
