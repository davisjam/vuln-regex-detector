# Summary

This directory contains vulnerable regex detectors.
These detectors identify regexes that are vulnerable to catastrophic backtracking.

The `detect-vuln.pl` driver accepts:
- 'pattern' (regex pattern to test)
- \['detectors'\] (array of names of detectors to query)
- \['timeLimit'\] (in seconds, time granted to each detector)
- \['memoryLimit'\] (in MB, memory granted to each detector)

and queries the requested detectors on the regex while applying per-detector time and memory limits.
It prints a summary in JSON to STDOUT.

See usage message for details.

# Directory structure

1. After you run `./configure`, the `src/detectors/` dir contains a built version of each detector.
2. The `src/drivers` dir contains a driver for each detector. This layer lets `detect-vuln.pl` query detectors with a uniform interface.

# What is catastrophic backtracking?

## How regex engines work

The regex engine in most languages is what's called a *backtracking* engine.
It builds a non-deterministic finite automata (NFA) to check whether the input string matches the regex.
To implement non-deterministic choices, a backtracking engine saves the current state, then makes one of the possible choices.
It pushes the state onto a stack of possible choices.

If the choice results in a match, it returns.

If the choice results in a mismatch, it pops off of the stack of possible choices and tries a different choice.
This is called backtracking.
When it runs out of possible choices, it returns "mismatch".

## Catastrophic backtracking

Catastrophic backtracking is a condition in which the regex engine backtracks super-linearly in the size of the input.
The degree of backtracking can be polynomial (e.g. `O(n^2)`) or in the worst case exponential (`O(2^n)`).

# Which detectors do we use?

We use detectors that propose evil input.
This excludes heuristics like star height, as popularized by the [safe-regex](https://github.com/substack/safe-regex) project.

These are the detectors we use:

1. RXXR2 (Rathnayake and Thielecke). [Project homepage](http://www.cs.bham.ac.uk/~hxt/research/rxxr2/index.shtml), [paper](https://arxiv.org/pdf/1405.7058.pdf).
2. REXPLOITER (Wustholz, Olivo, Heule, and Dillig). [JAR](http://www.wuestholz.com/downloads/regexcheck.zip), [paper](https://arxiv.org/pdf/1701.04045.pdf).
3. RegexStaticAnalysis (Weideman, van der Merwe, Berglund, and Watson). [Project homepage](https://github.com/NicolaasWeideman/RegexStaticAnalysis), [paper](https://link.springer.com/chapter/10.1007/978-3-319-40946-7_27), [thesis](http://scholar.sun.ac.za/bitstream/handle/10019.1/102879/weideman_static_2017.pdf?sequence=2).
4. ReScue (Shen, Jiang, Xu, Yu, Ma, and Lu). [Project homepage](https://github.com/2bdenny/ReScue), [paper](http://cs.nju.edu.cn/changxu/1_publications/ASE18.pdf).

# How do I add a new detector?

Writing a detector is difficult.
I have no advice on this.

Adding an existing detector is easy!

1. Create a git submodule for the detector.
2. Add any configuration steps necessary (if no git submodule is possible, configuration should download before building it).
3. Write a driver that accepts as input a file name whose contents are a JSON object with keys: `regex`.
4. Emit (to STDOUT) the result in JSON. This is an "opinion" object with keys:
    - `canAnalyze` (0 or 1)
    - `isSafe` (0 or 1)
    - `evilInputs`: array of "evil input" objects with keys:
        - `pumpPairs` array of "pumpPair" objects with keys: `prefix`, `pump`
        - `suffix`
        - If the output from the detector is unparseable, the evil input object should be the string "COULD-NOT-PARSE".
