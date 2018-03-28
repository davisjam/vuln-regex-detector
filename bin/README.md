# Summary

Scripts to drive vulnerable regex analysis for different granularities of inputs.

# Scripts

1. `check-repo.pl`: Check a GitHub repo.
2. `check-tree.pl`: Check a tree of files.
3. `check-file.pl`: Check a file.
4. `check-regex.pl`: Check a regex.

## `check-repo.pl`

Input format: JSON object with keys:
- 'url': The root of the tree whose files we should test.
- \['cloneRepo\_type'\]': 'git', 'svn', etc. Otherwise we'll try all possibilities.
- \['cloneRepo\_timeout'\]: how long to wait before giving up on the clone, in seconds.
- \['X'\]: Parms for `check-tree.pl`

## `check-tree.pl`

Input format: JSON object with keys:
- 'root': The root of the tree whose files we should test.
- 'X': Parms for `check-file.pl`.

## `check-file.pl`

Input format: JSON object with keys:
- 'file': The name of the file whose regexes we should extract.
- \['extractRegexes\_X'\]: where X is one of the fields for `extract-regexes.pl`.
- \['X'\]: Parms for `check-regex.pl`.

## `check-regex.pl`

Input format: JSON object with keys:
- 'pattern': The regex pattern to test.
- \['detectVuln\_X'\]: where X is one of the fields for `detect-vuln.pl`.
- 'validateVuln\_X': where X is one of the fields for `validate-vuln.pl`.

## Defaults

These scripts set appropriate limits by default, e.g. on `detectVuln\_memoryLimit` (8GB) and `detectVuln\_timeLimit` (60 seconds).

# Requirements

1. Set the environment variable `VULN_REGEX_DETECTOR_ROOT` to the repo root.
2. You must have run the `configure` script in the repo root.
