# Summary

Scripts to drive vulnerable regex analysis for different granularities of inputs.

# Scripts

1. `check-regex.pl`: Check a regex.
2. `check-file.pl`: Check a file.
3. `check-tree.pl`: Check a tree of files.
4. `check-repo.pl`: Check a GitHub repo.

## `check-regex.pl`

Input format: JSON object with keys:
- 'pattern': The regex pattern to test
- \['detectVuln\_X'\]: where X is one of the fields for `detect-vuln.pl`.
- 'validateVuln\_X': where X is one of the fields for `validate-vuln.pl`. Required: 'validateVuln\_nPumps', 'validateVuln\_timeLimit'.

# Requirements

1. Set the environment variable `VULN_REGEX_DETECTOR_ROOT` to the repo root.
2. You must have run the `configure` script in the repo root.
