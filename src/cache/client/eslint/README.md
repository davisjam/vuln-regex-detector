# eslint-plugin-vuln-regex-detector

Detect unsafe regexes.

## Recommended use

This plugin is *not* intended for use with your typical eslint runs.
It uses the eslint framework to identify the files you care about and to have
easy access to an AST from which to extract regexes.

It *does* work with as part of a regular eslint configuration.
However, it will be slow the first few times eslint is triggered until the local cache warms up.

So, how should you use it?
I suggest adding this line to the `scripts` section of your `package.json`:

```
"test:regex": "eslint --plugin vuln-regex-detector --rule '\"vuln-regex-detector/no-vuln-regex\": 2' FILES_YOU_CARE_ABOUT",
```

Then when you run `npm run test:regex`, you'll run your existing eslint rules *plus* identify vulnerable regexes in your code.
This is appropriate for use in your CI.

You should re-use your existing eslint invocation (see the `lint` line in your `package.json` scripts).
You might want to restrict the files you care about, since e.g. vulnerable regexes in `test/` are probably not an issue.

## Configuring

The vuln-regex-detector module lets users specify the server hostname and port, as well as the local cache.

### Server config

Invoke eslint with `ESLINT_PLUGIN_NO_VULN_REGEX_HOSTNAME=... ESLINT_PLUGIN_NO_VULN_REGEX_PORT=...`.

### Cache config

Invoke eslint with `ESLINT_PLUGIN_NO_VULN_REGEX_PERSISTENT_DIR=...`.

## Performance

### Cold cache

From an AWS micro instance, it takes about 30 seconds to scan a project with 100 regexes.

### Steady-state

This plugin relies on [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector) which queries a remote server about regexes.
Once the server gives a firm response (it might say "unknown" for a few minutes), it gets cached locally in the FS.
So after a few uses on the same machine, the plugin's performance will improve.
The improvement will be significant if you have many regexes.

## Installation

You'll first need to install [ESLint](http://eslint.org):

```
$ npm i eslint --save-dev
```

Next, install `eslint-plugin-vuln-regex-detector`:

```
$ npm install eslint-plugin-vuln-regex-detector --save-dev
```

**Note:** If you installed ESLint globally (using the `-g` flag) then you must also install `eslint-plugin-vuln-regex-detector` globally.

## Usage

If you want to use it in every eslint run, update your `.eslintrc` configuration file as follows:

1. Update plugins.


```json
{
    "plugins": [
        "vuln-regex-detector"
    ]
}
```

2. Update rules.

```json
{
    "rules": {
        "vuln-regex-detector/no-vuln-regex": 2
    }
}
```

## Supported Rules

- `no-vuln-regex`: Identify vulnerable regexes in your code.
