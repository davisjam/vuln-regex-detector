# eslint-plugin-vuln-regex-detector

Detect unsafe regexes.

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

Add `vuln-regex-detector` to the plugins section of your `.eslintrc` configuration file. You can omit the `eslint-plugin-` prefix:

```json
{
    "plugins": [
        "vuln-regex-detector"
    ]
}
```


Then configure the rules you want to use under the rules section.

```json
{
    "rules": {
        "vuln-regex-detector/rule-name": 2
    }
}
```

## Supported Rules

* Fill in provided rules here





