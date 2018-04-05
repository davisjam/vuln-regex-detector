# Summary

This is the server side of the vulnerable regex cache.
Clients ask it whether their regexes are vulnerable.
It responds to client requests with "VULNERABLE", "SAFE", "UNKNOWN", or "INVALID".
For regexes it has not seen before, it returns "UNKNOWN", and adds it to a background queue for evaluation.

# API

The server responds to POSTs to the following paths:

- `/api/lookup`
- `/api/update`

The body of the POST must be JSON, described below.

## /api/lookup

Client wants to know if a regex is vulnerable.
Client must supply both pattern and language, since regex vulnerability varies by language.
Supported languages: javascript perl php python ruby

Sample body:

```
{
	"pattern":"(a+)+$",
	"language":"javascript",
	"requestType":"LOOKUP_ONLY",
}
```

If the client plans to compute its own result if the server doesn't know, use requestType "LOOKUP" instead.
If the client further finds it to be vulnerable, this will save the server time when it calls `/api/update`.

The server responds to requests with e.g.:

```
{
	...
	"result": "UNKNOWN"
	...
}
```

or

```
{
	...
	"result": {
		...
		"result": "VULNERABLE" <-- Could also be "SAFE"
		"evilInput": ...
		...
	}
	...
}
```

If the server replies "UNKNOWN", the regex is placed in its background queue for subsequent analysis.
Try querying the server again after a few minutes.

Here's an example query:

```
curl -d '{"pattern":"(a+)+$","language":"javascript","requestType":"LOOKUP_ONLY"}' -H 'Content-Type: application/json' -X POST https://toybox.cs.vt.edu:8000/api/lookup --verbose
```

## /api/update

Client claims to have run `check-regex.pl` itself and uploads the answer.
If it finds the regex vulnerable it includes proof: the evil input.

The server doesn't trust the client, but when there's proof of vulnerability
this saves the server time during validation.

Sample body:

```
{
	"pattern":"(a+)+$",
	"language":"javascript",
	"requestType":"UPDATE",
	"result": "VULNERABLE",
	"evilInput": {
		"suffix":"!",
		"pumpPairs": [
			{
				"prefix":"a",
				"pump":"aa"
			}
		]
	}
}
```

# Implementation

## Database

The server uses a [MongoDB](https://www.mongodb.com/) backend.
The database is named `regexCache` has two tables: `lookup` and `upload`.
- The `lookup` table is trusted and is checked to respond to `/api/lookup`.
- The `upload` table is untrusted and is updated via `/api/update`.

The IDs of MongoDB documents are composed by concatenating the pattern with the language.

## Validation

When the `validate-uploads.js` program runs, it goes through every document in `upload` and runs `check-regex.pl` against it.
It adds each document to the `lookup` table, marked as "VULNERABLE" or "SAFE".

# Consent and privacy

By sending vulnerability queries to our server, you are sending us:
1. The regex.
2. The programming language (since vulnerabilities vary by language).

Obviously we will also get metadata like:
1. Your IP address.
2. The current time.

Queries are sent using HTTPS so only you and we will know about them.

If this is unacceptable, you can set up your own server using this source code.
See [here](https://github.com/davisjam/vuln-regex-detector/blob/master/src/cache/README.md) for instructions.

## Storage

We will save your anonymized queries to accelerate future lookups (yours and anyone else who makes the same query).

## Possible uses of your queries

1. We may analyze queries in aggregate to learn how our tools are being adopted and how regexes are being used in practice.
2. We may release the anonymized queries (no IP address) to facilitate future research, e.g. in the form of a giant database of the regexes used by practitioners.
