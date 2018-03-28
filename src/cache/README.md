# Summary

Querying detectors is expensive.
Once a regex has been queried once, there's no need to query it again.
If we can save the result (cache/[memoize](https://en.wikipedia.org/wiki/Memoization) it), we'll get vast speedups.

In addition, the same regexes often appear in multiple projects.
So if two projects use the same regex, this regex can be calculated once and the results used in both places.

# How the cache works

Caching is used during the Detect phase.

1. Before `detect-vuln.pl` queries the detectors, it first queries our remote database. If no hit, the detectors are queried locally. This querying is also performed by `check-file.pl` to filter out regexes for `detect-vuln.pl` in a batch, reducing network traffic.
2. After a local detector query, `detect-vuln.pl` sends each new result to our remote database to accelerate subsequent queries.

These are both implemented by `src/client/cache-client.js` using POST queries.

# Consent and privacy

By enabling this service, you will be consenting to send vulnerability queries to our server.
These queries will contain: (1) your regexes, (2) the language in which you are using them.
Because a regex can be safe in one language and vulnerable in another, we need both pieces of information.
For obvious reasons, queries will also include the client's IP address and the current time.

Queries are sent using HTTPS so only you and we will know about them.

## Storage

We will save your anonymized queries to accelerate future lookups (yours and anyone else who also queries these regexes).

## Possible uses of your queries

1. We may analyze queries in aggregate to learn how our tools are being adopted and how regexes are being used in practice.
2. We may release the anonymized queries (no IP address) to facilitate future research, e.g. in the form of a giant database of the regexes used by practitioners.

# Configuration

The cache configuration is stored here: `$VULN_REGEX_DETECTOR_ROOT/src/cache/.config.json`.
All parameters are included.
If you want to set up your own server, see `src/server/cache-server.js`.

## Default

This is the default cache configuration:
- The cache is enabled.
- It queries our server.
- You give us permission to disclose your anonymized queries.
