# Summary

Querying detectors is expensive.
Once a regex has been queried once, there's no need to query it again.
If we can save the result (cache/[memoize](https://en.wikipedia.org/wiki/Memoization) it), we'll get vast speedups.

In addition, the same regexes often appear in multiple projects.
So if two projects use the same regex, this regex can be checked once and the results used in both places.

# Interacting with the cache

- The server side is `server/cache-server.js`. It accepts POST queries to `/api/lookup` and `/api/update`.
- The client side is `client/cache-client.js`.

## Generous client

If you do not disable the cache, `check-regex.pl` interacts with the cache in two ways:

1. Before `detect-vuln.pl` queries the detectors, it first queries our server. If no hit, the detectors are queried locally.
2. After a local detector query, `detect-vuln.pl` sends the result to our server to accelerate subsequent queries (thank you!).

It uses `client/cache-client.js` to make these queries.

## Lazy client

You might want to use a cache-only configuration.
This way your client would not use the detectors itself, but would instead rely exclusively on the cache.
If the cache has the regex, great!
Otherwise, say "UNKNOWN" rather than paying the cost of the detectors locally.

One place to use this configuration is in a linter, where performance is more important than accuracy.

With a lazy client, use the `LOOKUP\_ONLY` mode of `client/cache-client.js`.
This tells the server that no subsequent result will be coming from the client.
Then server will answer the query in the background and eventually update its table for future lookups on the same regex.

# Consent and privacy

By enabling this service, you will be consenting to send vulnerability queries to our server.
Each query contains the following data:
1. The regex.
2. The programming language (since vulnerabilities vary by language).

Obviously we will also get metadata like:
1. Your IP address.
2. The current time.

Queries are sent using HTTPS so only you and we will know about them.

## Storage

We will save your anonymized queries to accelerate future lookups (yours and anyone else who also queries these regexes).

## Possible uses of your queries

1. We may analyze queries in aggregate to learn how our tools are being adopted and how regexes are being used in practice.
2. We may release the anonymized queries (no IP address) to facilitate future research, e.g. in the form of a giant database of the regexes used by practitioners.

# Configuration

The cache configuration is stored here: `$VULN_REGEX_DETECTOR_ROOT/src/cache/.config.json`.
All parameters are included.

Note:
- The anonymity parameter is not implemented, open an issue if you want it.
- However, I haven't implemented any query tracking either.

## Setting up your own cache

If you want to set up your own cache:
1. Set up `server/cache-server.js` to run forever.
2. Configure `server/validate-uploads.js` as a flock-guarded cron job.

Here's a sample crontab entry:

```bash
* * * * * jamie PATH=$NODE_BIN:$PATH VULN_REGEX_DETECTOR_ROOT=$VULN_REGEX_DETECTOR_ROOT /usr/bin/flock -w 0 /tmp/VULN_REGEX_DETECTOR-server.lock $NODE_BIN/node $VULN_REGEX_DETECTOR_ROOT/src/cache/server/cache-server.js >> /tmp/VULN_REGEX_DETECTOR-server.log 2>&1
* * * * * jamie PATH=$NODE_BIN:$PATH VULN_REGEX_DETECTOR_ROOT=$VULN_REGEX_DETECTOR_ROOT /usr/bin/flock -w 0 /tmp/VULN_REGEX_DETECTOR-validate.lock $NODE_BIN/node $VULN_REGEX_DETECTOR_ROOT/src/cache/server/validate-uploads.js >> /tmp/VULN_REGEX_DETECTOR-validate.log 2>&1
```

3. Tweak `.config.json` with your server and DB details.

## Default

This is the default cache configuration:
- The cache is enabled.
- It queries our server.
- You give us permission to disclose your anonymized queries.

# Disabling the cache

Edit `.config.json`: set the `useCache` field to `0`.

# Debugging the cache

Hit it with curl:

```
curl -d '{"pattern":"(a+)+$","language":"javascript","requestType":"LOOKUP"}' -H 'Content-Type: application/json' -X POST https://toybox.cs.vt.edu:8000/api/lookup -k --verbose
```
