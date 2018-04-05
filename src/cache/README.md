# Summary

Querying detectors is expensive.
Once a regex has been queried once, there's no need to query it again.
If we can save the result (cache/[memoize](https://en.wikipedia.org/wiki/Memoization) it), we'll get vast speedups.

In addition, the same regexes often appear in multiple projects.
So if two projects use the same regex, this regex can be checked once and the results used in both places.

# Interacting with the cache

- The server side is `server/cache-server.js`. Its API is defined [here](https://github.com/davisjam/vuln-regex-detector/blob/master/src/cache/server/README.md).
- The client sides are in `client/`: `cli/`, `npm/`, and `eslint/`.
	- `cli/`: Used internally via `check-regex.pl`
	- `npm/`: Source for the npm module [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector)
	- `eslint/`: Source for the eslint plugin (npm module) [eslint-plugin-vuln-regex-detector](https://www.npmjs.com/package/eslint-plugin-vuln-regex-detector)

# Configuration

The cache configuration is stored here: `$VULN_REGEX_DETECTOR_ROOT/src/cache/.config.json`.
All parameters are included.
This used by the server as well as the client CLI.

Note: The anonymity parameter is not implemented, open an issue if you want it.

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
4. The server accepts HTTPS connections. See [here](https://certbot.eff.org/) and [here](https://startupnextdoor.com/how-to-obtain-and-renew-ssl-certs-with-lets-encrypt-on-node-js/) for advice. Store your key and cert in `VULN_REGEX_DETECTOR_ROOT/src/cache/server/keys/`: `privkey.pem` and `fullchain.pem`.

## Default

This is the default cache configuration:
- The cache is enabled.
- It queries our server.
- You give us permission to disclose your anonymized queries.
