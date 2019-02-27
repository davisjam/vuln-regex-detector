#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test a regex to see if it is vulnerable
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;

# Globals.
my $PATTERN_SAFE       = "SAFE";
my $PATTERN_VULNERABLE = "VULNERABLE";
my $PATTERN_UNKNOWN    = "UNKNOWN";
my $PATTERN_INVALID    = "INVALID";

my $REQUEST_LOOKUP = "LOOKUP";
my $REQUEST_UPDATE = "UPDATE";

my $DEBUG = 0;
if ($ENV{REGEX_DEBUG}) {
  $DEBUG = 1;
}

my $tmpFile = "/tmp/check-regex-$$.json";
my $progressFile = "/tmp/check-regex-$$-progress.log";
unlink($tmpFile, $progressFile);

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

# Use cache?
my $useCache = 0;
my $cacheConfigFile = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json";
my $cacheConfig;
if (-f $cacheConfigFile) {
  $cacheConfig = decode_json(&readFile("file"=>$cacheConfigFile));
  if ($cacheConfig->{clientConfig}->{useCache}) {
    &log("Config says to use the cache");
    $useCache = 1;
  }
}
&log("Config says useCache $useCache");

my $detectVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/detect-vuln.pl";
my $validateVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl";
my $cacheClient = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/client/cli/cache-client.js"; # We don't need this to work.

for my $script ($detectVuln, $validateVuln) {
  if (not -x $script) {
    die "Error, could not find script $script\n";
  }
}

# Args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 regex-pattern.json\n";
}

my $queryFile = $ARGV[0];
if (not -f $queryFile) {
  die "Error, no such patternFile $queryFile\n";
}

my $query = decode_json(`cat $queryFile`);

# Handle common variations in args.
my %nick2real = ("regex"    => "pattern",
                 "language" => "validateVuln_language",
                );
for my $nick (keys %nick2real) {
  if (defined $query->{$nick} and not defined $query->{$nick2real{$nick}}) {
    $query->{$nick2real{$nick}} = $query->{$nick};
  }
}

for my $key ("pattern", "validateVuln_language") {
  if (not defined $query->{$key}) {
    die "Error, must provide key $key\n";
  }
}

if (defined $query->{useCache} and not $query->{useCache}) {
  &log("Query says I should not use the cache");
  $useCache = 0;
}

# We can't use the cache if we have no client.
if (not -x $cacheClient) {
  &log("Cannot use cache, could not find cacheClient $cacheClient");
  $useCache = 0;
}

# Query cache?
my $cacheResponse;
my $cacheHit = 0;
if ($useCache) {
  &log("Querying the cache");
  $cacheResponse = &queryCache($query);
  &log("Cache says $cacheResponse->{result}");
  if ($cacheResponse->{result} eq $PATTERN_SAFE or $cacheResponse->{result} eq $PATTERN_VULNERABLE) {
    $cacheHit = 1;
  }
}

my $result;
if ($cacheHit) {
  $result = &translateCacheResponse($cacheResponse);
}
else {
  $result = { "pattern" => $query->{pattern} };

  my %defaults = ("detectVuln_timeLimit"   => 60*1,   # 1 minute in seconds
                  "detectVuln_memoryLimit" => 1024*8, # 8GB in MB. Weideman/java is greedy.
                  # $validateVuln requires nPumps and timeLimit.
                  # Choose sensible defaults.
                  "validateVuln_nPumps"    => 250000, # 250K pumps
                  "validateVuln_timeLimit" => 5,      # 5 seconds
                 );
  for my $key (keys %defaults) {
    if (not defined $query->{$key}) {
      &log("Using default for $key: $defaults{$key}");
      $query->{$key} = $defaults{$key};
    }
  }

  ### Query detectors.

  # Prep a query to $detectVuln.
  my $detectVulnQuery = { "pattern" => $query->{pattern} };

  # Let $detectVuln set these defaults itself.
  if (defined $query->{detectVuln_detectors}) {
    $detectVulnQuery->{detectors} = $query->{detectVuln_detectors};
  }
  if (defined $query->{detectVuln_timeLimit}) {
    $detectVulnQuery->{timeLimit} = $query->{detectVuln_timeLimit};
  }
  if (defined $query->{detectVuln_memoryLimit}) {
    $detectVulnQuery->{memoryLimit} = $query->{detectVuln_memoryLimit};
  }

  # Query $detectVuln.
  &log("Querying detectors");
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($detectVulnQuery));
  my $detectReport = decode_json(&chkcmd("$detectVuln $tmpFile 2>>$progressFile"));
  &log("Detectors said: " . encode_json($detectReport));

  $result->{detectReport} = $detectReport;

  ### Validate any reported vulnerabilities.
 
  # Prep a query to $validateVuln.
  my $validateVulnQuery = { "pattern"   => $query->{pattern},
                            "language"  => $query->{validateVuln_language},
                            "nPumps"    => $query->{validateVuln_nPumps},
                            "timeLimit" => $query->{validateVuln_timeLimit},
                          };

  # See what each detector thought.
  # Bail if any finds a vulnerability so we don't waste time.
  $result->{isVulnerable} = 0;
  for my $do (@{$detectReport->{detectorOpinions}}) {
    # Are we done?
    last if ($result->{isVulnerable});

    # Check this detector's opinion.
    &log("Checking $do->{name} for timeout-triggering evil input");

    # Maybe vulnerable?
    if ($do->{hasOpinion} and $do->{opinion}->{canAnalyze} and not $do->{opinion}->{isSafe}) {
      my $isVariant = ($do->{patternVariant} eq $query->{pattern}) ? 1 : 0;
      &log("$do->{name}: the regex may be vulnerable (isVariant $isVariant)");
      # If unparseable, evilInput is an empty array or has elt 0 'COULD-NOT-PARSE'
      for my $evilInput (@{$do->{opinion}->{evilInput}}) {
        if ($evilInput eq "COULD-NOT-PARSE") {
          &log("  $do->{name}: Could not parse the evil input");
          next;
        }

        # Does this evilInput trigger catastrophic backtracking?
        $validateVulnQuery->{evilInput} = $evilInput;
        my $queryString = encode_json($validateVulnQuery);
        &log("  $do->{name}: Validating the evil input (query: $queryString)");
        &writeToFile("file"=>$tmpFile, "contents"=>$queryString);
        my $report = decode_json(&chkcmd("$validateVuln $tmpFile 2>>$progressFile"));
        if ($report->{timedOut}) {
          &log("  $do->{name}: evil input triggered a regex timeout");
          $result->{isVulnerable} = 1;
          $result->{validateReport} = $report;
          last;
        } else {
          &log("  $do->{name}: evil input did not trigger a regex timeout");
        }
      }
    } else {
      &log("  $do->{name}: says not vulnerable");
    }
  }

  if ($useCache) {
    &log("Updating the cache");
    &updateCache($result);
  }
}

# Cleanup.
unlink($tmpFile, $progressFile) unless $DEBUG;

# Report results.
print STDOUT encode_json($result) . "\n";

exit 0;

######################

# input: ($query) keys: pattern language
# output: ($cacheResponse) keys: pattern language result [evilInput]
sub queryCache {
  my ($query) = @_;

  my $unknownResponse = {
    "pattern"  => $query->{pattern},
    "language" => $query->{language},
    "result"   => $PATTERN_UNKNOWN,
  };

  if (not -x $cacheClient) {
    &log("queryCache: Could not find client $cacheClient");
    return $unknownResponse;
  }

  my $tmpFile = "/tmp/detect-vuln_queryCache-$$.json";
  my $cacheQuery = {
    "pattern"                      => $query->{pattern},
    "language"                     => $query->{language},
    "requestType"                  => $REQUEST_LOOKUP,
    "canDiscloseAnonymizedQueries" => $cacheConfig->{clientConfig}->{canDiscloseAnonymizedQueries},
  };
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($cacheQuery));
  my ($rc, $out) = &cmd("$cacheClient $tmpFile 2>>$progressFile");
  unlink $tmpFile;

  &log("cacheClient: rc $rc out\n$out");

  if ($rc eq 0) {
    my $ret = decode_json($out);

    if (not ref($ret->{result})) {
      &log("ret doesn't have a long result");
      return $unknownResponse;
    }
    if ($ret->{result}->{result} ne $PATTERN_VULNERABLE and $ret->{result}->{result} ne $PATTERN_SAFE) {
      &log("ret has unexpected result $ret->{result}->{result}");
      return $unknownResponse;
    }

    my $cacheResponse = {
      "pattern"  => $query->{pattern},
      "language" => $query->{language},
      "result"   => $ret->{result}->{result},
      "_full"    => $ret,
    };
    if ($ret->{result}->{result} eq $PATTERN_VULNERABLE) {
      $cacheResponse->{evilInput} = $ret->{result}->{result};
    }

    return $cacheResponse;
  }

  return $unknownResponse;
}

# input: ($checkRegexResponse) from a local query
# output: ()
sub updateCache {
  my ($checkRegexResponse) = @_;

  if (not -x $cacheClient) {
    &log("updateCache: Could not find client $cacheClient");
    return;
  }

  # Build "query".
  my $cacheQuery = {
    "pattern"                      => $query->{pattern},
    "language"                     => $query->{language},
    "requestType"                  => $REQUEST_UPDATE,
    "result"                       => $checkRegexResponse->{isVulnerable} ? $PATTERN_VULNERABLE : $PATTERN_SAFE,
    "canDiscloseAnonymizedQueries" => $cacheConfig->{clientConfig}->{canDiscloseAnonymizedQueries},
  };
  if ($checkRegexResponse->{isVulnerable}) {
    $cacheQuery->{evilInput} = $checkRegexResponse->{validateReport}->{evilInput};
  }

  my $tmpFile = "/tmp/detect-vuln_queryCache-$$.json";
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($cacheQuery));
  my ($rc, $out) = &cmd("$cacheClient $tmpFile 2>>$progressFile");
  unlink $tmpFile;

  &log("updateCache: rc $rc out\n$out");
  return;
}

# input: ($cacheResponse) from &queryCache
# output: has all the fields that a local query has, plus '"_fromCache": 1'
sub translateCacheResponse {
  my ($cacheResponse) = @_;

  my $checkRegexResponse = {
    "_fromCache"   => 1,
    "pattern"      => $cacheResponse->{pattern},
    "language"     => $cacheResponse->{language},
  };

  if ($cacheResponse->{result} eq $PATTERN_SAFE) {
    $checkRegexResponse->{isVulnerable} = 0;
  }
  elsif ($cacheResponse->{result} eq $PATTERN_VULNERABLE) {
    $checkRegexResponse->{isVulnerable} = 1;
    $checkRegexResponse->{validateReport} = {
      "pattern"   => $cacheResponse->{pattern},
      "language"  => $cacheResponse->{language},
      "evilInput" => $cacheResponse->{evilInput}
    };
  }

  return $checkRegexResponse;
}

##############################

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or die "Error, could not read $args{file}: $!\n";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

sub cmd {
  my ($cmd) = @_;
  &log("$cmd");
  my $out = `$cmd`;
  my $rc = $? >> 8;

  return ($rc, $out);
}

sub chkcmd {
  my ($cmd) = @_;
  my ($rc, $out) = &cmd($cmd);
  if ($rc) {
    die "Error, cmd <$cmd> gave rc $rc:\n$out\n";
  }

  return $out;
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}
