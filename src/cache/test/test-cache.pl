#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test the cache: client and server
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;
use Net::Domain qw(hostfqdn);

# Globals
my $PATTERN_VULNERABLE = 'VULNERABLE';
my $PATTERN_SAFE       = 'SAFE';
my $PATTERN_UNKNOWN    = 'UNKNOWN';
my $PATTERN_INVALID    = 'INVALID';

my $REQUEST_LOOKUP      = "LOOKUP";
my $REQUEST_LOOKUP_ONLY = "LOOKUP_ONLY";
my $REQUEST_UPDATE      = "UPDATE";

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $cacheClient = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/client/cli/cache-client.js";
my $cacheServer = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/server/cache-server.js";
my $validateUploads = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/server/validate-uploads.js";
my $resetDB = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/server/reset-db.js";

for my $script ($cacheClient, $cacheServer, $validateUploads, $resetDB) {
  if (not -x $script) {
    die "Error, could not find script $script\n";
  }
}

#### Setup
&log("\n\nSetup\n");

# Start MongoDB.
&log("Starting mongod");
&startMongoDB();

my $CACHE_CONFIG_FILE = &getCacheConfigFileForTesting("$ENV{VULN_REGEX_DETECTOR_ROOT}/src/cache/.config.json");

# Start the server.
&log("Starting the cache server");
my $pid = &startServer();
&log("Cache server has pid $pid");

#### Run tests.
&log("\n\nRunning tests\n");
&runTests();

#### Cleanup.
&log("\n\nCleanup\n");
&log("Killing the cache server");
&chkcmd("kill -9 $pid");

&log("Wiping the Mongo DB");
&resetDB();

exit 0;

######################
# Test cases
######################

# input: ()
# output: (@testCases)
#
# Each test case is a hashref with fields:
#   description -- string
#   queries     -- array of hashrefs with fields:
#      query -- JSON object for input to cache-client.pl
#      expectedResult -- one of $PATTERN_X
#      validateAfter -- if truthy, run &validateUploads() after the query
#
# Test cases are run against a server with an empty DB.
sub getTestCases {
  my @vulnPatterns = (
    # EXP
    "(a+)+\$", # Star height
    "(b+)+\$", # Star height
    "(\\d|\\w)+\$", # QOD
    # POLY
    ".*a.*a.*a.*a\$", # QOA
  );

  my @safePatterns = (
    "(ab+)+\$",
    "abc",
  );

  my @languages = (
    "javascript",
    "python",
  );

  # Define some queries.
  # Focus on $REQUEST_LOOKUP and $REQUEST_LOOKUP_ONLY since these are the key queries.
  
  # language -> requestType -> {safe|vuln} -> queries
  my %lang2queries;
  for my $lang (@languages) {
    for my $requestType ($REQUEST_LOOKUP, $REQUEST_LOOKUP_ONLY) {
      my %queries = ("vuln" => [], "safe" => []);

      for my $pattern (@vulnPatterns) {
        push @{$queries{vuln}}, { "pattern"     => $pattern,
                                  "language"    => $lang,
                                  "requestType" => $requestType,
                                };
      }

      for my $pattern (@safePatterns) {
        push @{$queries{safe}}, { "pattern"     => $pattern,
                                  "language"    => $lang,
                                  "requestType" => $requestType,
                                };
      }

      $lang2queries{$lang}->{$requestType} = \%queries;
    }
  }

  # Build some simple TCs.
  my @simpleTCs = (
    # LOOKUP
    { "description" => "Vulnerable LOOKUP queries without a validate-uploads run yields UNKNOWN-UNKNOWN",
      "queries" => [
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 0,
        },
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 0,
        }
      ],
    },
    { "description" => "Vulnerable LOOKUP queries with a validate-uploads run yields UNKNOWN-UNKNOWN",
      "queries" => [
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 1,
        },
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 0,
        }
      ],
    },
    # LOOKUP_ONLY: Vulnerable
    { "description" => "Vulnerable LOOKUP_ONLY queries without a validate-uploads run yields UNKNOWN-UNKNOWN",
      "queries" => [
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 0,
        },
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 0,
        }
      ],
    },
    { "description" => "Vulnerable LOOKUP_ONLY queries with a validate-uploads run yields UNKNOWN-VULNERABLE",
      "queries" => [
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{vuln}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 1,
        },
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{vuln}->[0],
          "expectedResult" => $PATTERN_VULNERABLE,
          "validateAfter" => 0,
        }
      ],
    },
    # LOOKUP_ONLY: Safe
    { "description" => "Safe LOOKUP_ONLY queries with a validate-uploads run yields UNKNOWN-SAFE",
      "queries" => [
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 1,
        },
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
          "expectedResult" => $PATTERN_SAFE,
          "validateAfter" => 0,
        }
      ],
    },
    # LOOKUP_ONLY: Different languages
    { "description" => "Languages are independent",
      "queries" => [
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 1,
        },
        { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
          "expectedResult" => $PATTERN_SAFE,
          "validateAfter" => 0,
        },
        { "query" => $lang2queries{$languages[1]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
          "expectedResult" => $PATTERN_UNKNOWN,
          "validateAfter" => 1,
        },
        { "query" => $lang2queries{$languages[1]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
          "expectedResult" => $PATTERN_SAFE,
          "validateAfter" => 0,
        }
      ],
    },
  );

  # Hand-craft a more complex TC.
  # LOOKUP_ONLY all vulnerable (no validate) and then one safe (validate).
  # Then LOOKUP_ONLY again and confirm decisions.
  my @beforeQueries = map { { 
                              "query" => $_,
                              "expectedResult" => $PATTERN_UNKNOWN,
                              "validateAfter"=> 0,
                              };
                          } @{$lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{vuln}};
  my $triggerValidate = { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
                          "expectedResult" => $PATTERN_UNKNOWN,
                          "validateAfter"=> 1,
                        };

  my @afterQueries = map { { 
                              "query" => $_,
                              "expectedResult" => $PATTERN_VULNERABLE,
                              "validateAfter"=> 0,
                              };

                         } @{$lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{vuln}};
  push @afterQueries, { "query" => $lang2queries{$languages[0]}->{$REQUEST_LOOKUP_ONLY}->{safe}->[0],
                        "expectedResult" => $PATTERN_SAFE,
                        "validateAfter"=> 0,
                      };

  my $complexTC = { "description" => "Multiple patterns with a validate-upload run yields correct results",
                    "queries" => [@beforeQueries, $triggerValidate, @afterQueries],
                  };

  # Concatenate and return.
  my @TCs = (@simpleTCs, $complexTC);
  return @TCs;
}

sub runTests {
  my @testCases = &getTestCases();
  my $nTCs = scalar(@testCases);

  &log("Running $nTCs test cases");

  my @failedTCs;
  for my $tc (@testCases) {
    &log("\nRunning test case: $tc->{description}\n");
    my $passed = &runTestCase($tc);
    if ($passed) {
      &log("PASSED");
    }
    else {
      &log("FAILED");
      push @failedTCs, $tc;
    }
  }

  my $nFailed = scalar(@failedTCs);
  my $nPassed = $nTCs - $nFailed;

  &log("\nSUMMARY: $nPassed/$nTCs test cases passed");
  if (@failedTCs) {
    &log("Failed cases:");
    for my $tc (@failedTCs) {
      &log("  $tc->{description}");
    }
  }

  return;
}

# input: ($testCase) one TC from &getTestCases
# output: ($passed) 1 if passed, else 0
sub runTestCase {
  my ($testCase) = @_;

  my $queryFile = "/tmp/test-cache-$$-queryFile.json";

  &log("Wiping DB");
  &resetDB();

  my $passed = 1;
  for my $query (@{$testCase->{queries}}) {
    &log("Running query: " . encode_json($query));

    &writeToFile("file"=>$queryFile, "contents"=>encode_json($query->{query}));
    my $out = &queryCache($queryFile);
    &log("Result: " . encode_json($out));

    if (not &resultsMatch($query, $out)) {
      &log("Error, result $out->{result}->{result} does not match expectedResult $query->{expectedResult}");
      $passed = 0;
      last;
    }

    if ($query->{validateAfter}) {
      &validateUploads();
    }

  }

  unlink $queryFile;
  return $passed;
}

# input: ($query, $result)
#  query: one of the queries from a TC
#  result: output from a $cacheClient query
sub resultsMatch {
  my ($query, $result) = @_;

  my $resultResult;
  if ($result->{result} eq "UNKNOWN") {
    $resultResult = $result->{result};
  }
  else {
    $resultResult = $result->{result}->{result};
  }

  if ($query->{expectedResult} eq $resultResult) {
    return 1;
  }
  else {
    &log("expectedResult $query->{expectedResult} resultResult $resultResult");
    return 0;
  }
}


######################
# Semantic helpers
######################

# input: ()
# output: ($testConfigFile) contains cache config for use in testing (127.0.0.1 everywhere!)
sub getCacheConfigFileForTesting {
  my ($cacheConfigFile) = @_;

  # Read.
  my $cacheConfig = decode_json(&readFile("file"=>$cacheConfigFile));

  # Edit for testing.
  my $host = hostfqdn;
  $cacheConfig->{clientConfig}->{cacheServer} = $host; # For letsencrypt cert, use DNS name.
  $cacheConfig->{serverConfig}->{dbConfig}->{dbServer} = "127.0.0.1";

  # Put in tmp file.
  my $tmpFile = "/tmp/test-cache-$$-cacheConfig.json";
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($cacheConfig));

  return $tmpFile;
}


sub startMongoDB {
  &chkcmd("sudo service mongod start");
}

# input: ()
# output: ($pid) pid of the $cacheServer
sub startServer {
  my $pid = fork();
  if ($pid eq 0) {
    ### Child

    # Discard stdout/stderr
    open STDOUT, ">", '/dev/null' or die $!;
    open STDERR, ">", '/dev/null' or die $!;

    # cache config
    $ENV{VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE} = $CACHE_CONFIG_FILE;

    # Here we go!
    exec($cacheServer);
  }
  return $pid;
}

sub resetDB {
  &chkcmd("VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE=$CACHE_CONFIG_FILE $resetDB 2>/dev/null");
}

sub validateUploads {
  &chkcmd("VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE=$CACHE_CONFIG_FILE $validateUploads 2>/dev/null");
}

sub queryCache {
  my ($queryFile) = @_;
  return decode_json(&chkcmd("VULN_REGEX_DETECTOR_CACHE_CONFIG_FILE=$CACHE_CONFIG_FILE $cacheClient $queryFile 2>/dev/null"));
}


######################
# Low-level helpers
######################

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

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or die "Error, could not read $args{file}: $!\n";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}
