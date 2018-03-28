#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test a regex to see if it is vulnerable
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $detectVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/detect-vuln.pl";
my $validateVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl";

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

my $tmpFile = "/tmp/check-regex-$$.json";
my $progressFile = "/tmp/check-regex-$$-progress.log";
unlink($tmpFile, $progressFile);

my $result = { "pattern" => $query->{pattern} };

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

$result->{detectReport} = $detectReport;

### Validate any reported vulnerabilities.

# Prep a query to $validateVuln.
my $validateVulnQuery = { "pattern"   => $query->{pattern},
                          "language"  => $query->{validateVuln_language},
                          "nPumps"    => $query->{validateVuln_nPumps},
                          "timeLimit" => $query->{validateVuln_timeLimit},
                        };

# See what each detector thought.
# Bail if any finds a vulnerability.
$result->{isVulnerable} = 0;
for my $do (@{$detectReport->{detectorOpinions}}) {
  # Are we done?
  last if ($result->{isVulnerable});

  # Check this detector's opinion.
  &log("Checking $do->{name} for timeout-triggering evil input");

  # Maybe vulnerable?
  if ($do->{hasOpinion} and $do->{opinion}->{canAnalyze} and not $do->{opinion}->{isSafe}) {
    # If unparseable, evilInput is an empty array or has elt 0 'COULD-NOT-PARSE'
    for my $evilInput (@{$do->{opinion}->{evilInput}}) {
      next if $evilInput eq "COULD-NOT-PARSE";

      # Does this evilInput trigger catastrophic backtracking?
      $validateVulnQuery->{evilInput} = $evilInput;
      &log("Validating evilInput: " . encode_json($evilInput));
      &writeToFile("file"=>$tmpFile, "contents"=>encode_json($validateVulnQuery));
      my $report = decode_json(&chkcmd("$validateVuln $tmpFile 2>>$progressFile"));
      if ($report->{timedOut}) {
        &log("evilInput worked: triggered a timeout");
        $result->{isVulnerable} = 1;
        $result->{validateReport} = $report;
        last;
      }
    }
  }
}

# Cleanup.
unlink($tmpFile, $progressFile);

# Report results.
print STDOUT encode_json($result) . "\n";

exit 0;

######################

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
