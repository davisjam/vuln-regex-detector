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

my $patternFile = $ARGV[0];
if (not -f $patternFile) {
  die "Error, no such patternFile $patternFile\n";
}

my $pattern = decode_json(`cat $patternFile`);

my $tmpFile = "/tmp/check-regex-$$.json";

my $result = {};

### Query detectors.

# Prep a query to $detectVuln.
my $detectVulnQuery = {};

if (defined $pattern->{regex}) {
  $detectVulnQuery->{pattern} = $pattern->{regex};
}
elsif (defined $pattern->{pattern}) {
  $detectVulnQuery->{pattern} = $pattern->{pattern};
}
else {
  die "Error, neither 'regex' nor 'pattern' specified in input\n";
}

$result->{pattern} = $detectVulnQuery->{pattern};

if (defined $pattern->{detectVuln_detectors}) {
  $detectVulnQuery->{detectors} = $pattern->{detectVuln_detectors};
}
if (defined $pattern->{detectVuln_timeLimit}) {
  $detectVulnQuery->{timeLimit} = $pattern->{detectVuln_timeLimit};
}
if (defined $pattern->{detectVuln_memoryLimit}) {
  $detectVulnQuery->{memoryLimit} = $pattern->{detectVuln_memoryLimit};
}

# Query $detectVuln.
&log("Querying detectors");
&writeToFile("file"=>$tmpFile, "contents"=>encode_json($detectVulnQuery));
my $detectReport = decode_json(&chkcmd("$detectVuln $tmpFile 2>/dev/null"));

$result->{detectReport} = $detectReport;

### Validate any reported vulnerabilities.

# Prep a query to $validateVuln.
my $validateVulnQuery = {};

if (defined $pattern->{regex}) {
  $validateVulnQuery->{pattern} = $pattern->{regex};
}
elsif (defined $pattern->{pattern}) {
  $validateVulnQuery->{pattern} = $pattern->{pattern};
}
else {
  die "Error, neither 'regex' nor 'pattern' specified in input\n";
}

if (defined $pattern->{validateVuln_language}) {
  $validateVulnQuery->{language} = $pattern->{validateVuln_language};
}
else {
  die "Error, input did not specify validateVuln_language\n";
}

# $validateVuln requires nPumps and timeLimit.
# Choose sensible defaults.
if (defined $pattern->{validateVuln_nPumps}) {
  $validateVulnQuery->{nPumps} = $pattern->{validateVuln_nPumps};
}
else {
  $validateVulnQuery->{nPumps} = 250000;
}

if (defined $pattern->{validateVuln_timeLimit}) {
  $validateVulnQuery->{timeLimit} = $pattern->{validateVuln_timeLimit};
}
else {
  $validateVulnQuery->{timeLimit} = 5;
}

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
      my $report = decode_json(&chkcmd("$validateVuln $tmpFile 2>/dev/null"));
      if ($report->{timedOut}) {
        &log("evilInput worked: triggered a timeout");
        $result->{isVulnerable} = 1;
        $result->{validateReport} = $report;
        last;
      }
    }
  }
}

unlink $tmpFile;
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
