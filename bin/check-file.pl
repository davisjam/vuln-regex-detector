#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test all regexes in a file to see if any are vulnerable
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

my $extractRegexes = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/extract/extract-regexes.pl";
my $checkRegex = "$ENV{VULN_REGEX_DETECTOR_ROOT}/bin/check-regex.pl";

for my $script ($extractRegexes, $checkRegex) {
  if (not -x $script) {
    die "Error, could not find script $script\n";
  }
}

# Args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 file.json\n";
}

my $queryFile = $ARGV[0];
if (not -f $queryFile) {
  die "Error, no such queryFile $queryFile\n";
}

my $query = decode_json(`cat $queryFile`);
for my $key ("file") {
  if (not defined $query->{$key}) {
    die "Error, must provide key $key\n";
  }
}

my $tmpFile = "/tmp/check-file-$$.json";
my $progressFile = "/tmp/check-file-$$-progress.log";
unlink($tmpFile, $progressFile);

my $result = { "file"=>$query->{file} };

### Extract regexes.

# Prep a query to $extractRegexes.
my $extractRegexesQuery = {};

if (defined $query->{file}) {
  $extractRegexesQuery->{file} = $query->{file};
}
else {
  die "Error, no 'file' specified in input\n";
}

if (defined $query->{extractRegexes_language}) {
  $extractRegexesQuery->{language} = $query->{extractRegexes_language};
}

# Query $extractRegexes.
my $extractReport;

&log("Extracting regexes");
&writeToFile("file"=>$tmpFile, "contents"=>encode_json($extractRegexesQuery));
{
  my ($rc, $out) = &cmd("$extractRegexes $tmpFile 2>>$progressFile");
  if ($rc eq 0) {
    $result->{couldExtractRegexes} = 1;
    $extractReport = decode_json($out);
    $result->{extractReport} = $extractReport;
  }
  else {
    $result->{couldExtractRegexes} = 0;
  }
}

### Pass each unique regex to $checkRegex.

if ($result->{couldExtractRegexes}) {
  my @patterns = map { $_->{pattern} } @{$extractReport->{regexps}};
  my %uniquePatterns;
  map { $uniquePatterns{$_} = 1 } @patterns;
  my @uniquePatterns = keys %uniquePatterns;

  &log("Extracted " . scalar(@uniquePatterns) . " regexes. Testing each for vulnerability");

  my @checkRegexReports;
  my @vulnRegexes;
  my $i = 1;
  my $n = scalar(@uniquePatterns);
  for my $pattern (@uniquePatterns) {
    next if ($pattern eq "DYNAMIC-PATTERN");

    if ($i % 10 eq 0) {
      &log("Testing regex $i/$n");
    }
    $i++;

    # Copy so we have the args to $checkRegex.
    my $checkRegexQuery = decode_json(encode_json($query));

    # Fill in extra args.
    $checkRegexQuery->{pattern} = $pattern;
    $checkRegexQuery->{validateVuln_language} = $extractReport->{language};

    &writeToFile("file"=>$tmpFile, "contents"=>encode_json($checkRegexQuery));
    my $checkRegexReport = decode_json(&chkcmd("$checkRegex $tmpFile 2>>$progressFile"));
    push @checkRegexReports, $checkRegexReport;

    if ($checkRegexReport->{isVulnerable}) {
      push @vulnRegexes, $pattern;
    }
  }

  # Update result.
  $result->{checkRegexReports} = \@checkRegexReports;
  $result->{vulnRegexes} = \@vulnRegexes;

  if (scalar(@{$result->{vulnRegexes}})) {
    $result->{anyVulnRegexes} = 1;
  }
  else {
    $result->{anyVulnRegexes} = 0;
  }

  # Summary.
  &log("File $query->{file} contained " . scalar(@vulnRegexes) . " vulnerable regex(es)");
}

# Cleanup.
unlink($tmpFile, $progressFile);

# Emit.
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
