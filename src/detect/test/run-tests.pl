#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Tests for detect phase.
#
# Requirements:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use File::Basename;
use JSON::PP;

# Check dependencies.

if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $detectVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/detect-vuln.pl";
if (not -x $detectVuln) {
  die "Error, could not find validate-vuln $detectVuln\n";
}

# Get tests.

my @files = `find . -mindepth 2 -name '*json'`;
chomp @files;
@files = sort @files;

my @safeTests = grep { m/\/safe/ } @files;
my @unsafeTests = grep { m/\/unsafe/ } @files;
my @invalidTests = grep { m/\/invalid/ } @files;

# Test: query and make sure we get reasonable-looking results.
#
# We're not testing the detectors for correctness here,
# just that the output seems to fit the API.

print "Trying tests with safe regexes\n\n";
for my $f (@safeTests) {
  print "Test: $f\n";
  my $res = decode_json(`$detectVuln $f 2>/dev/null`);

  print encode_json($res) . "\n";

  my $nDetectors = 0;
  my $nSaidUnsafe = 0;
  for my $do (@{$res->{detectorOpinions}}) {
    $nDetectors++;
    if ($do->{hasOpinion} and $do->{opinion}->{canAnalyze} and not $do->{opinion}->{isSafe}) {
      ++$nSaidUnsafe;
    }
  }

  if ($nSaidUnsafe eq $nDetectors) {
    die "Error, safe $f was found unsafe by all detectors:\n" . encode_json($res) . "\n";
  } 
}

print "\nTrying tests with unsafe regexes\n\n";
for my $f (@unsafeTests) {
  print "Test: $f\n";
  my $res = decode_json(`$detectVuln $f 2>/dev/null`);

  my $nDetectors = 0;
  my $nSaidSafe = 0;
  for my $do (@{$res->{detectorOpinions}}) {
    $nDetectors++;
    if ($do->{hasOpinion} and $do->{opinion}->{canAnalyze} and $do->{opinion}->{isSafe}) {
      $nSaidSafe++;
    }
  }

  if ($nSaidSafe eq $nDetectors) {
    die "Error, unsafe $f was found safe by all detectors:\n" . encode_json($res) . "\n";
  } 
}

print "\nTrying tests with invalid regexes\n\n";
for my $f (@invalidTests) {
  print "Test: $f\n";
  my $res = decode_json(`$detectVuln $f 2>/dev/null`);

  for my $do (@{$res->{detectorOpinions}}) {
    if ($do->{hasOpinion} and $do->{opinion}->{canAnalyze}) {
      die "Error, detector had opinion about invalid $f:\n" . encode_json($res) . "\n";
    }
  }

}

#########

sub contains {
  my ($L, $x) = @_;
  for my $e (@$L) {
    if ($e eq $x) {
      return 1;
    }
  }

  return 0;
}
