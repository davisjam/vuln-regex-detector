#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Tests for validation.
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

my $validateVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl";
if (not -x $validateVuln) {
  die "Error, could not find validate-vuln $validateVuln\n";
}

# Get tests.

my @files = `find . -mindepth 2 -name '*json' | grep -v generic`;
chomp @files;
@files = sort @files;

my @safeTests = grep { m/\/safe/ } @files;
my @unsafeTests = grep { m/\/unsafe/ } @files;

# These languages time out on the unsafe cases.
my @unsafeLangs = ("javascript", "ruby", "python");

print "Trying tests with safe regexes\n\n";
for my $f (@safeTests) {
  print "Test: $f\n";
  my $res = decode_json(`$validateVuln $f 2>/dev/null`);
  if ($res->{timedOut}) {
    die "Error, $f timed out\n";
  }
}

print "\nTrying tests with unsafe regexes\n\n";
for my $f (@unsafeTests) {
  print "Test: $f\n";
  my $res = decode_json(`$validateVuln $f 2>/dev/null`);

  my $lang = dirname($f);
  if (&contains(\@unsafeLangs, $lang)) {
    if (not $res->{timedOut}) {
      die "Error, $f did not time out although $lang is unsafe\n";
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
