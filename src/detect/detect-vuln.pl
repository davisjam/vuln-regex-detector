#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Query each of the REDOS detectors to see if a regex pattern is vulnerable.
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP; # I/O
use Carp;
use Time::HiRes qw( gettimeofday tv_interval );

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

# Check args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 pattern-query.json\n";
}

my $patternFile = $ARGV[0];
if (not -f $patternFile) {
  die "Error, no such patternFile $patternFile\n";
}

# Read.
my $cont = &readFile("file"=>$patternFile);
my $query = decode_json($cont);

# Check validity.
my @keys = ("pattern");
for my $k (@keys) {
  if (not defined $query->{$k}) {
    die "Error, query missing key $k\n";
  }
}

# Which detectors should we use?
my @DETECTORS = &getDetectors();
if (defined $query->{detectors}) {
  @DETECTORS = grep { &listContains($query->{detectors}, $_->{name}) } @DETECTORS;
  if (not @DETECTORS) {
    die "Error, no detectors matched names <@{$query->{detectors}}>\n";
  }
}
my @detectorNames = map { $_->{name} } @DETECTORS;
&log("Using detectors <@detectorNames>");

# Define limits on each detector.
my $ONE_MB_IN_BYTES = 1*1024*1024;
my $memoryLimitInBytes = (defined $query->{memoryLimit}) ? int($query->{memoryLimit}) * $ONE_MB_IN_BYTES : -1;

my $limitTime = (defined $query->{timeLimit}) ? "timeout $query->{timeLimit}s" : "";
my $ulimitMemory = (defined $query->{memoryLimit}) ? "ulimit -m $memoryLimitInBytes; ulimit -v $memoryLimitInBytes;" : "";

# Run each detector. Can re-use the input file.
my @detectorOpinions;
&log("Applying detectors to pattern /$query->{pattern}/");
for my $d (@DETECTORS) {
  &log("Querying detector $d->{name}");
  my $t0 = [gettimeofday];
  my $stderrFile = "/tmp/detect-vuln-$$-stderr";
  my ($rc, $out) = &cmd("$ulimitMemory $limitTime $d->{driver} $patternFile 2>$stderrFile");
  my $elapsed = tv_interval($t0);
  chomp $out;

  # Clean up in case there was a timeout.
  my $stderr = &readFile("file"=>$stderrFile);
  my @filesToClean = ($stderr =~ m/CLEANUP: (\S+)/g);
  &log("Cleaning up @filesToClean");
  unlink @filesToClean;
  unlink $stderrFile;

  my $opinion = { "name"         => $d->{name},
                  "secToDecide" => sprintf("%.4f", $elapsed),
                };

  if ($rc eq 124) {
    &log("Detector $d->{name} timed out");
    $opinion->{hasOpinion} = 0;
    $opinion->{opinion} = "TIMEOUT"; 
  }
  elsif ($rc) {
    &log("Detector $d->{name} said rc $rc");
    $opinion->{hasOpinion} = 0;
    $opinion->{opinion} = "INTERNAL-ERROR"; 
  }
  else {
    &log("Detector $d->{name} said: $out");
    my $result = decode_json($out);
    # Extract the details needed to make the summary.
    # Otherwise we repeat ourselves too much.
    $opinion->{hasOpinion} = 1;
    $opinion->{opinion} = $result->{opinion};
  }

  push @detectorOpinions, $opinion;
}

$query->{detectorOpinions} = \@detectorOpinions;

print STDOUT encode_json($query) . "\n";

#####################

# input: ($cmd)
# output: ($rc, $out)
sub cmd {
  my ($cmd) = @_;
  &log("CMD: $cmd");
  my $out = `$cmd`;
  return ($? >> 8, $out);
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}


# input: ()
# output: (@detectors) fields: name driver
#   name: shorthand
#   driver: absolute path to the detector driver
sub getDetectors {
  my $driverPrefix = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/src/drivers";

  # field: name
  my @detectors = ( {"name" => "rathnayake-rxxr2"},
                    {"name" => "weideman-RegexStaticAnalysis"},
                    {"name" => "wuestholz-RegexCheck"},
                  );
  # field: driver
  for my $d (@detectors) {
    $d->{driver} = "$driverPrefix/query-$d->{name}.pl";
  }

  # Confirm detector driver is available
  for my $d (@detectors) {
    if (not -x $d->{driver}) {
      die "Error, cannot run driver for $d->{name}: $d->{driver}\n";
    }
  }
 
  return @detectors;
}

# input: (\@list, $e)
# output: true if $e is in @list, else false
sub listContains {
  my ($list, $e) = @_;
  for my $elt (@$list) {
    if ($elt eq $e) {
      return 1;
    }
  }

  return 0;
}

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or confess "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}
