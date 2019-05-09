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

my $DEBUG = 0;
if ($ENV{REGEX_DEBUG}) {
  $DEBUG = 1;
}

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
    die "Error, no available detectors matched names <@{$query->{detectors}}>\n";
  }
}
my @detectorNames = map { $_->{name} } @DETECTORS;
&log("Using detectors <@detectorNames>");

my @PATTERN_VARIANTS = &getPatternVariants();
if (defined $query->{patternVariants}) {
  @PATTERN_VARIANTS = grep { &listContains($query->{patternVariants}, $_) } @PATTERN_VARIANTS;
}
&log("Using pattern variants <@PATTERN_VARIANTS>");

# Define limits on each detector.
my $ONE_MB_IN_KB = 1*1024; # ulimit -m and -v accept units of KB.
my $memoryLimitInBytes = (defined $query->{memoryLimit}) ? int($query->{memoryLimit}) * $ONE_MB_IN_KB : -1;

my $limitTime = (defined $query->{timeLimit}) ? "timeout $query->{timeLimit}s" : "";
my $ulimitMemory = (defined $query->{memoryLimit}) ? "ulimit -m $memoryLimitInBytes; ulimit -v $memoryLimitInBytes;" : "";

my @patternsToTry = &expandPatternSpaceForDetectors($query->{pattern}, \@PATTERN_VARIANTS);

# This will contain N_DETECTORS * scalar(@patternsToTry) opinions.
my @detectorOpinions;
# Try each pattern.
for my $pattern (@patternsToTry) {
  &log("Applying detectors to pattern /$pattern/");

  # Craft query file.
  my $newQuery = decode_json(encode_json($query));
  $newQuery->{pattern} = $pattern;
  my $tmpPatternFile = &makeQueryFile($newQuery);

  # Ask each detector.
  for my $d (@DETECTORS) {
    &log("Querying detector $d->{name}");
    my $t0 = [gettimeofday];
    my $stderrFile = "/tmp/detect-vuln-$$-stderr";
    my ($rc, $out) = &cmd("$ulimitMemory $limitTime $d->{driver} $tmpPatternFile 2>$stderrFile");
    my $elapsed = tv_interval($t0);
    chomp $out;

    # Clean up in case there was a timeout.
    my $stderr = &readFile("file"=>$stderrFile);
    my @filesToClean = ($stderr =~ m/CLEANUP: (\S+)/g);
    &log("Cleaning up @filesToClean");
    unlink @filesToClean unless $DEBUG;
    unlink $stderrFile unless $DEBUG;

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

      # Note the pattern we queried about, so we can distinguish from the original.
      $opinion->{patternVariant} = $pattern;
    }

    push @detectorOpinions, $opinion;
  }

  unlink $tmpPatternFile unless $DEBUG;
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
                    {"name" => "shen-ReScue"},
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

sub makeQueryFile {
  my ($query) = @_;
  my $tmpFile = "/tmp/detect-vuln-$$.json";
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($query));
  return $tmpFile;
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

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

sub getPatternVariants {
  # Defaults are aggressive, we assume the outcome will be dynamically validated in the languages of interest
  # "leftanchor" is the most conservative, "bigCurlies" is still pretty conservative
  return ("leftanchor", "allCurlies");
}

sub expandPatternSpaceForDetectors {
  my ($pattern, $patternVariantList) = @_;

  my %dedupVariants;
  for my $variant (@$patternVariantList) {
    $dedupVariants{$variant} = 1;
  }
  my @variants = keys %dedupVariants;

  my @patternsToTry = ($pattern);

  if (&listContains(\@variants, "leftanchor")) {
    &log("Variant: leftanchor");
    # If pattern is unanchored, a backtracking regex engine will run the loop:
    #   for (1 .. n):
    #     _match(regex, substr)
    # This means that if each match is linear-time, the worst-case behavior is quadratic.
    # For example, /a+$/ is quadratic in Node.js.
    # The detectors don't seem to acknowledge this loop.
    # We can simulate it by prefixing un-anchored regexes with '^(.*?)'.
    # This is also how a linear-time engine scans all starting indices in parallel; see Cox's writings.
    if (substr($query->{pattern}, 0, 1) ne "^") {
      my $anchoredPattern = "^(.*?)$query->{pattern}";
      push @patternsToTry, $anchoredPattern;
    }
  }

  if (&listContains(\@variants, "allCurlies") or &listContains(\@variants, "bigCurlies")) {
    # If pattern contains curlies "{\d*,\d*}", the detectors may time out due to graph expansion.
    # We can try a more general pattern with "*" and "+" instead.
    # The detectors might give false positives but that's OK, that's what the validate stage is for.
    # I'm not being careful about escaped curly braces, so let's hope there are no meta-regexes here.
    my $curlyThreshold;
    if (&listContains(\@variants, "allCurlies")) {
      &log("Variant: allCurlies");
      $curlyThreshold = 0;
    }
    elsif (&listContains(\@variants, "bigCurlies")) {
      &log("Variant: bigCurlies");
      $curlyThreshold = 100; # Probably overly generous, but false positives are Bad.
    }

    my $decurlied = $query->{pattern};
    $decurlied =~ s/\{(\d+),(\d+)\}/$2 > $curlyThreshold ? ($1 > 0 ? "+" : "*") : "{$1,$2}"/ge;
    $decurlied =~ s/\{,(\d+)\}/$1 > $curlyThreshold ? "*" : "{,$1}"/ge;
    $decurlied =~ s/\{(\d+),\}/$1 > 0 ? "+" : "*"/ge;

    my $genericCurlies = $query->{pattern};
    # {0, and {, both mean "0 or more"
    $genericCurlies =~ s/{0,\d*}/\*/g;
    $genericCurlies =~ s/{,\d*}/\*/g;
    # {[1-9] means "1 or more"
    $genericCurlies =~ s/{[1-9]\d*,\d*}/\+/g;
    if ($genericCurlies ne $pattern) {
      push @patternsToTry, $genericCurlies;
    }
  }

  return @patternsToTry;
}
