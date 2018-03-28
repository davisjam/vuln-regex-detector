#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Clone and scan a source code repo to check for vulnerable regexes.
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

my $checkTree = "$ENV{VULN_REGEX_DETECTOR_ROOT}/bin/check-tree.pl";

for my $script ($checkTree) {
  if (not -x $script) {
    die "Error, could not find script $script\n";
  }
}

# Args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 repo.json\n";
}

my $queryFile = $ARGV[0];
if (not -f $queryFile) {
  die "Error, no such queryFile $queryFile\n";
}

my $query = decode_json(`cat $queryFile`);
for my $key ("url") {
  if (not defined $query->{$key}) {
    die "Error, must provide key $key\n";
  }
}

my %defaults = ("cloneRepo_timeout" => 60*60*24, # 1 day in seconds, basically forever
               );
for my $key (keys %defaults) {
  if (not defined $query->{$key}) {
    &log("Using default for $key: $defaults{$key}");
    $query->{$key} = $defaults{$key};
  }
}

my $tmpFile = "/tmp/check-repo-$$.json";
my $progressFile = "/tmp/check-repo-$$-progress.log";
unlink($tmpFile, $progressFile);

my $repoRoot = "/tmp/check-repo-$$-repoRoot";
&cmd("rm -rf $repoRoot");

my $result = {};

### Clone

my $repoType = &cloneURL($query->{url}, $repoRoot, int($query->{cloneRepo_timeout}));

if (defined $repoType) {
  $result->{couldClone} = 1;
  $result->{repoType} = $repoType;

  ### $checkTree

  # Compose query
  my $checkTreeQuery = decode_json(encode_json($query));
  $checkTreeQuery->{root} = $repoRoot;
  if ($repoType eq "git") {
    $checkTreeQuery->{excludeDirs} = [(".git")];
  }
  elsif ($repoType eq "svn") {
    $checkTreeQuery->{excludeDirs} = [(".svn")];
  }

  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($checkTreeQuery));

  # Query
  my $checkTreeResult = decode_json(&chkcmd("$checkTree $tmpFile 2>>$progressFile"));
  $result->{checkTreeResult} = $checkTreeResult;
}
else {
  $result->{couldClone} = 0;
}

### Summarize
if ($result->{couldClone}) {
  print encode_json($result) . "\n";

  my @vulnFileReports = grep { $_->{anyVulnRegexes} } @{$result->{checkTreeResult}->{checkFileReports}};

  my @vulnFiles = map { $_->{file} } @vulnFileReports;

  my @vulnRegexes;
  for my $report (@vulnFileReports) {
    push @vulnRegexes, @{$report->{vulnRegexes}};
  }

  my %uniqueRegexes;
  map { $uniqueRegexes{$_} = 1; } @vulnRegexes;

  my $nVulnFiles = scalar(@vulnFiles);
  my $nVulnRegexAppearances = scalar(@vulnRegexes);
  my $nUniqueVulnRegexes = scalar(keys %uniqueRegexes);

  &log("Repo $query->{url} contained $nVulnFiles files with vulnerable regexes. $nUniqueVulnRegexes vuln regexes appeared a total of $nVulnRegexAppearances times");
  $result->{nVulnFiles} = $nVulnFiles;
  $result->{nVulnRegexAppearances} = $nVulnRegexAppearances;
  $result->{nUniqueVulnRegexes} = $nUniqueVulnRegexes;
}

# Cleanup.
unlink($tmpFile, $progressFile);
&cmd("rm -rf $repoRoot");

# Report results.
print STDOUT encode_json($result) . "\n";

exit 0;

######################

# return $type if succeeds, else undef
sub cloneURL {
  my ($url, $dest, $timeout) = @_;

  my %type2cloner = ("git" => \&cloneAsGit,
                     "svn" => \&cloneAsSVN,
                    );

  my @typesToTry;
  if (defined $query->{checkRepo_type}) {
    if (defined $type2cloner{$query->{checkRepo_type}}) {
      @typesToTry = ($query->{checkRepo_type});
    }
    else {
      my @types = keys %type2cloner;
      die "Error, unsupported repo type $query->{checkRepo_type}. Choose from <@types>\n";
    }
  }
  else {
    @typesToTry = keys %type2cloner;
  }

  my $succeeded = 0;

  for my $type (@typesToTry) {
    &log("Trying to clone as $type");
    $succeeded = $type2cloner{$type}->($url, $dest, $timeout);
    if ($succeeded) {
      &log("Bingo, git repo: $url");
      return $type;
    }
  }

  return undef;
}

# return 1 if clone succeeds, else 0
sub cloneAsGit {
  my ($url, $dest, $timeout) = @_;

  my ($rc, $out) = &cmd("timeout ${timeout}s git clone $url $dest 2>>$progressFile");

  if ($rc eq 0) {
    return 1;
  }
  return 0;
}

# return 1 if clone succeeds, else 0
sub cloneAsSVN {
  my ($url, $dest, $timeout) = @_;

  my ($rc, $out) = &cmd("timeout ${timeout}s svn checkout $url $dest 2>>$progressFile");

  if ($rc eq 0) {
    return 1;
  }
  return 0;
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
