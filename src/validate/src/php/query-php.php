#!/usr/bin/env php
<?php
// Author: Jamie Davis <davisjam@vt.edu>
// Description: Try REDOS attack on PHP

function my_log($msg) {
  fwrite(STDERR, $msg . "\n");
}

function main() {
  // Assume args are correct, this is a horrible language.
  global $argc, $argv;
  $FH = fopen($argv[1], "r") or die("Unable to open file!");
  $cont = fread($FH, filesize($argv[1]));
  fclose($FH);

  $obj = json_decode($cont);
  my_log('obj');

  // Query regexp.
  my_log('matching: Pattern /' . $obj->{'pattern'} . '/, input: len ' . strlen($obj->{'input'}));

  $matched = @preg_match('/' . $obj->{'pattern'} . '/', $obj->{'input'}, $matches); // Partial match
	//var_dump($matches);
	// NB: (a?)abc|(d)  on "abc" --> (a?) is empty, but (d) is just dropped

  // capture exception, if any.
  // will return OK even if there's compilation problems.
  // PHP 7.4-dev emits a warning unless we @ to ignore it.
  $except = @array_flip(get_defined_constants(true)['pcre'])[preg_last_error()];

  // check for compilation
  $compilation_failed_message = 'preg_match(): Compilation failed:';
  $last_error = error_get_last();
  if(strpos($last_error['message'], $compilation_failed_message) !== false) {
    my_log("caught the invalid input");
    $except = "INVALID_INPUT";
		$obj->{'validPattern'} = 0;
  } else {
		$obj->{'validPattern'} = 1;
	}

  // Compose output.
  $obj->{'matched'} = $matched;
	if ($matched) {
		$obj->{'matchContents'} = new stdClass();
		$obj->{'matchContents'}->{'matchedString'} = $matches[0];
		$obj->{'matchContents'}->{'captureGroups'} = array_slice($matches, 1);
	}
  $obj->{'inputLength'} = strlen($obj->{'input'});
  $obj->{'exceptionString'} = $except;
  fwrite(STDOUT, json_encode($obj) . "\n");

  // Whew.
  exit(0);
}

main();
?>
