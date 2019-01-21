#!/usr/bin/env php
<?php
// Author: Jamie Davis <davisjam@vt.edu>
// Description: Evaluate a regex in PHP

function my_log($msg) {
  fwrite(STDERR, $msg . "\n");
}

// Return a string that can be used
// Returns NULL if nothing could be found
function patternAsPHPRegex($pat) {
	//http://php.net/manual/en/regexp.reference.delimiters.php
	$pairedDelimiters = [
		['/', '/'],
		['#', '#'],
		['`', '`'],
		['(', ')'],
		['{', '}'],
		['[', ']'],
		['<', '>'],
	];
	foreach($pairedDelimiters as $delim) {
		$first = $delim[0];
		$last = $delim[1];
		if (strpos($pat, $first) === FALSE && strpos($pat, $last) === FALSE) {
			return $first . $pat . $last;
		}
	}

	return NULL;
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
  $phpPattern = patternAsPHPRegex($obj->{'pattern'});
	if (!is_null($phpPattern)) {
		my_log('matching: pattern ' . $obj->{'pattern'} . ' --> phpPattern ' . $phpPattern);
		my_log('matching: Pattern ' . $phpPattern . ', input: len ' . strlen($obj->{'input'}));

		$matched = @preg_match($phpPattern, $obj->{'input'}, $matches); // Partial match
		//var_dump($matches);
		// NB: (a?)abc|(d)  on "abc" --> (a?) is empty, but trailing unused groups like (d) are just dropped

		// capture exception, if any.
		// will return OK even if there's compilation problems.
		// PHP 7.4-dev emits a warning unless we @ to ignore it.
		$except = @array_flip(get_defined_constants(true)['pcre'])[preg_last_error()];

		// check for compilation
		$compilation_failed_message = 'preg_match(): Compilation failed:';
		$last_error = error_get_last();
		if(strpos($last_error['message'], $compilation_failed_message) !== false) {
			my_log("caught the invalid input");
			$except = "INVALID_INPUT"; // Override compilation failed
			$obj->{'validPattern'} = 0;
		} else {
			$obj->{'validPattern'} = 1;
		}

		// Compose output.
		$obj->{'matched'} = $matched;
		if ($matched) {
			$obj->{'matchContents'} = new stdClass();
			$obj->{'matchContents'}->{'matchedString'} = $matches[0];

			// Unset any capture groups keyed by name instead of number for consistency with other testers
			foreach ($matches as $key => $value) {
				if (!is_int($key)) {
					unset($matches[$key]);
				}
			}

			$obj->{'matchContents'}->{'captureGroups'} = array_slice($matches, 1);
		}
	} else {
		$except = "INVALID_INPUT"; // Override compilation failed
		$obj->{'validPattern'} = 0;
		// Dummy values
		$obj->{'matched'} = 0;
		$obj->{'matchContents'} = new stdClass();
		$obj->{'matchContents'}->{'matchedString'} = "";
		$obj->{'matchContents'}->{'captureGroups'} = [];
	}

  $obj->{'inputLength'} = strlen($obj->{'input'});
  $obj->{'exceptionString'} = $except;
  fwrite(STDOUT, json_encode($obj) . "\n");

  // Whew.
  exit(0);
}

main();
?>
