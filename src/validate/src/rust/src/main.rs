// Author: Jamie Davis <davisjam@vt.edu>
// Description: Attempt REDOS against Rust
//   NB This should always fail because Rust claims linear-time matching.
//      Seeing the performance will indicate the cost of the linear-time solution in production.
//   NB Does not follow the API of all of the other query-LANGUAGE solutions

// command-line args
use std::env;

// File I/O
use std::fs::File;
use std::io::prelude::*;

// JSON
extern crate serde;
extern crate serde_json;
use serde_json::{Value, Error};

#[macro_use]
extern crate serde_derive;

// Regex
extern crate regex;
use regex::Regex;

/*
// JSON object types

struct EvilInput {
}

#[derive(Serialize, Deserialize)]
struct Pattern {
    pattern: String,
    nPumps: u8,
		evilInput: EvilInput,
}
*/

fn main() {
	// Get file from command-line args
	let args: Vec<String> = env::args().collect();
	let filename = &args[1];
	println!("File: {}", filename);

	// Read file contents into string
	let mut f = File::open(filename).expect("file not found");

	let mut contents = String::new();
	f.read_to_string(&mut contents)
			.expect("something went wrong reading the file");

	println!("File contents:\n{}", contents);

	// Parse as JSON
	let mut patternObj: Value = serde_json::from_str(&contents).unwrap();

  let pattern = patternObj["pattern"].as_str().unwrap();
  println!("The pattern is: {}", pattern);

	let input = patternObj["input"].as_str().unwrap();

	// Match
	println!("matching: pattern {} input {}", pattern, input);

  let re = Regex::new(pattern).unwrap();
  let matched = re.is_match(&input);
	println!("matched: {}", matched);
}
