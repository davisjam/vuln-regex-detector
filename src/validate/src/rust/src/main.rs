// Author: Jamie Davis <davisjam@vt.edu>
// Description: Test regex in Python
//   NB This should always take linear-time, unless there are subtleties in the Rust docs.

// command-line args
use std::env;

// File I/O
use std::fs::File;
use std::io::prelude::*;

// JSON
extern crate serde;
#[macro_use]
extern crate serde_json;
use serde_json::{Value, Error};

#[macro_use]
extern crate serde_derive;

// Regex
extern crate regex;
use regex::Regex;

fn main() {
	// Get file from command-line args
	let args: Vec<String> = env::args().collect();
	let filename = &args[1];
	eprintln!("File: {}", filename);

	// Read file contents into string
	let mut f = File::open(filename).expect("file not found");

	let mut contents = String::new();
	f.read_to_string(&mut contents)
			.expect("something went wrong reading the file");

	eprintln!("File contents:\n{}", contents);

	// Parse as JSON
	let mut patternObj: Value = serde_json::from_str(&contents).unwrap();

  let pattern = patternObj["pattern"].as_str().unwrap();
  eprintln!("The pattern is: {}", pattern);

	let input = patternObj["input"].as_str().unwrap();

	// Try a match
	eprintln!("matching: pattern {} input {}", pattern, input);

	// Result object
	let mut res: serde_json::Value = json!({
		"pattern": patternObj["pattern"].as_str().unwrap(),
		"input": patternObj["input"].as_str().unwrap(),
		"inputLength": patternObj["input"].as_str().unwrap().len(),
	});

  match Regex::new(pattern) {
		Ok(re) => {
			// Could build. Add 'matched' field.
			res["validPattern"] = serde_json::Value::Bool(true);

      // Partial-match semantics
			match re.captures(&input) {
				Some(caps) => {
					res["matched"] = serde_json::Value::Bool(true);
					let mut matchedString = caps.get(0).unwrap().as_str();
					let mut captureGroups = Vec::new();
					for i in 1..caps.len() {
						match caps.get(i) {
							Some(m) => {
								captureGroups.push(m.as_str());
							},
							None => {
								captureGroups.push(""); // Interpret unused capture group as ""
							}
						}
					}
					let mut matchContents = json!({});
					matchContents["matchedString"] = json!(matchedString);
					matchContents["captureGroups"] = json!(captureGroups);
					res["matchContents"] = matchContents;
				},
				None => {
					res["matched"] = serde_json::Value::Bool(false);
				}
			}
		}
		Err(error) => {
			// Could not build.
			res["validPattern"] = serde_json::Value::Bool(false);
		}
	};
	println!("{}", res.to_string());
}
