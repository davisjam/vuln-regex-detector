// Author: Jamie Davis <davisjam@vt.edu>
// Description: Test a <regex, input> pair in Go

package main

///////////
// IMPORTS
///////////

import (
  "fmt"
  "os"
  "io/ioutil"
  "encoding/json"
  "regexp"
)

type Query struct {
  Pattern string  `json:"pattern"`
  Input string    `json:"input"`
}

type MatchContents struct {
  MatchedString string          `json:"matchedString"`
  CaptureGroups []string        `json:"captureGroups"`
}

type MatchResult struct {
  // Duplicate the Query
  Pattern string         `json:"pattern"`
  Input string           `json:"input"`
  // Additional fields
  InputLength int        `json:"inputLength"`
  ValidGoPattern bool    `json:"validPattern"`
  Matched bool           `json:"matched"`
  MC MatchContents       `json:"matchContents"`
}

///////////
// FUNCTIONS
///////////

func myLog(str string) {
  fmt.Fprintln(os.Stderr, str)
}

func check(e error) {
  if e != nil {
    panic(e)
  }
}

///////////
// main
///////////

func main() {
  if len(os.Args) <= 1 {
    fmt.Printf("Usage: query-go query.json\n")
    os.Exit(1)
  }

  // Load file contents
  queryFile := os.Args[1]
  myLog("queryFile " + queryFile)
  fd, err := os.Open(queryFile)
  check(err)
  byteValue, _ := ioutil.ReadAll(fd)

  // Load into a Query
  var query Query
  json.Unmarshal(byteValue, &query)
  myLog("Query: pattern /" + query.Pattern + "/")

  // Evaluate the Query as a MatchResult
  var matchResult MatchResult
  matchResult.Pattern = query.Pattern
  matchResult.Input = query.Input
  matchResult.InputLength = len(query.Input)

  re, err := regexp.Compile(query.Pattern)
  if err == nil {
    matchResult.ValidGoPattern = true
    matches := re.FindSubmatch([]byte(query.Input)) // Partial match

    if matches != nil {
			//fmt.Println(matches)
      matchResult.Matched = true
      matchResult.MC.MatchedString = string(matches[0])

      // Build up the capture groups, from []byte to string
      matchResult.MC.CaptureGroups = make([]string, 0)
			for _, byteString := range matches[1:] {
				matchResult.MC.CaptureGroups = append(matchResult.MC.CaptureGroups, string(byteString))
			}
    } else {
      matchResult.Matched = false
    }
  } else {
    matchResult.ValidGoPattern = false
    matchResult.Matched = false
  }

  // Emit
  str, _ := json.Marshal(matchResult)
  fmt.Println(string(str))
}
