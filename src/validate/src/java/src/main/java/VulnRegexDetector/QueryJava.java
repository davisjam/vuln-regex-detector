package VulnRegexDetector;

/* Taken from https://docs.oracle.com/javase/tutorial/essential/regex/test_harness.html */
import java.io.Console;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/* I/O. */
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.io.IOException;

public class QueryJava {
  public static void main(String[] args)
    throws IOException
  {
    if (args.length == 1) {
   		// Trust input is valid.
		  String cont = readFile(args[0], Charset.defaultCharset());
		  JsonElement jelement = new JsonParser().parse(cont);
      JsonObject query = jelement.getAsJsonObject();

      String pattern = query.get("pattern").getAsString();
      String input = query.get("input").getAsString();
      log(String.format("matching: pattern /%s/, input: len %d value <%s>",
        pattern, input.length(), input));

			int inputLength = input.length();

      // Try to create regex
      Pattern p = null;
      boolean validPattern = false;
      try {
        p = Pattern.compile(pattern);
        validPattern = true;
      } catch (Exception e) {
        log("Exception compiling pattern: " + e);
        validPattern = false;
      }

			boolean matched = false;
			MyMatchContents matchContents = new MyMatchContents("", new ArrayList<String>());
      if (validPattern) {
        // Attempt match
        Matcher matcher = p.matcher(input);
        matched = matcher.find(); // Partial match

				if (matched) {
					String matchedString = matcher.group();
					List<String> captureGroups = new ArrayList<String>();
					for (int i = 1; i <= matcher.groupCount(); i++) {
						String grp = matcher.group(i);
						// Strictly speaking, there is a distinction between "did not match" and "matched the empty string".
						if (grp == null) {
							captureGroups.add("");
						} else {
							captureGroups.add(grp);
						}
					}
					matchContents = new MyMatchContents(matchedString, captureGroups);
				}
      }

			MyMatchResult matchResult = new MyMatchResult(validPattern, inputLength, matched, matchContents);

      // Emit
      System.out.println(new Gson().toJson(matchResult));
    } else {
      System.out.println("Usage: INVOCATION query.json");
      System.exit(-1);
    }
  }

 	/* https://stackoverflow.com/a/326440 */
	static String readFile(String path, Charset encoding)
		throws IOException 
	{
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}

	static void log(String msg) {
		System.err.println(msg);
	}
}

class MyMatchResult {
	private boolean validPattern;
	private int inputLength;
	private boolean matched;
	private MyMatchContents matchContents;

	public MyMatchResult(boolean validPattern, int inputLength, boolean matched, MyMatchContents matchContents) {
		this.validPattern = validPattern;
		this.inputLength = inputLength;
		this.matched = matched;
		this.matchContents = matchContents;
	}
}

class MyMatchContents {
	private String matchedString;
	private List<String> captureGroups;

	public MyMatchContents(String matchedString, List<String> captureGroups) {
		this.matchedString = matchedString;
		this.captureGroups = captureGroups;
	}
}
