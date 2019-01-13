package VulnRegexDetector;

/* Taken from https://docs.oracle.com/javase/tutorial/essential/regex/test_harness.html */
import java.io.Console;
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
      JsonObject obj = jelement.getAsJsonObject();

      String pattern = obj.get("pattern").getAsString();
      String input = obj.get("input").getAsString();
      log(String.format("matching: pattern /%s/, input: len %d value <%s>",
        pattern, input.length(), input));

      // Attempt match.
      Pattern p = Pattern.compile(pattern);
      Matcher m = p.matcher(input);

      boolean found = m.find();

      obj.addProperty("inputLength", input.length());
      obj.addProperty("matched", found ? 1 : 0);

      System.out.println(new Gson().toJson(obj));
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