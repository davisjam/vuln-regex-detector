var re;

// RegExpLiteral
var _ = ''.match(/string-match/);
re = /inline-regexp-no-flags/;
re = /inline-regexp-with-flags/i;
re = /inline-regexp-with-flags/ig;

// new RegExp
var dynamicPattern = "dynamic pattern";
var dynamicFlags = "gim";

re = new RegExp("explicit-regexp-no-flags");
re = new RegExp("explicit-regexp-with-flags", "g");
re = new RegExp(dynamicPattern, "gis");
re = new RegExp("explicit-regexp-dynamic-flags", dynamicFlags);
re = new RegExp(dynamicPattern, dynamicFlags);

// Nesting
var foo = foo(/inline-in-func-call/g);
var result = foo(bar(new RegExp("explicit-in-func-call")));

/* Complicating the analysis. */
var j = 0;
for (var i = 0; i < 100; i++) {
    if (1) {}
      else {}
        j = 1;
}

var b = new Promise( function(resolve, reject) { process.nextTick(()=>{console.log('resolving'); resolve();}) }); 
b.then(() => {
  console.log('resolved');
  re.match('abc');
});
