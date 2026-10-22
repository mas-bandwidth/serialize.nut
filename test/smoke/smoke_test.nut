// TestSmoke: the skeleton of serialize-squirrel-design (DESIGN.md (i), the
// runner; the card's TEST line). It pins, with no family file present or
// needed: the entry loads under the pinned VM; every API name DESIGN.md lists
// exists; the lazy dispatch raises its not-implemented error by name; the
// latch holds; and loading is closed. A test throws to fail.

local check = function(cond, what) {
  if (!cond) throw "TestSmoke: " + what;
};

// raises(fn, prefix): fn() throws a string starting with prefix. fn is called
// directly, never through .call or acall: sq prints a throw that crosses a
// native call to stderr even when it is caught (DESIGN.md (i)).
local raises = function(fn, prefix, what) {
  local got = null;
  try { fn(); } catch (e) { got = e; }
  check(got != null, what + ": did not raise");
  check(typeof got == "string" && got.len() >= prefix.len() && got.slice(0, prefix.len()) == prefix,
    what + ": raised " + got + ", want " + prefix);
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  foreach (c in b) s += c.tochar();
  return s;
};

local writeText = function(path, text) {
  local f = file(path, "wb");
  foreach (c in text) f.writen(c, 'b');
  f.close();
};

// the names DESIGN.md (a) lists, one per line in its API block:
//   api <name>            a name of the table the entry returns
//   method <name>         a method of every stream
//   write <name>          a method of WriteStream only
local designNames = function(root) {
  local names = { api = [], method = [], write = [] };
  local text = readText(root + "/DESIGN.md");
  foreach (line in split(text, "\n")) {
    local words = split(line, " ");
    if (words.len() == 2 && words[0] in names) names[words[0]].append(words[1]);
  }
  return names;
};

function TestSmoke() {
  local root = ::SERIALIZE_ROOT;

  // THE NUMBER MODEL (DESIGN.md (c)): the pin is sq64 with SQUSEDOUBLE
  check(_intsize_ == 8 && _floatsize_ == 8, "the VM is not sq64 + SQUSEDOUBLE");

  // LOADING IS CLOSED (DESIGN.md (f)): a shadowing serialize_stream.nut in the
  // working directory and one level above src is never loaded. Each shadow
  // raises when run, which is proved first, so a load of either would raise.
  local shadows = [ "serialize_stream.nut", root + "/serialize_stream.nut" ];
  foreach (path in shadows) writeText(path, "throw \"SHADOW \" + \"" + path + "\";\n");
  local failure = null;
  local serialize = null;
  try {
    foreach (path in shadows) {
      local shadow = loadfile(path, true);
      raises(function() { shadow(); }, "SHADOW", "the shadow at " + path);
    }
    serialize = dofile(root + "/src/serialize.nut", true);
  } catch (e) {
    failure = e;
  }
  foreach (path in shadows) remove(path);
  if (failure != null) throw failure;

  check(typeof serialize == "table", "the entry returned " + typeof serialize + ", not the API table");
  check(serialize.dir == root + "/src", "the loader resolves " + serialize.dir + ", not " + root + "/src");

  // every API name DESIGN.md lists exists
  local names = designNames(root);
  check(names.api.len() > 0 && names.method.len() > 0 && names.write.len() > 0, "DESIGN.md lists no API names");
  local ws = serialize.WriteStream(blob(16));
  local rs = serialize.ReadStream(blob(0));
  local ms = serialize.MeasureStream();
  foreach (n in names.api) check(n in serialize, "the API table has no " + n);
  foreach (n in names.method) {
    foreach (s in [ws, rs, ms]) check(n in s, "a stream has no method " + n);
  }
  foreach (n in names.write) check(n in ws, "WriteStream has no method " + n);
  check(ws.isWriting() && !ws.isReading(), "WriteStream direction");
  check(!rs.isWriting() && rs.isReading(), "ReadStream direction");
  check(ms.isWriting() && !ms.isReading(), "MeasureStream direction");

  // THE LAZY DISPATCH (DESIGN.md (h)): a family whose file is absent raises
  // its not-implemented error by name, on every stream kind. The family is a
  // test-only name no card creates, so this stays green as families land.
  foreach (s in [ws, rs, ms]) {
    raises(function() { s._arm("smoke_test_only", "serializeSmokeTestOnly"); },
      "serialize: serializeSmokeTestOnly not implemented", "the absent family");
  }
  // and the loader refuses a name that is not a basename beside it
  raises(function() { ws._arm("../smoke", "serializeSmokeTestOnly"); },
    "serialize: the loader refuses serialize_../smoke", "a traversal name");

  // THE REFUSAL REASONS (STANDARD.md, Refusal reasons): exactly the closed
  // list of eight, each spelled as the standard spells it, and None
  local reasons = {
    PastEnd = "past_end", ValueOutOfRange = "value_out_of_range",
    NonzeroPadding = "nonzero_padding", TrailingData = "trailing_data",
    NonFiniteFloat = "non_finite_float", InvalidUtf8 = "invalid_utf8",
    EmbeddedNul = "embedded_nul", NonCanonical = "non_canonical",
  };
  local kinds = 0;
  foreach (k, v in serialize.SerializeError) {
    kinds++;
    if (k == "None") { check(v == null, "SerializeError.None is " + v); continue; }
    check(k in reasons && reasons[k] == v, "SerializeError." + k + " = " + v + " is not on the closed list");
  }
  check(kinds == 9, "SerializeError has " + kinds + " kinds, want the eight reasons and None");

  // THE LATCH (DESIGN.md (g)): on a ReadStream over empty data a read of one
  // bit fails and latches PastEnd (STANDARD.md Reader Obligations); a later
  // call fails, consumes nothing and leaves its holder unchanged; the first
  // error sticks
  check(rs.ok() && rs.error() == serialize.SerializeError.None, "a fresh ReadStream is not healthy");
  check(rs._room(1) == false, "a one-bit read of empty data did not fail");
  check(rs.error() == serialize.SerializeError.PastEnd, "the empty read latched " + rs.error());
  // zero-bit operations consult the latch too: an align on an aligned stream
  // and an end refuse on a failed stream, keeping the first reason (STANDARD.md,
  // Failure is terminal). Reversed witness: the format 1.1 align returned true.
  check(rs.alignBits() == 0 && rs.serializeAlign() == false, "an aligned align succeeded on a failed stream");
  check(rs.serializeEnd() == false && rs.error() == serialize.SerializeError.PastEnd, "an end on a failed stream answered " + rs.error());
  local holder = { value = 7 };
  local later = { serialize = function(stream) { holder.value = 9; return true; } };
  check(rs.serializeObject(later) == false, "a call after the latch succeeded");
  check(holder.value == 7, "a call after the latch changed its holder to " + holder.value);
  check(rs.bitsProcessed() == 0, "a call after the latch consumed bits");
  local refusing = { serialize = function(stream) { return false; } };
  check(rs.serializeObject(refusing) == false && rs.error() == serialize.SerializeError.PastEnd,
    "the first error did not stick");
  // an object that refuses its own value latches ValueOutOfRange (DESIGN.md (a))
  local rs2 = serialize.ReadStream(blob(0));
  check(rs2.serializeObject(refusing) == false && rs2.error() == serialize.SerializeError.ValueOutOfRange,
    "a refusing object latched " + rs2.error());
  check(rs2.serializeObject(later) == false && holder.value == 7, "the object latch is not terminal");
  // reset clears the latch
  rs2.reset(blob(0));
  check(rs2.ok(), "reset did not clear the latch");

  // the write capacity and the measure bound (DESIGN.md (g)): a write past the
  // buffer latches PastEnd; a measure refuses nothing and charges 7 per align
  check(ws._room(128) && !ws._room(129) && ws.error() == serialize.SerializeError.PastEnd, "the write capacity");
  local wa = serialize.WriteStream(blob(8));
  check(!wa._room(65) && wa.serializeAlign() == false, "an aligned align succeeded on a failed writer");
  check(ms._room(1 << 40) && ms.alignBits() == 7, "the measure bound");
  // a failed measure stream is terminal: once it latches (here a non-finite
  // float) every later call refuses and charges nothing. Reversed witness: the
  // format 1.1 measure arms of bits, bool, the uints, align and compressed
  // float charged and returned true.
  local mf = serialize.MeasureStream();
  check(mf.serializeFloat({ value = casti2f(0x7FF8000000000000) }) == false, "the measure accepted a NaN");
  local mcalls = [
    function() { return mf.serializeBits({ value = 1 }, 3); },
    function() { return mf.serializeBits64({ value = 1 }, 40); },
    function() { return mf.serializeBool({ value = true }); },
    function() { return mf.serializeUint8({ value = 1 }); },
    function() { return mf.serializeUint16({ value = 1 }); },
    function() { return mf.serializeUint32({ value = 1 }); },
    function() { return mf.serializeUint64({ value = 1 }); },
    function() { return mf.serializeAlign(); },
    function() { return mf.serializeCompressedFloat({ value = 1.0 }, 0.0, 10.0, 0.01); },
    function() { return mf.serializeEnd(); },
  ];
  foreach (i, call in mcalls) check(call() == false, "measure call " + i + " succeeded on a failed measure stream");
  check(mf.bitsProcessed() == 0 && mf.error() == serialize.SerializeError.NonFiniteFloat,
    "the failed measure charged " + mf.bitsProcessed() + " bits, reason " + mf.error());
  raises(function() { serialize.WriteStream(blob(12)); }, "serialize: bit writer buffer size must be a multiple of 8 bytes", "a 12-byte buffer");
}
