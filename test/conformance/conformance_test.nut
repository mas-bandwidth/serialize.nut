// TestConformanceCorpus: serialize-squirrel-conformance (DESIGN.md (i), the
// runner), format 2.0. It discovers every conformance/*.txt (never a fixed
// list), parses every record (STANDARD.md, "The vector format"), and checks
// what a runner must (STANDARD.md, "What a runner checks"): an accepted read
// decodes the stated value or bit pattern and consumes exactly `consumed`
// bits; a `writer canonical` record is re-emitted byte for byte; a
// `writer_input` record's input is written to exactly the record's bytes; a
// refused read is refused FOR ITS STATED REASON (the stream's first refusal),
// leaves its destination untouched and makes the stream terminal; a
// sequence's steps run in order on one stream; and `measure_at_least` is a
// floor for MeasureStream. Vector names are unique across the corpus.
//
// The controls STANDARD.md requires live here too ("A gate nobody has seen go
// red is a claim, not a measurement"): a corpus file whose operation has no
// runner is REJECTED (the vendored conformance-controls/unknown-operation.txt,
// and a scratch file spelling the retired `wstring`), and for each refusal
// rule a copy of src/ with that ONE rule deleted, loaded through its own
// entry, fails exactly the vectors conformance-controls/<rule>.expected names
// and no others.
//
// The step machine is the one serialize.go's conformance_test.go uses
// (TestConformanceCorpus): a single-operation record is a short step list, so
// there is one execution path for the operation files and the sequence files.
// A test passes by returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestConformanceCorpus: " + what;
};

local MIN64 = 0x8000000000000000;

// --- 128-bit number parsing (the vectors are up to 128 bits wide; this is
// number syntax, never a codec) ------------------------------------------------
local ucmp = function(a, b) {
  local ax = a[1] ^ MIN64;
  local ay = b[1] ^ MIN64;
  if (ax < ay) return -1;
  if (ax > ay) return 1;
  local lx = a[0] ^ MIN64;
  local ly = b[0] ^ MIN64;
  if (lx < ly) return -1;
  if (lx > ly) return 1;
  return 0;
};

local usub = function(a, b) {
  local lo = a[0] - b[0];
  local br = ucmp([a[0], 0], [b[0], 0]) < 0 ? 1 : 0;
  local hi = a[1] - b[1] - br;
  return [lo, hi];
};

local uadd = function(a, b) {
  local lo = a[0] + b[0];
  local ca = ucmp([a[0], 0], [lo, 0]) > 0 ? 1 : 0;
  local hi = a[1] + b[1] + ca;
  return [lo, hi];
};

local lsh = function(x, n) {
  if (n == 0) return x;
  if (n < 64) return [(x[0] << n), ((x[1] << n) | (x[0] >>> (64 - n)))];
  return [0, x[0] << (n - 64)];
};

local mul10 = function(x) { return uadd(lsh(x, 3), lsh(x, 1)); };
local neg128 = function(x) { return usub([0, 0], x); };
local same128 = function(a, b) { return a[0] == b[0] && a[1] == b[1]; };
local int128From64 = function(x) { return [x, x < 0 ? -1 : 0]; };

local hexDig = function(c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw "bad hex digit " + c;
};

local hexVal16 = function(h) {
  local v = 0;
  foreach (c in h) v = (v << 4) | hexDig(c);
  return v;
};

local hexTo128 = function(s) {
  while ((s.len() % 16) != 0) s = "0" + s;
  local lo = hexVal16(s.slice(s.len() - 16));
  local hi = s.len() > 16 ? hexVal16(s.slice(0, s.len() - 16)) : 0;
  return [lo, hi];
};

local parseDec = function(s) {
  local num = [0, 0];
  foreach (c in s) {
    local d = c - '0';
    num = uadd(mul10(num), [d, 0]);
  }
  return num;
};

local parseNumber = function(tok) {
  local t = tok;
  local neg = false;
  if (t.len() > 0 && t.slice(0, 1) == "-") { neg = true; t = t.slice(1); }
  else if (t.len() > 0 && t.slice(0, 1) == "+") t = t.slice(1);
  local v = (t.len() >= 2 && t.slice(0, 2) == "0x") ? hexTo128(t.slice(2)) : parseDec(t);
  if (neg) v = neg128(v);
  return v;
};

// parseFloatParam(tok): a float parameter (STANDARD.md, The vector format: a
// `param` takes its operation's type, so `res` is a float32). Squirrel's
// tofloat reads an all-digit token as an integer first and saturates it at
// 2^63, so an integer-spelled value is parsed as up to 128 bits and widened
// lane by lane: exact for every float32, which has 24 significant bits.
local u64ToFloat = function(x) { return (x >>> 1).tofloat() * 2.0 + (x & 1).tofloat(); };
local parseFloatParam = function(tok) {
  local t = tok;
  local neg = false;
  if (t.len() > 0 && (t[0] == '-' || t[0] == '+')) { neg = t[0] == '-'; t = t.slice(1); }
  local digits = t.len() > 0;
  foreach (c in t) if (c < '0' || c > '9') digits = false;
  if (!digits) return tok.tofloat();
  local v = parseDec(t);
  local f = u64ToFloat(v[1]) * 18446744073709551616.0 + u64ToFloat(v[0]);
  return neg ? -f : f;
};

local signed32 = function(x) {
  local v = x & 0xffffffff;
  if (v & 0x80000000) v = v - 0x100000000;
  return v;
};

// --- text and bytes helpers --------------------------------------------------
local strip = function(s) {
  local a = 0, b = s.len();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
  return s.slice(a, b);
};

local tokens = function(line) {
  local out = [];
  local cur = "";
  foreach (ch in line) {
    local c = ch & 0xff;
    if (c == 32 || c == 9 || c == 13) {
      if (cur.len() > 0) { out.append(cur); cur = ""; }
    } else cur += c.tochar();
  }
  if (cur.len() > 0) out.append(cur);
  return out;
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  for (local i = 0; i < b.len(); i++) s += (b[i] & 0xff).tochar();
  return s;
};

local blobOfHexs = function(hexs) {
  local words = [];
  foreach (w in split(hexs, " ")) if (w.len() > 0) words.append(w);
  local b = blob(words.len());
  for (local i = 0; i < words.len(); i++) b[i] = (hexDig(words[i][0]) << 4) | hexDig(words[i][1]);
  return b;
};

local hexValue = function(tok) {
  local v = 0;
  foreach (c in tok) v = (v << 4) | hexDig(c);
  return v;
};

local hexLane = function(x) {
  local digs = "0123456789ABCDEF";
  local out = "";
  for (local i = 15; i >= 0; i--) out += digs[((x >>> (i * 4)) & 15)].tochar();
  return out;
};

local hex128 = function(p) { return hexLane(p[1]) + hexLane(p[0]); };

local blobToHex = function(b) {
  local hex = "0123456789ABCDEF";
  local o = "";
  for (local i = 0; i < b.len(); i++) {
    if (i > 0) o += " ";
    o += hex[(b[i] >> 4) & 15].tochar();
    o += hex[b[i] & 15].tochar();
  }
  return o;
};

local stringToBlob = function(s) {
  local b = blob(s.len());
  for (local i = 0; i < s.len(); i++) b[i] = s[i] & 0xff;
  return b;
};

local bytesOfString = function(s) {
  local out = [];
  foreach (ch in s) out.append(ch & 0xff);
  return out;
};

// the float32 bit conversion the vector vocabulary needs, taken from the
// library's own serialize_float.nut exports (never a second narrowing)
// (loaded the way the closed loader does, DESIGN.md (f): vargv[0] the exports
// table, vargv[1] a require that resolves beside it)
local srcRequire;
srcRequire = function(name, who = null) {
  local m = {};
  loadfile(::SERIALIZE_ROOT + "/src/" + name + ".nut", true).bindenv(::getroottable())(m, srcRequire);
  return m;
};
local floatMod = srcRequire("serialize_float");
local float32Bits = floatMod.float32Bits;
local float32FromBits = floatMod.float32FromBits;

// THE REFUSAL REASONS (STANDARD.md, Refusal reasons): the closed list. A
// refused vector states one of them; a missing or unknown reason makes the
// vector malformed, which is red.
local REASONS = {
  past_end = true, value_out_of_range = true, nonzero_padding = true,
  trailing_data = true, non_finite_float = true, invalid_utf8 = true,
  embedded_nul = true, non_canonical = true,
};

// --- the vector parser (STANDARD.md, "The vector format") --------------------
local newRecord = function() {
  return {
    operation = "", name = "", params = {}, paramNames = [], steps = [],
    bytes = blob(0), expectKind = "", expect = "", reason = null, consumed = 0,
    hasConsumed = false, measureAtLeast = 0, hasMeasure = false, writer = false,
    writerInput = null,
  };
};

local parseRecords = function(text) {
  local recs = [];
  local rec = null;
  foreach (line in split(text, "\n")) {
    if (line.len() > 0 && line[0] == '#') continue;
    local s = strip(line);
    if (s.len() == 0) {
      if (rec != null && ("operation" in rec) && rec.operation != "") recs.append(rec);
      rec = null;
      continue;
    }
    if (rec == null) rec = newRecord();
    local sp = s.find(" ");
    local key, rest;
    if (sp == null) { key = s; rest = ""; }
    else { key = s.slice(0, sp); rest = strip(s.slice(sp + 1)); }
    if (key == "operation") rec.operation = rest;
    else if (key == "name") rec.name = rest;
    else if (key == "param") {
      local eq = rest.find("=");
      check(eq != null, "param needs `name = value`: " + s);
      local pn = strip(rest.slice(0, eq));
      local pv = strip(rest.slice(eq + 1));
      if (pn == "step") rec.steps.append(pv);
      else { rec.paramNames.append(pn); rec.params[pn] <- pv; }
    }
    else if (key == "bytes") rec.bytes = blobOfHexs(rest);
    else if (key == "expect") {
      local w = tokens(rest);
      if (w.len() > 0 && w[0] == "refused") {
        check(w.len() == 2, (rec.name != "" ? rec.name : "a record") + ": `expect refused` must state exactly one reason: " + s);
        check(w[1] in REASONS, (rec.name != "" ? rec.name : "a record") + ": unknown refusal reason `" + w[1] + "`");
        rec.expectKind = "refused";
        rec.reason = w[1];
      }
      else {
        local eq = rest.find("=");
        check(eq != null, "bad expect: " + s);
        local k = strip(rest.slice(0, eq));
        local v = strip(rest.slice(eq + 1));
        check(k == "value" || k == "bits", "unknown expect kind " + k);
        rec.expectKind = k;
        rec.expect = v;
      }
    }
    else if (key == "consumed") { rec.consumed = rest.tointeger(); rec.hasConsumed = true; }
    else if (key == "measure_at_least") { rec.measureAtLeast = rest.tointeger(); rec.hasMeasure = true; }
    else if (key == "writer") {
      check(rest == "canonical", "unknown writer mode " + rest);
      rec.writer = true;
    }
    else if (key == "writer_input") {
      local w = tokens(rest);
      check(w.len() == 3 && w[0] == "bits" && w[1] == "=" && w[2].len() > 2 && w[2].slice(0, 2) == "0x",
        "writer_input must be `bits = 0x...`: " + s);
      rec.writerInput = hexValue(w[2].slice(2));
    }
    else throw "unknown record key: " + s;
  }
  if (rec != null && ("operation" in rec) && rec.operation != "") recs.append(rec);
  return recs;
};

// --- the step machine (ported from serialize.go conformance_test.go) ----------
local numericKinds = {
  bits = true, uint128 = true, float = true, double = true,
  compressed_float = true, int = true, int64 = true, int128 = true,
  int_relative = true, fixed = true,
};

local newStep = function(kind) {
  return {
    kind = kind, width = 0, min = [0, 0], max = [0, 0],
    integerBits = 0, fractionBits = 0, fmin = 0.0, fmax = 0.0, fres = 0.0,
    previous = 0, pattern = [0, 0], boolean = false, data = null, text = "",
  };
};

local stepFromWords = function(text) {
  local w = tokens(text);
  check(w.len() > 0, "empty step");
  local number = function(i) {
    check(i < w.len(), "step `" + text + "` is missing a number");
    return parseNumber(w[i]);
  };
  local s;
  if (w[0] == "bool" && w.len() == 1) s = newStep("bool");
  else if (w[0] == "align" && w.len() == 1) s = newStep("align");
  else if (w[0] == "end" && w.len() == 1) s = newStep("end");
  else if (w[0] == "float" && w.len() == 1) s = newStep("float");
  else if (w[0] == "double" && w.len() == 1) s = newStep("double");
  else if (w[0] == "uint128" && w.len() == 1) s = newStep("uint128");
  else if (w[0] == "int_relative" && w.len() == 2) {
    s = newStep("int_relative"); s.previous = signed32(number(1)[0]);
  }
  else if (w[0] == "compressed_float" && w.len() == 4) {
    s = newStep("compressed_float");
    s.fmin = parseFloatParam(w[1]); s.fmax = parseFloatParam(w[2]); s.fres = parseFloatParam(w[3]);
  }
  else if (w[0] == "bits" && w.len() == 2) { s = newStep("bits"); s.width = number(1)[0]; }
  else if (w[0] == "object" && w.len() == 2) { s = newStep("object"); s.width = number(1)[0]; }
  else if (w[0] == "bytes" && w.len() == 2) { s = newStep("bytes"); s.width = number(1)[0]; }
  else if (w[0] == "string" && w.len() == 2) { s = newStep("string"); s.width = number(1)[0]; }
  else if ((w[0] == "int" || w[0] == "int64" || w[0] == "int128") && w.len() == 3) {
    s = newStep(w[0]); s.min = number(1); s.max = number(2);
  }
  else if (w[0] == "fixed" && w.len() == 5) {
    s = newStep("fixed");
    s.integerBits = number(1)[0]; s.fractionBits = number(2)[0];
    s.min = number(3); s.max = number(4);
  }
  else throw "no runner for step `" + text + "`";
  return s;
};

local operationTakesParam = function(operation, name) {
  if (name == "preceding_bits") return operation == "align" || operation == "bytes";
  if (name == "bits") return operation == "bits";
  if (name == "count") return operation == "bytes";
  if (name == "buffer_size") return operation == "string";
  if (name == "previous") return operation == "int_relative";
  if (name == "res") return operation == "compressed_float";
  if (name == "integer_bits" || name == "fraction_bits") return operation == "fixed";
  if (name == "min" || name == "max") {
    return operation == "int" || operation == "int64" || operation == "int128" ||
      operation == "fixed" || operation == "compressed_float";
  }
  return false;
};

local buildSteps = function(rec) {
  if (rec.operation == "sequence") {
    check(rec.steps.len() > 0, rec.name + ": a sequence states no steps");
    local out = [];
    foreach (text in rec.steps) out.append(stepFromWords(text));
    return out;
  }
  check(rec.steps.len() == 0, rec.name + ": steps are only meaningful on a sequence");

  local number = function(name) {
    check(name in rec.params, rec.name + ": no " + name + " parameter");
    return parseNumber(rec.params[name]);
  };
  local floatParam = function(name) {
    check(name in rec.params, rec.name + ": no " + name + " parameter");
    return parseFloatParam(rec.params[name]);
  };

  local steps = [];
  if ("preceding_bits" in rec.params) {
    local w = parseNumber(rec.params["preceding_bits"])[0];
    if (w > 0) { local b = newStep("bits"); b.width = w; steps.append(b); }
  }

  local s;
  local op = rec.operation;
  if (op == "bits") { s = newStep("bits"); s.width = number("bits")[0]; }
  else if (op == "bool") s = newStep("bool");
  else if (op == "uint128") s = newStep("uint128");
  else if (op == "align") s = newStep("align");
  else if (op == "end") s = newStep("end");
  else if (op == "float") s = newStep("float");
  else if (op == "double") s = newStep("double");
  else if (op == "int" || op == "int64" || op == "int128") {
    s = newStep(op); s.min = number("min"); s.max = number("max");
  }
  else if (op == "int_relative") {
    s = newStep("int_relative"); s.previous = signed32(number("previous")[0]);
  }
  else if (op == "compressed_float") {
    s = newStep("compressed_float");
    s.fmin = floatParam("min"); s.fmax = floatParam("max"); s.fres = floatParam("res");
  }
  else if (op == "bytes") { s = newStep("bytes"); s.width = number("count")[0]; }
  else if (op == "string") { s = newStep("string"); s.width = number("buffer_size")[0]; }
  else if (op == "fixed") {
    s = newStep("fixed");
    s.integerBits = number("integer_bits")[0]; s.fractionBits = number("fraction_bits")[0];
    s.min = number("min"); s.max = number("max");
  }
  else throw rec.name + ": no runner for operation `" + op + "`";
  steps.append(s);
  return steps;
};

// --- running one step on any stream -----------------------------------------
// The step carries its value both ways, so the writer and the measure leg
// re-serialize exactly what the reader decoded.
local runStep = function(stream, s) {
  local kind = s.kind;
  if (kind == "bits") {
    local h = { value = s.pattern[0] };
    local ok = stream.serializeBits64(h, s.width);
    if (ok) s.pattern = [h.value, 0];
    return ok;
  }
  if (kind == "bool") {
    local h = { value = s.boolean };
    local ok = stream.serializeBool(h);
    if (ok) s.boolean = h.value;
    return ok;
  }
  if (kind == "uint128") {
    local h = { value = [s.pattern[0], s.pattern[1]] };
    local ok = stream.serializeUint128(h);
    if (ok) s.pattern = [h.value[0], h.value[1]];
    return ok;
  }
  if (kind == "align") return stream.serializeAlign();
  if (kind == "end") return stream.serializeEnd();
  if (kind == "int") {
    local h = { value = signed32(s.pattern[0]) };
    local ok = stream.serializeInt(h, signed32(s.min[0]), signed32(s.max[0]));
    if (ok) s.pattern = int128From64(h.value);
    return ok;
  }
  if (kind == "int64") {
    local h = { value = s.pattern[0] };
    local ok = stream.serializeInt64(h, s.min[0], s.max[0]);
    if (ok) s.pattern = int128From64(h.value);
    return ok;
  }
  if (kind == "int128") {
    local h = { value = [s.pattern[0], s.pattern[1]] };
    local ok = stream.serializeInt128(h, s.min, s.max);
    if (ok) s.pattern = [h.value[0], h.value[1]];
    return ok;
  }
  if (kind == "int_relative") {
    local h = { value = signed32(s.pattern[0]) };
    local ok = stream.serializeIntRelative(s.previous, h);
    if (ok) s.pattern = int128From64(h.value);
    return ok;
  }
  if (kind == "float") {
    local h = { value = float32FromBits(s.pattern[0]) };
    local ok = stream.serializeFloat(h);
    if (ok) s.pattern = [float32Bits(h.value), 0];
    return ok;
  }
  if (kind == "double") {
    local h = { value = casti2f(s.pattern[0]) };
    local ok = stream.serializeDouble(h);
    if (ok) s.pattern = [castf2i(h.value), 0];
    return ok;
  }
  if (kind == "compressed_float") {
    local h = { value = float32FromBits(s.pattern[0]) };
    local ok = stream.serializeCompressedFloat(h, s.fmin, s.fmax, s.fres);
    if (ok) s.pattern = [float32Bits(h.value), 0];
    return ok;
  }
  if (kind == "bytes") {
    if (stream.isReading()) s.data = blob(s.width);
    local ok = stream.serializeBytes(s.data);
    return ok;
  }
  if (kind == "string") {
    local h = { value = s.text };
    local ok = stream.serializeString(h, s.width);
    if (ok) s.text = h.value;
    return ok;
  }
  if (kind == "fixed") {
    if (s.integerBits + s.fractionBits <= 64) {
      local h = { value = s.pattern[0] };
      local ok = stream.serializeFixed64(h, s.integerBits, s.fractionBits, s.min[0], s.max[0]);
      if (ok) s.pattern = int128From64(h.value);
      return ok;
    }
    local h = { value = [s.pattern[0], s.pattern[1]] };
    local ok = stream.serializeFixed128(h, s.integerBits, s.fractionBits, s.min[0], s.max[0]);
    if (ok) s.pattern = [h.value[0], h.value[1]];
    return ok;
  }
  throw "no runner for step kind " + kind;
};

local stepSpan = function(steps, i) {
  return steps[i].kind == "object" ? 1 + steps[i].width : 1;
};

local runSteps;
local makeNested = function(steps, from, to, state) {
  local o = {};
  o.serialize <- function(stream) {
    local stop = runSteps(stream, steps, from, to, state);
    return stop == to;
  };
  return o;
};

runSteps = function(stream, steps, from, to, state) {
  local i = from;
  while (i < to) {
    local span = stepSpan(steps, i);
    if (steps[i].kind == "object") {
      local obj = makeNested(steps, i + 1, i + 1 + steps[i].width, state);
      if (!stream.serializeObject(obj)) { state.failed = steps[i]; return i; }
      i += span;
      continue;
    }
    if (!runStep(stream, steps[i])) {
      state.failed = steps[i];
      return i;
    }
    i += span;
  }
  return to;
};

// --- expectations ------------------------------------------------------------
local splitExpect = function(text) {
  local parts = split(text, "|");
  local out = [];
  foreach (p in parts) out.append(strip(p));
  return out;
};

local renderStepValue = function(s) {
  if (s.kind in numericKinds) return "0x" + hex128(s.pattern);
  if (s.kind == "bool") return s.boolean ? "true" : "false";
  if (s.kind == "bytes") return blobToHex(s.data == null ? blob(0) : s.data);
  if (s.kind == "string") return blobToHex(stringToBlob(s.text));
  if (s.kind == "align" || s.kind == "end") return "0";
  return "-";
};

local expectationMatches = function(s, expected) {
  if (s.kind in numericKinds) return same128(s.pattern, parseNumber(expected));
  return renderStepValue(s) == expected;
};

// --- sentinels (a refused read leaves them in place) -------------------------
local sentinelPattern = [0xCAFEF00D, 0];
local sentinelNumber = int128From64(-1234567);

local sentinelFor = function(kind) {
  if (kind == "int" || kind == "int64" || kind == "int128" ||
      kind == "int_relative" || kind == "fixed") return sentinelNumber;
  return sentinelPattern;
};

local seedSentinels = function(steps) {
  foreach (s in steps) {
    s.pattern = [sentinelFor(s.kind)[0], sentinelFor(s.kind)[1]];
    s.boolean = true;
    s.data = null;
    s.text = "";
  }
};

// --- the reader, writer and measure legs ------------------------------------
local checkDestination = function(rec, s) {
  if (s.kind in numericKinds) {
    check(same128(s.pattern, sentinelFor(s.kind)), rec.name + ": the refused read wrote to its destination");
  } else if (s.kind == "bool") {
    check(s.boolean == true, rec.name + ": the refused read wrote to its destination");
  }
};

local checkTerminal = function(rec, stream) {
  local before = stream.bitsProcessed();
  local h = { value = 0xFFFFFFFF };
  check(stream.serializeBits(h, 8) == false, rec.name + ": a read after the refusal succeeded; failure is not terminal");
  check(h.value == 0xFFFFFFFF, rec.name + ": the read after the refusal wrote to its destination");
  check(stream.bitsProcessed() == before, rec.name + ": the read after the refusal consumed bits");
};

local runReader = function(serialize, rec, steps) {
  seedSentinels(steps);
  local stream = serialize.ReadStream(rec.bytes);
  local state = { failed = null };
  local stoppedAt = runSteps(stream, steps, 0, steps.len(), state);

  if (rec.expectKind == "refused") {
    check(stoppedAt < steps.len(), rec.name + ": the read succeeded, the corpus requires refusal");
    // the FIRST refusal's reason is the stream's, and it must be the stated one
    // (STANDARD.md, Refusal reasons: any other reason is a disagreement about
    // the format, however red the stream ends up)
    check(stream.error() == rec.reason,
      rec.name + ": refused as " + stream.error() + ", the corpus states " + rec.reason);
    if (state.failed != null) checkDestination(rec, state.failed);
    // every later top-level step must refuse too, even where readable bits remain
    local i = stoppedAt + stepSpan(steps, stoppedAt);
    while (i < steps.len()) {
      local span = stepSpan(steps, i);
      local nextState = { failed = null };
      local stop = runSteps(stream, steps, i, i + span, nextState);
      check(stop < i + span, rec.name + ": step " + (i + 1) + " succeeded after step " + (stoppedAt + 1) + " was refused");
      i += span;
    }
    check(stream.error() == rec.reason,
      rec.name + ": the later refusals changed the reason to " + stream.error() + "; they are echoes of " + rec.reason);
    checkTerminal(rec, stream);
    return;
  }

  check(stoppedAt == steps.len(), rec.name + ": the read was refused, the corpus requires it accepted");

  local entries = splitExpect(rec.expect);
  local offset = steps.len() - entries.len();
  check(offset >= 0, rec.name + ": the expect list states more values than the vector has steps");
  for (local j = 0; j < entries.len(); j++) {
    if (entries[j] == "-") continue;
    local s = steps[offset + j];
    check(expectationMatches(s, entries[j]),
      rec.name + ": step " + (offset + j + 1) + " decoded " + renderStepValue(s) + ", the corpus states " + entries[j]);
  }
  if (rec.hasConsumed) {
    check(stream.bitsProcessed() == rec.consumed,
      rec.name + ": consumed " + stream.bitsProcessed() + " bits, the corpus states " + rec.consumed);
  }
};

local runWriter = function(serialize, rec, steps) {
  local cap = ((rec.bytes.len() + 64) / 8 * 8) + 8;
  local stream = serialize.WriteStream(blob(cap));
  local state = { failed = null };
  local stop = runSteps(stream, steps, 0, steps.len(), state);
  check(stop == steps.len(), rec.name + ": the writer refused a canonical vector (step " + (stop + 1) + ")");
  stream.flush();
  local got = stream.data();
  check(got.len() == rec.bytes.len(), rec.name + ": the writer emitted " + got.len() + " bytes, the corpus states " + rec.bytes.len());
  for (local i = 0; i < rec.bytes.len(); i++) {
    check((got[i] & 0xff) == (rec.bytes[i] & 0xff), rec.name + ": the writer emitted " + blobToHex(got) + ", the corpus states " + blobToHex(rec.bytes));
  }
};

local runMeasure = function(serialize, rec, steps) {
  local stream = serialize.MeasureStream();
  local state = { failed = null };
  local stop = runSteps(stream, steps, 0, steps.len(), state);
  check(stop == steps.len(), rec.name + ": the measure refused a step, a measure refuses nothing at runtime");
  check(stream.bitsProcessed() >= rec.measureAtLeast,
    rec.name + ": measured " + stream.bitsProcessed() + " bits, the corpus requires at least " + rec.measureAtLeast);
};

// runWriterInput: a `writer_input` record hands the writer that float32 and
// requires exactly the record's bytes (STANDARD.md, What a runner checks). It
// runs on refused vectors too: the input pins the writer, whatever the bytes
// decode to.
local runWriterInput = function(serialize, rec) {
  check(rec.operation == "compressed_float", rec.name + ": writer_input is only meaningful on compressed_float");
  local steps = buildSteps(rec);
  check(steps.len() == 1, rec.name + ": writer_input takes a single compressed_float step");
  steps[0].pattern = [rec.writerInput, 0];
  local cap = ((rec.bytes.len() + 64) / 8 * 8) + 8;
  local stream = serialize.WriteStream(blob(cap));
  check(runStep(stream, steps[0]), rec.name + ": the writer refused its writer_input");
  stream.flush();
  local got = stream.data();
  check(got.len() == rec.bytes.len() && blobToHex(got) == blobToHex(rec.bytes),
    rec.name + ": the writer emitted " + blobToHex(got) + " for its writer_input, the corpus states " + blobToHex(rec.bytes));
};

// --- one file, then the whole corpus ----------------------------------------
local prepare = function(rec) {
  check(rec.operation != "" && rec.name != "", "a record needs both an operation and a name");
  foreach (pn in rec.paramNames) {
    check(operationTakesParam(rec.operation, pn),
      rec.name + ": no runner for parameter `" + pn + "` on operation `" + rec.operation + "`");
  }
  return buildSteps(rec);
};

// runRecord: every leg one record carries; it throws on the first failure
local runRecord = function(serialize, rec) {
  local steps = prepare(rec);
  check(rec.expectKind != "", rec.name + ": no expect line");
  runReader(serialize, rec, steps);
  if (rec.expectKind != "refused") {
    if (rec.writer) runWriter(serialize, rec, steps);
    if (rec.hasMeasure) runMeasure(serialize, rec, steps);
  }
  if (rec.writerInput != null) runWriterInput(serialize, rec);
};

local runRecords = function(serialize, recs) {
  foreach (rec in recs) runRecord(serialize, rec);
};

local runPath = function(serialize, path, label) {
  local recs = parseRecords(readText(path));
  runRecords(serialize, recs);
  print(label + ": " + recs.len() + " records\n");
  return recs.len();
};

// --- the rule-deletion controls --------------------------------------------
// readBlob(path) / writeBlob(path, b): whole files as blobs, no conversion
local readBlob = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  return b;
};

local writeBlob = function(path, b) {
  local f = file(path, "wb");
  if (b.len() > 0) f.writeblob(b);
  f.close();
};

// findAll(hay, needle): every offset of the blob needle in the blob hay
local findAll = function(hay, needle) {
  local out = [];
  local n = needle.len();
  for (local i = 0; i + n <= hay.len(); i++) {
    local j = 0;
    while (j < n && hay[i + j] == needle[j]) j++;
    if (j == n) out.append(i);
  }
  return out;
};

// patchBlob(b, needle, patch): b with its ONE occurrence of needle replaced.
// A needle that stops matching, or matches twice, is a failure of the
// control, never a silent no-op (the reference's FATAL_ERROR).
local patchBlob = function(b, needle, patch, what) {
  local nb = stringToBlob(needle);
  local at = findAll(b, nb);
  check(at.len() == 1, what + ": the needle occurs " + at.len() + " times, it must occur once: " + needle);
  local pb = stringToBlob(patch);
  local out = blob(0);
  b.seek(0);
  if (at[0] > 0) out.writeblob(b.readblob(at[0]));
  if (pb.len() > 0) out.writeblob(pb);
  b.seek(at[0] + nb.len());
  local rest = b.len() - at[0] - nb.len();
  if (rest > 0) out.writeblob(b.readblob(rest));
  return out;
};

// The controls: one per refusal rule the reference names, each the needle(s)
// of src/ that delete that one rule and nothing else (the reference
// CMakeLists.txt, SERIALIZE_CONTROL_*). Where this port spells one reference
// rule at several sites (the align padding of align, bytes and string; the
// ranged int of int, the int_relative payloads and the string length), the
// control deletes it at every site, as the reference's one shared function.
local CONTROLS = [
  { rule = "align-padding", patches = [
    { file = "serialize_bits.nut", needle = "if (s._take(n) != 0) return s._fail(Err.NonzeroPadding);", patch = "s._take(n); // NEGATIVE CONTROL" },
    { file = "serialize_bytes.nut", needle = "    local pad = s._take(align);\n    if (pad != 0) return s._fail(E.NonzeroPadding);\n  }\n  local n = data.len();", patch = "    s._take(align); // NEGATIVE CONTROL\n  }\n  local n = data.len();" },
    { file = "serialize_bytes.nut", needle = "    local pad = s._take(align);\n    if (pad != 0) return s._fail(E.NonzeroPadding);\n  }\n  if (!s._room(8 * length)) return false;\n  local data", patch = "    s._take(align); // NEGATIVE CONTROL\n  }\n  if (!s._room(8 * length)) return false;\n  local data" },
  ] },
  { rule = "ranged-reconstruction", patches = [
    { file = "serialize_int.nut", needle = "h.value = unsigned + min;", patch = "h.value = unsigned; // NEGATIVE CONTROL" },
    { file = "serialize_int_relative.nut", needle = "local c = previous + TIERS[i].min + off;", patch = "local c = previous + off; // NEGATIVE CONTROL" },
  ] },
  { rule = "ranged-range", patches = [
    { file = "serialize_int.nut", needle = "if (unsigned > ((max - min) & 0xFFFFFFFF)) return s._fail(SerializeError.ValueOutOfRange);", patch = "// NEGATIVE CONTROL" },
    { file = "serialize_int_relative.nut", needle = "if (off > TIERS[i].max - TIERS[i].min) return s._fail(SerializeError.ValueOutOfRange);", patch = "// NEGATIVE CONTROL" },
    { file = "serialize_bytes.nut", needle = "  if (offset > max - min) {\n    s._fail(E.ValueOutOfRange);\n    return { ok = false };\n  }\n", patch = "  // NEGATIVE CONTROL\n" },
  ] },
  { rule = "fixed-degenerate-terminal", patches = [
    { file = "serialize_fixed.nut", needle = "  if (s._error != null) return false;\n  if (p.numBits == 0) { h.value = p.rawMin; return true; }", patch = "  if (p.numBits == 0) { h.value = p.rawMin; return true; } // NEGATIVE CONTROL\n  if (s._error != null) return false;" },
    { file = "serialize_fixed.nut", needle = "  if (s._error != null) return false;\n  if (p.numBits == 0) { h.value = [p.rawMin[0], p.rawMin[1]]; return true; }", patch = "  if (p.numBits == 0) { h.value = [p.rawMin[0], p.rawMin[1]]; return true; } // NEGATIVE CONTROL\n  if (s._error != null) return false;" },
  ] },
  { rule = "float-finite", patches = [
    { file = "serialize_float.nut", needle = "    local bits = s._take(32);\n    if (!floatBitsAreFinite(bits)) return s._fail(SerializeError.NonFiniteFloat);", patch = "    local bits = s._take(32); // NEGATIVE CONTROL" },
  ] },
  { rule = "double-finite", patches = [
    { file = "serialize_float.nut", needle = "    local bits = lo | (hi << 32);\n    if (!doubleBitsAreFinite(bits)) return s._fail(SerializeError.NonFiniteFloat);", patch = "    local bits = lo | (hi << 32); // NEGATIVE CONTROL" },
  ] },
  { rule = "compressed-float-finite", patches = [
    { file = "serialize_compressed_float.nut", needle = "if (isNotFinite(result)) return s._fail(SerializeError.NonFiniteFloat);", patch = "// NEGATIVE CONTROL" },
  ] },
  { rule = "end-trailing-data", patches = [
    { file = "serialize_stream.nut", needle = "if (remaining >= 8) return _fail(SerializeError.TrailingData);", patch = "// NEGATIVE CONTROL" },
  ] },
  { rule = "end-padding", patches = [
    { file = "serialize_stream.nut", needle = "if (remaining > 0 && _take(remaining) != 0) return _fail(SerializeError.NonzeroPadding);", patch = "if (remaining > 0 && remaining < 8) _take(remaining); // NEGATIVE CONTROL" },
  ] },
  { rule = "int-relative-canonical", patches = [
    { file = "serialize_int_relative.nut", needle = "if (v - previous <= TIERS[TIERS.len() - 1].max) return s._fail(SerializeError.NonCanonical);", patch = "// NEGATIVE CONTROL" },
  ] },
  { rule = "string-embedded-nul", patches = [
    { file = "serialize_bytes.nut", needle = "  if (hasNul(data)) return s._fail(E.EmbeddedNul);\n", patch = "  // NEGATIVE CONTROL\n" },
  ] },
  { rule = "string-utf8", patches = [
    { file = "serialize_bytes.nut", needle = "  if (!utf8Valid(data)) return s._fail(E.InvalidUtf8);\n", patch = "  // NEGATIVE CONTROL\n" },
  ] },
  { rule = "string-utf8-surrogate", patches = [
    { file = "serialize_bytes.nut", needle = "      if (c == 0xed && c1 > 0x9f) return false;\n", patch = "      // NEGATIVE CONTROL\n" },
  ] },
  { rule = "int64-through-double", patches = [
    { file = "serialize_int.nut", needle = "h.value = off + min;", patch = "local t = (off + min).tofloat(); h.value = t >= 9223372036854775807.0 ? 0x7FFFFFFFFFFFFFFF : t.tointeger(); // NEGATIVE CONTROL" },
  ] },
  { rule = "wrong-reason", patches = [
    { file = "serialize_bytes.nut", needle = "if (hasNul(data)) return s._fail(E.EmbeddedNul);", patch = "if (hasNul(data)) return s._fail(E.InvalidUtf8); // NEGATIVE CONTROL" },
  ] },
];

// listDir(dir, suffix): the names in dir ending in suffix, sorted; the pinned
// interpreter has no directory-listing builtin, so list through system() into
// a scratch file
local listDir = function(root, dir, suffix, scratchName) {
  local scratch = root + "/build/" + scratchName;
  local rc = system("ls -1 '" + dir + "' > '" + scratch + "'");
  check(rc == 0, "could not list " + dir);
  local names = [];
  foreach (line in split(strip(readText(scratch)), "\n")) {
    local name = strip(line);
    if (name.len() < suffix.len() || name.slice(name.len() - suffix.len()) != suffix) continue;
    names.append(name);
  }
  names.sort();
  return names;
};

// sabotagedLibrary(root, control): a copy of src/ under build/controls/<rule>/
// with the control's patches applied, loaded through its own entry (the closed
// loader resolves modules beside the entry it was loaded from, DESIGN.md (f))
local sabotagedLibrary = function(root, control) {
  local dir = root + "/build/controls/" + control.rule;
  check(system("rm -rf '" + dir + "' && mkdir -p '" + dir + "'") == 0, "could not make " + dir);
  local files = {};
  foreach (name in listDir(root, root + "/src", ".nut", "controls-src-listing.txt")) files[name] <- readBlob(root + "/src/" + name);
  foreach (p in control.patches) {
    check(p.file in files, control.rule + ": no src/" + p.file);
    files[p.file] = patchBlob(files[p.file], p.needle, p.patch, control.rule + " src/" + p.file);
  }
  foreach (name, b in files) writeBlob(dir + "/" + name, b);
  return dofile(dir + "/serialize.nut", true);
};

// readExpected(path): the vector names a .expected file lists, one per line,
// # comments and blank lines skipped
local readExpected = function(path) {
  local out = {};
  foreach (line in split(readText(path), "\n")) {
    local s = strip(line);
    if (s.len() == 0 || s[0] == '#') continue;
    out[s] <- true;
  }
  return out;
};

function TestConformanceCorpus() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  local files = listDir(root, root + "/conformance", ".txt", "conformance-listing.txt");
  check(files.len() > 0, "empty corpus directory");
  local total = 0;
  local corpus = [];
  local names = {};
  foreach (f in files) {
    local recs = parseRecords(readText(root + "/conformance/" + f));
    foreach (rec in recs) {
      // a vector's name is unique across the corpus (STANDARD.md, The vector format)
      check(!(rec.name in names), f + ": the vector name " + rec.name + " is also in " + (rec.name in names ? names[rec.name] : ""));
      names[rec.name] <- f;
      corpus.append(rec);
    }
    runRecords(serialize, recs);
    print(f + ": " + recs.len() + " records\n");
    total += recs.len();
  }
  print("corpus: " + files.len() + " files, " + total + " records\n");

  // CONTROL: a corpus file whose operation has no runner is REJECTED, never
  // skipped: the reference's own control file, and a scratch file spelling the
  // retired `wstring`, which is an unknown operation in format 2.0.
  local rejected = false;
  try { runPath(serialize, root + "/conformance-controls/unknown-operation.txt", "control"); } catch (e) { rejected = true; }
  check(rejected, "conformance-controls/unknown-operation.txt was not rejected");
  local scratch = root + "/build/conformance-control-wstring.txt";
  local body = "operation wstring\nname control-wstring-is-retired\nparam buffer_size = 8\nbytes 00\nexpect value = 0\nconsumed 3\n";
  writeBlob(scratch, stringToBlob(body));
  rejected = false;
  try { runPath(serialize, scratch, "control"); } catch (e) { rejected = true; }
  check(rejected, "an operation spelled wstring was not rejected");
  print("control unknown-operation: both files rejected\n");

  // CONTROL: a malformed refusal (no reason, or one outside the closed list)
  // is red, never read as a bare refusal
  foreach (bad in ["expect refused\n", "expect refused overflow\n"]) {
    rejected = false;
    try { parseRecords("operation bits\nname control-reason\nparam bits = 1\nbytes\n" + bad); } catch (e) { rejected = true; }
    check(rejected, "a record with `" + strip(bad) + "` was not rejected");
  }

  // CONTROL, one per refusal rule: that rule deleted fails exactly its
  // .expected vectors, and no others
  foreach (control in CONTROLS) {
    local lib = sabotagedLibrary(root, control);
    local expected = readExpected(root + "/conformance-controls/" + control.rule + ".expected");
    local red = {};
    foreach (rec in corpus) {
      local failed = false;
      try { runRecord(lib, rec); } catch (e) { failed = true; }
      if (failed) red[rec.name] <- true;
    }
    local wrong = [];
    foreach (name, _ in red) if (!(name in expected)) wrong.append("red but not listed: " + name);
    foreach (name, _ in expected) if (!(name in red)) wrong.append("listed but green: " + name);
    foreach (w in wrong) print("control " + control.rule + ": " + w + "\n");
    check(expected.len() > 0, "control " + control.rule + ": its .expected lists nothing");
    check(wrong.len() == 0, "control " + control.rule + " did not fail exactly its .expected vectors");
    print("control " + control.rule + ": " + red.len() + " vectors red, exactly its .expected\n");
  }
  check(system("rm -rf '" + root + "/build/controls'") == 0, "could not remove build/controls");
}
