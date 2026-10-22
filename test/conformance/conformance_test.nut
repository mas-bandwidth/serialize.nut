// TestConformanceCorpus: serialize-squirrel-conformance (DESIGN.md (i), the
// runner). It discovers every conformance/*.txt (never a fixed list), parses
// every record (STANDARD.md, "The vector format"), and checks what a runner
// must (STANDARD.md, "What a runner checks"): an accepted read decodes the
// stated value or bit pattern and consumes exactly `consumed` bits; a
// `writer canonical` record is re-emitted byte for byte; a refused read is
// refused, leaves its destination untouched and makes the stream terminal; a
// sequence's steps run in order on one stream; and `measure_at_least` is a
// floor for MeasureStream. The two controls STANDARD.md requires live here
// too: a corpus file whose operation has no runner is REJECTED, and a reader
// with the align-padding refusal switched off through a test-only hook goes
// red on exactly the vectors that pin that rule.
//
// The step machine is the one serialize.go v1.15.1's conformance_test.go uses
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

local encodeCodepoint = function(cp) {
  local out = [];
  if (cp < 0x80) out.append(cp);
  else if (cp < 0x800) { out.append(0xc0 | (cp >>> 6)); out.append(0x80 | (cp & 0x3f)); }
  else if (cp < 0x10000) { out.append(0xe0 | (cp >>> 12)); out.append(0x80 | ((cp >>> 6) & 0x3f)); out.append(0x80 | (cp & 0x3f)); }
  else { out.append(0xf0 | (cp >>> 18)); out.append(0x80 | ((cp >>> 12) & 0x3f)); out.append(0x80 | ((cp >>> 6) & 0x3f)); out.append(0x80 | (cp & 0x3f)); }
  return out;
};

local stringFromCodepoints = function(cps) {
  local bytes = [];
  foreach (cp in cps) foreach (b in encodeCodepoint(cp)) bytes.append(b);
  local s = "";
  foreach (b in bytes) s += (b & 0xff).tochar();
  return s;
};

local utf8Codepoints = function(s) {
  local b = bytesOfString(s);
  local out = [];
  local i = 0;
  while (i < b.len()) {
    local c = b[i];
    local cp = 0xfffd;
    local n = 1;
    if (c < 0x80) cp = c;
    else if (c >= 0xc2 && c <= 0xdf && i + 1 < b.len() && (b[i + 1] & 0xc0) == 0x80) {
      cp = ((c & 0x1f) << 6) | (b[i + 1] & 0x3f); n = 2;
    } else if (c >= 0xe0 && c <= 0xef && i + 2 < b.len() &&
      (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80) {
      cp = ((c & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f); n = 3;
    } else if (c >= 0xf0 && c <= 0xf4 && i + 3 < b.len() &&
      (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80 && (b[i + 3] & 0xc0) == 0x80) {
      cp = ((c & 0x07) << 18) | ((b[i + 1] & 0x3f) << 12) | ((b[i + 2] & 0x3f) << 6) | (b[i + 3] & 0x3f); n = 4;
    }
    out.append(cp);
    i += n;
  }
  return out;
};

local unitsFromString = function(s) {
  local out = [];
  foreach (cp in utf8Codepoints(s)) {
    if (cp >= 0x10000) {
      local v = cp - 0x10000;
      out.append(0xd800 + (v >>> 10));
      out.append(0xdc00 + (v & 0x3ff));
    } else out.append(cp);
  }
  return out;
};

local hex4 = function(v) {
  local digs = "0123456789ABCDEF";
  local out = "";
  for (local i = 3; i >= 0; i--) out += digs[((v >>> (i * 4)) & 15)].tochar();
  return out;
};

local renderUnits = function(s) {
  local out = "";
  local first = true;
  foreach (u in unitsFromString(s)) {
    if (!first) out += " ";
    out += hex4(u);
    first = false;
  }
  return out;
};

// the float32 bit conversion the vector vocabulary needs, taken from the
// library's own serialize_float.nut exports (never a second narrowing)
local floatMod = {};
loadfile(::SERIALIZE_ROOT + "/src/serialize_float.nut", true).bindenv(::getroottable())(floatMod, null);
local float32Bits = floatMod.float32Bits;
local float32FromBits = floatMod.float32FromBits;

// --- the vector parser (STANDARD.md, "The vector format") --------------------
local newRecord = function() {
  return {
    operation = "", name = "", params = {}, paramNames = [], steps = [],
    bytes = blob(0), expectKind = "", expect = "", consumed = 0,
    hasConsumed = false, measureAtLeast = 0, hasMeasure = false, writer = false,
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
      if (rest == "refused") rec.expectKind = "refused";
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
    else throw "unknown record key: " + s;
  }
  if (rec != null && ("operation" in rec) && rec.operation != "") recs.append(rec);
  return recs;
};

// --- the step machine (ported from serialize.go v1.15.1 conformance_test.go) --
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
  else if (w[0] == "float" && w.len() == 1) s = newStep("float");
  else if (w[0] == "double" && w.len() == 1) s = newStep("double");
  else if (w[0] == "uint128" && w.len() == 1) s = newStep("uint128");
  else if (w[0] == "int_relative" && w.len() == 2) {
    s = newStep("int_relative"); s.previous = signed32(number(1)[0]);
  }
  else if (w[0] == "compressed_float" && w.len() == 4) {
    s = newStep("compressed_float");
    s.fmin = w[1].tofloat(); s.fmax = w[2].tofloat(); s.fres = w[3].tofloat();
  }
  else if (w[0] == "bits" && w.len() == 2) { s = newStep("bits"); s.width = number(1)[0]; }
  else if (w[0] == "object" && w.len() == 2) { s = newStep("object"); s.width = number(1)[0]; }
  else if (w[0] == "bytes" && w.len() == 2) { s = newStep("bytes"); s.width = number(1)[0]; }
  else if (w[0] == "string" && w.len() == 2) { s = newStep("string"); s.width = number(1)[0]; }
  else if (w[0] == "wstring" && w.len() == 2) { s = newStep("wstring"); s.width = number(1)[0]; }
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
  if (name == "buffer_size") return operation == "string" || operation == "wstring";
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
    return rec.params[name].tofloat();
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
  else if (op == "wstring") { s = newStep("wstring"); s.width = number("buffer_size")[0]; }
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
local runStep = function(stream, s, sabotage) {
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
  if (kind == "align") {
    if (sabotage == "align-padding" && stream.isReading()) {
      local n = stream.alignBits();
      if (n > 0) {
        if (!stream._room(n)) return false;
        stream._take(n);
      }
      return true;
    }
    return stream.serializeAlign();
  }
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
  if (kind == "wstring") {
    local h = { value = s.text };
    local ok = stream.serializeWideString(h, s.width);
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
    if (!runStep(stream, steps[i], state.sabotage)) {
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
  if (s.kind == "wstring") return renderUnits(s.text);
  if (s.kind == "align") return "0";
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

local runReader = function(serialize, rec, steps, sabotage) {
  seedSentinels(steps);
  local stream = serialize.ReadStream(rec.bytes);
  local state = { failed = null, sabotage = sabotage };
  local stoppedAt = runSteps(stream, steps, 0, steps.len(), state);

  if (rec.expectKind == "refused") {
    check(stoppedAt < steps.len(), rec.name + ": the read succeeded, the corpus requires refusal");
    if (state.failed != null) checkDestination(rec, state.failed);
    // every later top-level step must refuse too, even where readable bits remain
    local i = stoppedAt + stepSpan(steps, stoppedAt);
    while (i < steps.len()) {
      local span = stepSpan(steps, i);
      local nextState = { failed = null, sabotage = sabotage };
      local stop = runSteps(stream, steps, i, i + span, nextState);
      check(stop < i + span, rec.name + ": step " + (i + 1) + " succeeded after step " + (stoppedAt + 1) + " was refused");
      i += span;
    }
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
  local state = { failed = null, sabotage = null };
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
  local state = { failed = null, sabotage = null };
  local stop = runSteps(stream, steps, 0, steps.len(), state);
  check(stop == steps.len(), rec.name + ": the measure refused a step, a measure refuses nothing at runtime");
  check(stream.bitsProcessed() >= rec.measureAtLeast,
    rec.name + ": measured " + stream.bitsProcessed() + " bits, the corpus requires at least " + rec.measureAtLeast);
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

local runRecords = function(serialize, recs, sabotage) {
  foreach (rec in recs) {
    local steps = prepare(rec);
    if (sabotage != null) {
      runReader(serialize, rec, steps, sabotage);
      continue;
    }
    runReader(serialize, rec, steps, null);
    if (rec.expectKind != "refused") {
      if (rec.writer) runWriter(serialize, rec, steps);
      if (rec.hasMeasure) runMeasure(serialize, rec, steps);
    }
  }
};

local runPath = function(serialize, path, label) {
  local recs = parseRecords(readText(path));
  runRecords(serialize, recs, null);
  print(label + ": " + recs.len() + " records\n");
  return recs.len();
};

// discover the corpus directory (never a fixed list): the pinned interpreter
// has no directory-listing builtin, so list through system() into a scratch
// file. A file added to conformance/ is picked up with no edit here.
local discoverCorpusFiles = function(root) {
  local scratch = root + "/build/conformance-listing.txt";
  local rc = system("ls -1 '" + root + "/conformance' > '" + scratch + "'");
  check(rc == 0, "could not list the corpus directory");
  local names = [];
  foreach (line in split(strip(readText(scratch)), "\n")) {
    local name = strip(line);
    if (name.len() < 4 || name.slice(name.len() - 4) != ".txt") continue;
    names.append(name);
  }
  names.sort();
  check(names.len() > 0, "empty corpus directory");
  return names;
};

function TestConformanceCorpus() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  local files = discoverCorpusFiles(root);
  local total = 0;
  foreach (f in files) total += runPath(serialize, root + "/conformance/" + f, f);
  print("corpus: " + files.len() + " files, " + total + " records\n");

  // Control 1 (STANDARD.md, "A gate nobody has seen go red..."): a corpus file
  // whose operation has no runner is REJECTED, never skipped.
  local scratch = root + "/build/conformance-control-unknown.txt";
  local f = file(scratch, "wb");
  local body = "operation not_a_real_operation\nname control\nbytes 00\nexpect value = 0\nconsumed 1\n";
  foreach (c in body) f.writen(c, 'b');
  f.close();
  local rejected = false;
  try { runPath(serialize, scratch, "control"); } catch (e) { rejected = true; }
  system("rm -f '" + scratch + "'");
  check(rejected, "an unknown operation was not rejected");

  // Control 2: a reader with the align-padding refusal switched off through the
  // test-only hook, run over the real corpus. It must go red on exactly the
  // vectors that pin that rule (the `align` records that expect a refusal) and
  // on no others.
  local expected = 0, seen = 0, wrong = 0;
  foreach (name in files) {
    local recs = parseRecords(readText(root + "/conformance/" + name));
    foreach (rec in recs) {
      local steps = prepare(rec);
      local failed = false;
      try { runReader(serialize, rec, steps, "align-padding"); } catch (e) { failed = true; }
      local hasAlign = false;
      foreach (s in steps) if (s.kind == "align") hasAlign = true;
      local shouldFail = rec.expectKind == "refused" && hasAlign;
      if (shouldFail) expected++;
      if (failed) seen++;
      if (failed != shouldFail) {
        wrong++;
        if (wrong <= 5) print("sabotage control: " + name + "/" + rec.name + " " + (failed ? "went red" : "stayed green") + "\n");
      }
    }
  }
  check(expected > 0, "the align-padding sabotage found no vector to break");
  check(wrong == 0, "the align-padding sabotage did not go red on exactly the vectors that pin the rule");
  print("sabotage control: " + seen + " records red, all " + expected + " align-padding refusals\n");
}
