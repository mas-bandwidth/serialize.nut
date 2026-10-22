// fuzz/driver.nut: the Squirrel side of TestDifferentialAgainstSerializeGo
// (serialize-squirrel-fuzz-differential, fuzz/differential_test.go).
//
//   sq fuzz/driver.nut <repo root> <batch file>
//
// The batch file holds one request per line; the driver answers each with one
// line on stdout, every value in lowercase hex, then `done <count>`. It is run
// once per batch of 100 programs (one interpreter process, the batch in the
// test's own scratch file; the interpreter is the pin of DESIGN.md (i)), and it raises nothing on data: sq
// exits 0 on an uncaught throw (DESIGN.md (i)), so the Go side fails a batch
// whose stderr is not empty or that lacks the completion line.
//
// THE REQUESTS.
//
//   w <id> <capacity> <program>   write the program into a blob of <capacity>
//                                 bytes (a multiple of 8, DESIGN.md (d))
//   r <id> x<hex> <program>       read the program's steps from those bytes
//
// THE ANSWERS.
//
//   <id> w ok x<hex>                          the flushed data()
//   <id> r ok <bits> <v0> ... <vn-1>          bitsProcessed() and every value
//   <id> <w|r> refused <i> <kind> <v0> ... <vi-1>
//                                             the refusing step, error(), and on
//                                             a read the values decoded before it
//
// <kind> is the stream's first refusal reason, spelled as STANDARD.md spells it
// (format 2.0, Refusal reasons). A refused read whose destination was written
// answers kind `touched:<kind>`,
// so the differential goes red on it (DESIGN.md (g): a refusal leaves the
// caller's destination untouched).
//
// THE PROGRAM TEXT: steps one after another, each `<kind> <params> <value>`;
// a number is 32 hex digits, the 128-bit two's complement (signed kinds sign
// extended, unsigned kinds zero extended; a float by its bit pattern); a byte
// string is `x` and its hex; widths, Q formats and buffer sizes are decimal.
//
//   bits <w> N  bits64 <w> N  bool 0|1  uint8 N  uint16 N  uint32 N  uint64 N
//   uint128 N  int MIN MAX N  int64 MIN MAX N  int128 MIN MAX N
//   fixed64 <ib> <fb> MIN MAX N  fixed128 <ib> <fb> MIN MAX N
//   int_relative PREV N  float N  double N  cfloat MIN MAX RES N
//   cfloatpre MIN MAX RES N  bytes xHEX  string <buffer> xHEX
//   align  end  object <span>
//
// `object <span>` serializes the next <span> steps inside serializeObject
// (STANDARD.md object). A value token is ignored on a read.

local root = vargv[0];
local path = vargv[1];
local serialize = dofile(root + "/src/serialize.nut", true);

// the float32 bit conversions, taken from the library's own
// serialize_float.nut exports (DESIGN.md (e): bit patterns, never conversions),
// exactly as test/conformance does: never a second narrowing
local srcRequire;
srcRequire = function(name, who = null) {
  local m = {};
  loadfile(root + "/src/" + name + ".nut", true).bindenv(::getroottable())(m, srcRequire);
  return m;
};
local floatMod = srcRequire("serialize_float");
local float32Bits = floatMod.float32Bits;
local float32FromBits = floatMod.float32FromBits;

local fh = file(path, "rb");
local B = fh.readblob(fh.len());
fh.close();
local N = B.len();
local cur = { p = 0 };

// --- the reader of the request text (bytes, never string concatenation of a
// payload: a payload is decoded straight into a blob) ------------------------
local hexDig = function(c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  throw "driver: bad hex digit " + c;
};

local skip = function() {
  while (cur.p < N && (B[cur.p] & 0xff) == ' ') cur.p++;
};

local atEol = function() {
  skip();
  return cur.p >= N || (B[cur.p] & 0xff) == '\n';
};

local word = function() {
  skip();
  local s = "";
  while (cur.p < N) {
    local c = B[cur.p] & 0xff;
    if (c == ' ' || c == '\n') break;
    s += c.tochar();
    cur.p++;
  }
  if (s.len() == 0) throw "driver: a token is missing at byte " + cur.p;
  return s;
};

local dec = function() { return word().tointeger(); };

// a 128-bit number, 32 hex digits, as [lo, hi] (DESIGN.md (c): 128 bits is two
// halves, each composed with shifts only)
local num = function() {
  skip();
  local hi = 0, lo = 0;
  for (local i = 0; i < 32; i++) {
    local d = hexDig(B[cur.p + i] & 0xff);
    if (i < 16) hi = (hi << 4) | d;
    else lo = (lo << 4) | d;
  }
  cur.p += 32;
  return [lo, hi];
};

local xblob = function() {
  skip();
  if ((B[cur.p] & 0xff) != 'x') throw "driver: a byte string starts with x";
  cur.p++;
  local start = cur.p;
  while (cur.p < N) {
    local c = B[cur.p] & 0xff;
    if (c == ' ' || c == '\n') break;
    cur.p++;
  }
  local n = (cur.p - start) / 2;
  local b = blob(n);
  for (local i = 0; i < n; i++) {
    b[i] = (hexDig(B[start + 2 * i] & 0xff) << 4) | hexDig(B[start + 2 * i + 1] & 0xff);
  }
  return b;
};

local blobToString = function(b) {
  local s = "";
  for (local i = 0; i < b.len(); i++) s += (b[i] & 0xff).tochar();
  return s;
};

local signed32 = function(x) {
  local v = x & 0xffffffff;
  if (v & 0x80000000) v = v - 0x100000000;
  return v;
};

// --- rendering (lowercase hex) ----------------------------------------------
local DIGITS = "0123456789abcdef";
local lane = function(x) {
  local out = "";
  for (local i = 15; i >= 0; i--) out += DIGITS[(x >>> (i * 4)) & 15].tochar();
  return out;
};
local n128 = function(p) { return lane(p[1]) + lane(p[0]); };
local signedN = function(v) { return n128([v, v < 0 ? -1 : 0]); };
local unsignedN = function(v) { return n128([v, 0]); };
local xOfBlob = function(b) {
  local out = "x";
  for (local i = 0; i < b.len(); i++) {
    local c = b[i] & 0xff;
    out += DIGITS[c >> 4].tochar();
    out += DIGITS[c & 15].tochar();
  }
  return out;
};
local xOfString = function(s) {
  local out = "x";
  foreach (ch in s) {
    local c = ch & 0xff;
    out += DIGITS[c >> 4].tochar();
    out += DIGITS[c & 15].tochar();
  }
  return out;
};
// a long payload is printed in pieces, so no answer line is built by
// quadratic concatenation
local printBlob = function(b) {
  print("x");
  local piece = "";
  for (local i = 0; i < b.len(); i++) {
    local c = b[i] & 0xff;
    piece += DIGITS[c >> 4].tochar();
    piece += DIGITS[c & 15].tochar();
    if (piece.len() >= 128) { print(piece); piece = ""; }
  }
  print(piece);
};

// --- the program -------------------------------------------------------------
local parseSteps = function() {
  local steps = [];
  while (!atEol()) {
    local s = { kind = word(), width = 0, ib = 0, fb = 0, min = [0, 0], max = [0, 0],
      prev = 0, fmin = 0.0, fmax = 0.0, fres = 0.0, v = [0, 0], b = false, data = null };
    local k = s.kind;
    if (k == "bits" || k == "bits64") { s.width = dec(); s.v = num(); }
    else if (k == "bool") s.b = dec() == 1;
    else if (k == "uint8" || k == "uint16" || k == "uint32" || k == "uint64" ||
      k == "uint128" || k == "float" || k == "double") s.v = num();
    else if (k == "int" || k == "int64" || k == "int128") { s.min = num(); s.max = num(); s.v = num(); }
    else if (k == "fixed64" || k == "fixed128") {
      s.ib = dec(); s.fb = dec(); s.min = num(); s.max = num(); s.v = num();
    }
    else if (k == "int_relative") { s.prev = signed32(num()[0]); s.v = num(); }
    else if (k == "cfloat" || k == "cfloatpre") {
      s.fmin = float32FromBits(num()[0]); s.fmax = float32FromBits(num()[0]);
      s.fres = float32FromBits(num()[0]); s.v = num();
    }
    else if (k == "bytes") s.data = xblob();
    else if (k == "string") { s.width = dec(); s.data = xblob(); }
    else if (k == "align" || k == "end") {}
    else if (k == "object") s.width = dec();
    else throw "driver: no step kind " + k;
    steps.append(s);
  }
  return steps;
};

// --- one step on any stream: the holder carries the program's value on a
// write; on a read it starts at a sentinel that a refusal must leave in place
local SENTINEL = 0x5a5a5a5a;
local SENTINEL_F = 1234.5;
local SENTINEL_S = "sentinel";

local runOne = function(stream, s, i, st) {
  local k = s.kind;
  local w = stream.isWriting();
  local h, ok, out;
  local untouched;
  if (k == "bits" || k == "bits64" || k == "uint8" || k == "uint16" || k == "uint32" || k == "uint64") {
    h = { value = w ? s.v[0] : SENTINEL };
    if (k == "bits") ok = stream.serializeBits(h, s.width);
    else if (k == "bits64") ok = stream.serializeBits64(h, s.width);
    else if (k == "uint8") ok = stream.serializeUint8(h);
    else if (k == "uint16") ok = stream.serializeUint16(h);
    else if (k == "uint32") ok = stream.serializeUint32(h);
    else ok = stream.serializeUint64(h);
    if (ok) out = unsignedN(h.value);
    untouched = function() { return h.value == SENTINEL; };
  } else if (k == "bool") {
    h = { value = w ? s.b : null };
    ok = stream.serializeBool(h);
    if (ok) out = h.value ? "1" : "0";
    untouched = function() { return h.value == null; };
  } else if (k == "uint128" || k == "int128" || k == "fixed128") {
    h = { value = w ? [s.v[0], s.v[1]] : [SENTINEL, SENTINEL] };
    if (k == "uint128") ok = stream.serializeUint128(h);
    else if (k == "int128") ok = stream.serializeInt128(h, s.min, s.max);
    else ok = stream.serializeFixed128(h, s.ib, s.fb, s.min[0], s.max[0]);
    if (ok) out = n128(h.value);
    untouched = function() { return h.value[0] == SENTINEL && h.value[1] == SENTINEL; };
  } else if (k == "int" || k == "int64" || k == "fixed64" || k == "int_relative") {
    if (k == "int") {
      h = { value = w ? signed32(s.v[0]) : SENTINEL };
      ok = stream.serializeInt(h, signed32(s.min[0]), signed32(s.max[0]));
    } else if (k == "int64") {
      h = { value = w ? s.v[0] : SENTINEL };
      ok = stream.serializeInt64(h, s.min[0], s.max[0]);
    } else if (k == "fixed64") {
      h = { value = w ? s.v[0] : SENTINEL };
      ok = stream.serializeFixed64(h, s.ib, s.fb, s.min[0], s.max[0]);
    } else {
      h = { value = w ? signed32(s.v[0]) : SENTINEL };
      ok = stream.serializeIntRelative(s.prev, h);
    }
    if (ok) out = signedN(h.value);
    untouched = function() { return h.value == SENTINEL; };
  } else if (k == "float" || k == "cfloat" || k == "cfloatpre") {
    h = { value = w ? float32FromBits(s.v[0]) : SENTINEL_F };
    if (k == "float") ok = stream.serializeFloat(h);
    else if (k == "cfloat") ok = stream.serializeCompressedFloat(h, s.fmin, s.fmax, s.fres);
    else {
      local c = serialize.compressedFloatParams(s.fmin, s.fmax, s.fres);
      ok = stream.serializeCompressedFloatPrecomputed(h, c.maxIntegerValue, c.bits, c.delta, s.fmin);
    }
    if (ok) out = unsignedN(float32Bits(h.value));
    untouched = function() { return h.value == SENTINEL_F; };
  } else if (k == "double") {
    h = { value = w ? casti2f(s.v[0]) : SENTINEL_F };
    ok = stream.serializeDouble(h);
    if (ok) out = unsignedN(castf2i(h.value));
    untouched = function() { return h.value == SENTINEL_F; };
  } else if (k == "bytes") {
    local data = s.data;
    if (!w) {
      data = blob(s.data.len());
      for (local j = 0; j < data.len(); j++) data[j] = 0xa5;
    }
    ok = stream.serializeBytes(data);
    if (ok) out = xOfBlob(data);
    untouched = function() {
      for (local j = 0; j < data.len(); j++) if ((data[j] & 0xff) != 0xa5) return false;
      return true;
    };
  } else if (k == "string") {
    h = { value = w ? blobToString(s.data) : SENTINEL_S };
    ok = stream.serializeString(h, s.width);
    if (ok) out = xOfString(h.value);
    untouched = function() { return h.value == SENTINEL_S; };
  } else if (k == "align") {
    ok = stream.serializeAlign();
    out = "-";
    untouched = function() { return true; };
  } else if (k == "end") {
    ok = stream.serializeEnd();
    out = "-";
    untouched = function() { return true; };
  } else throw "driver: no runner for " + k;
  if (ok) st.vals[i] = out;
  else if (!w && !untouched()) st.touched = true;
  return ok;
};

local runSteps;
local makeNested = function(steps, from, to, st) {
  local o = {};
  o.serialize <- function(stream) { return runSteps(stream, steps, from, to, st) == to; };
  return o;
};

// the steps [from, to) in order on one stream; returns the index of the first
// refusing step (st.failed), or `to` (STANDARD.md object: a nested object's
// steps run inline, no bytes of its own)
runSteps = function(stream, steps, from, to, st) {
  local i = from;
  while (i < to) {
    local s = steps[i];
    if (s.kind == "object") {
      st.vals[i] = "-";
      if (!stream.serializeObject(makeNested(steps, i + 1, i + 1 + s.width, st))) {
        if (st.failed == null) st.failed = i;
        return i;
      }
      i += 1 + s.width;
      continue;
    }
    if (!runOne(stream, s, i, st)) {
      if (st.failed == null) st.failed = i;
      return i;
    }
    i++;
  }
  return to;
};

local kindOf = function(stream, st) {
  local e = stream.error();
  local k = e == null ? "none" : e;
  return st.touched ? "touched:" + k : k;
};

// --- the requests ------------------------------------------------------------
local count = 0;
while (cur.p < N) {
  if ((B[cur.p] & 0xff) == '\n') { cur.p++; continue; }
  local op = word();
  local id = word();
  if (op == "w") {
    local capacity = dec();
    local steps = parseSteps();
    local st = { vals = array(steps.len(), "-"), failed = null, touched = false };
    local ws = serialize.WriteStream(blob(capacity));
    local stop = runSteps(ws, steps, 0, steps.len(), st);
    if (stop == steps.len()) {
      ws.flush();
      print(id + " w ok ");
      printBlob(ws.data());
      print("\n");
    } else {
      print(id + " w refused " + st.failed + " " + kindOf(ws, st) + "\n");
    }
  } else if (op == "r") {
    local data = xblob();
    local steps = parseSteps();
    local st = { vals = array(steps.len(), "-"), failed = null, touched = false };
    local rs = serialize.ReadStream(data);
    local stop = runSteps(rs, steps, 0, steps.len(), st);
    local n = steps.len();
    if (stop == steps.len()) {
      print(id + " r ok " + rs.bitsProcessed());
    } else {
      n = st.failed;
      print(id + " r refused " + st.failed + " " + kindOf(rs, st));
    }
    for (local j = 0; j < n; j++) print(" " + st.vals[j]);
    print("\n");
  } else throw "driver: no request " + op;
  count++;
}
print("done " + count + "\n");
