// TestSerializeFixed: the fixed point family card of serialize-squirrel-fixed
// (DESIGN.md (h), the card's TEST line). It runs every record of
// conformance/fixed.txt as the runner must (value, bits consumed, canonical
// bytes, refusal with destination untouched and the stream terminal), prints
// the record count and fails unless it equals the file's count; plus every
// misuse rule raising serialize.go's panic text, and the byte identity of the
// fixed wire with serializeInt64 over the raw bounds for three Q formats
// (STANDARD.md, fixed (Q format, ranged)). A test throws to fail.

local check = function(cond, what) {
  if (!cond) throw "TestSerializeFixed: " + what;
};

// raises(fn, prefix, what): fn() throws a string starting with prefix. fn is
// called directly, never through .call or acall: sq prints a throw that crosses
// a native call to stderr even when it is caught (DESIGN.md (i)).
local raises = function(fn, prefix, what) {
  local got = null;
  try { fn(); } catch (e) { got = e; }
  check(got != null, what + ": did not raise");
  check(typeof got == "string" && got.len() >= prefix.len() && got.slice(0, prefix.len()) == prefix,
    what + ": raised " + got + ", want " + prefix);
};

local MIN64 = 0x8000000000000000;
local PANIC_PARAMS = "serialize: fixed point requires integer bits >= 1, fraction bits >= 0, a Q format that fits the storage width, and min <= max";
local PANIC_BOUNDS = "serialize: fixed point bounds in whole units do not fit the Q format";

// --- 128-bit number parsing and comparison (the vectors' raw values reach
// 128 bits; never a reimplementation of the codec) ---------------------------
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

// the test's own 64-bit lanes (DESIGN.md (c)): a sum, a difference or a left
// shift that can wrap is composed from 32-bit halves, so the oracle never
// overflows a SQInteger either (make test-ubsan runs it)
local add64 = function(a, b) {
  local lo = (a & 0xFFFFFFFF) + (b & 0xFFFFFFFF);
  local hi = ((a >>> 32) + (b >>> 32) + (lo >>> 32)) & 0xFFFFFFFF;
  return (hi << 32) | (lo & 0xFFFFFFFF);
};
local sub64 = function(a, b) {
  local lo = (a & 0xFFFFFFFF) - (b & 0xFFFFFFFF);
  local hi = ((a >>> 32) - (b >>> 32) - (lo < 0 ? 1 : 0)) & 0xFFFFFFFF;
  return (hi << 32) | (lo & 0xFFFFFFFF);
};
local shl64 = function(x, n) {
  if (n == 0) return x;
  return (x & (0xFFFFFFFFFFFFFFFF >>> n)) << n;
};

local usub = function(a, b) {
  local lo = sub64(a[0], b[0]);
  local br = ucmp([a[0], 0], [b[0], 0]) < 0 ? 1 : 0;
  local hi = sub64(sub64(a[1], b[1]), br);
  return [lo, hi];
};

local uadd = function(a, b) {
  local lo = add64(a[0], b[0]);
  local ca = ucmp([a[0], 0], [lo, 0]) > 0 ? 1 : 0;
  local hi = add64(add64(a[1], b[1]), ca);
  return [lo, hi];
};

local lsh = function(x, n) {
  if (n == 0) return x;
  if (n < 64) return [shl64(x[0], n), (shl64(x[1], n) | (x[0] >>> (64 - n)))];
  return [0, shl64(x[0], n - 64)];
};

local mul10 = function(x) { return uadd(lsh(x, 3), lsh(x, 1)); };
local neg128 = function(x) { return usub([0, 0], x); };

local hexDig = function(c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw "TestSerializeFixed: bad hex digit " + c;
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
  foreach (c in s) num = uadd(mul10(num), [c - '0', 0]);
  return num;
};

local parseNumber = function(tok) {
  local t = tok;
  local neg = false;
  if (t.len() > 0 && t.slice(0, 1) == "-") { neg = true; t = t.slice(1); }
  local v = (t.len() >= 2 && t.slice(0, 2) == "0x") ? hexTo128(t.slice(2)) : parseDec(t);
  if (neg) v = neg128(v);
  return v;
};

local to64 = function(x) { return x[0]; };

// --- text and bytes helpers -------------------------------------------------
local strip = function(s) {
  local a = 0, b = s.len();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
  return s.slice(a, b);
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  foreach (c in b) s += c.tochar();
  return s;
};

local blobOf = function(hexs) {
  local words = [];
  foreach (w in split(hexs, " ")) if (w.len() > 0) words.append(w);
  local b = blob(words.len());
  for (local i = 0; i < words.len(); i++) b[i] = (hexDig(words[i][0]) << 4) | hexDig(words[i][1]);
  return b;
};

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

// --- the conformance vector parser ------------------------------------------
local parseRecords = function(text) {
  local recs = [];
  local rec = null;
  foreach (line in split(text, "\n")) {
    line = strip(line);
    if (line.len() == 0) {
      if (rec != null && ("operation" in rec)) recs.append(rec);
      rec = null;
      continue;
    }
    if (line[0] == '#') continue;
    if (rec == null) rec = {};
    local words = split(line, " ");
    if (words[0] == "operation") rec["operation"] <- words[1];
    else if (words[0] == "name") rec["name"] <- words[1];
    else if (words[0] == "param") rec["param_" + words[1]] <- parseNumber(words[3]);
    else if (words[0] == "bytes") {
      local hexs = "";
      for (local i = 1; i < words.len(); i++) { if (i > 1) hexs += " "; hexs += words[i]; }
      rec["bytes"] <- hexs;
    }
    else if (words[0] == "expect") {
      rec["expect"] <- (words[1] == "value") ? ["value", parseNumber(words[3])] : ["refused"];
    }
    else if (words[0] == "consumed") rec["consumed"] <- words[1].tointeger();
    else if (words[0] == "writer") rec["writer"] <- words[1];
  }
  if (rec != null && ("operation" in rec)) recs.append(rec);
  return recs;
};

local countOps = function(text) {
  local n = 0;
  foreach (line in split(text, "\n")) {
    local s = strip(line);
    if (s.len() >= 9 && s.slice(0, 9) == "operation") n++;
  }
  return n;
};

// the storage width decides the arm: exactly 128 bits is the wide form
// (DESIGN.md (a): Go's two names; STANDARD.md, fixed)
local wide = function(rec) {
  return to64(rec.param_integer_bits) + to64(rec.param_fraction_bits) == 128;
};

// --- the runner --------------------------------------------------------------
local runRead = function(serialize, rec) {
  local is128 = wide(rec);
  local rs = serialize.ReadStream(blobOf(rec["bytes"]));
  local sentinel = is128 ? [0x1111222233334444, 0x5555666677778888] : 123456789;
  local h = { value = sentinel };
  local ib = to64(rec.param_integer_bits);
  local fb = to64(rec.param_fraction_bits);
  local mn = to64(rec.param_min);
  local mx = to64(rec.param_max);
  local ok = is128 ? rs.serializeFixed128(h, ib, fb, mn, mx)
                   : rs.serializeFixed64(h, ib, fb, mn, mx);

  if (rec.expect[0] == "refused") {
    check(ok == false, rec.name + ": refused read returned true");
    check(rs.error() != null, rec.name + ": no error latched");
    check(is128 ? (h.value[0] == sentinel[0] && h.value[1] == sentinel[1]) : h.value == sentinel,
      rec.name + ": a refusal changed the destination");
    local before = rs.bitsProcessed();
    local h2 = { value = sentinel };
    local ok2 = is128 ? rs.serializeFixed128(h2, ib, fb, mn, mx)
                      : rs.serializeFixed64(h2, ib, fb, mn, mx);
    check(ok2 == false, rec.name + ": the stream is not terminal");
    check(rs.bitsProcessed() == before, rec.name + ": a terminal read consumed bits");
    check(is128 ? (h2.value[0] == sentinel[0] && h2.value[1] == sentinel[1]) : h2.value == sentinel,
      rec.name + ": a terminal read changed its destination");
  } else {
    check(ok == true, rec.name + ": accepted read returned false (" + rs.error() + ")");
    check(is128 ? (h.value[0] == rec.expect[1][0] && h.value[1] == rec.expect[1][1])
                : h.value == to64(rec.expect[1]),
      rec.name + ": decoded value mismatch");
    check(rs.bitsProcessed() == rec.consumed, rec.name + ": consumed " + rs.bitsProcessed() + ", want " + rec.consumed);
  }
};

local runWriter = function(serialize, rec) {
  local is128 = wide(rec);
  local ws = serialize.WriteStream(blob(64));
  local h = { value = is128 ? rec.expect[1] : to64(rec.expect[1]) };
  local ib = to64(rec.param_integer_bits);
  local fb = to64(rec.param_fraction_bits);
  local mn = to64(rec.param_min);
  local mx = to64(rec.param_max);
  local ok = is128 ? ws.serializeFixed128(h, ib, fb, mn, mx)
                   : ws.serializeFixed64(h, ib, fb, mn, mx);
  check(ok == true, rec.name + ": writer refused its canonical value");
  ws.flush();
  local gothex = blobToHex(ws.data());
  check(gothex == rec["bytes"], rec.name + ": writer bytes " + gothex + ", want " + rec["bytes"]);
};

local runFile = function(serialize, name) {
  local text = readText(::SERIALIZE_ROOT + "/conformance/" + name + ".txt");
  local recs = parseRecords(text);
  check(recs.len() == countOps(text), name + ": parsed " + recs.len() + " records, " + countOps(text) + " operations");
  foreach (rec in recs) {
    runRead(serialize, rec);
    if ("writer" in rec && rec.writer == "canonical") runWriter(serialize, rec);
  }
  print(name + ": " + recs.len() + " records\n");
};

// the raw (scaled) bounds of a Q format, independently of the codec
local rawMin64 = function(cfg) { return shl64(cfg.min, cfg.fractionBits); };
local rawMax64 = function(cfg) { return shl64(cfg.max, cfg.fractionBits); };

function TestSerializeFixed() {
  local serialize = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);

  // the conformance corpus (DESIGN.md (i), STANDARD.md "The vector format"):
  // every record of fixed.txt, the count checked against the file's own
  runFile(serialize, "fixed");

  // every misuse rule raises serialize.go's panic text, in every stream state
  // (DESIGN.md (g); serialize.go panicFixedParams and panicFixedBounds)
  local w = serialize.WriteStream(blob(64));
  local r = serialize.ReadStream(blob(64));
  local m = serialize.MeasureStream();
  foreach (s in [w, r, m]) {
    raises(function() { s.serializeFixed64({ value = 0 }, 0, 0, 0, 0); }, PANIC_PARAMS, "integer bits 0");
    raises(function() { s.serializeFixed64({ value = 0 }, 8, -1, 0, 0); }, PANIC_PARAMS, "fraction bits -1");
    raises(function() { s.serializeFixed64({ value = 0 }, 64, 1, 0, 0); }, PANIC_PARAMS, "Q format past 64 bits");
    raises(function() { s.serializeFixed64({ value = 0 }, 8, 8, 100, -100); }, PANIC_PARAMS, "min > max");
    raises(function() { s.serializeFixed64({ value = 0 }, 8, 0, -129, 0); }, PANIC_BOUNDS, "signed min below capacity");
    raises(function() { s.serializeFixed64({ value = 0 }, 8, 0, 0, 256); }, PANIC_BOUNDS, "unsigned max above capacity");

    raises(function() { s.serializeFixed128({ value = [0, 0] }, 64, 63, 0, 0); }, PANIC_PARAMS, "wide Q format not 128 bits");
    raises(function() { s.serializeFixed128({ value = [0, 0] }, 0, 128, 0, 0); }, PANIC_PARAMS, "wide integer bits 0");
    raises(function() { s.serializeFixed128({ value = [0, 0] }, 64, 64, 1, -1); }, PANIC_PARAMS, "wide min > max");
    raises(function() { s.serializeFixed128({ value = [0, 0] }, 32, 96, -2147483649, 0); }, PANIC_BOUNDS, "wide min below capacity");
  }

  // the wire is serializeInt64 of the raw value over the raw bounds: fixed
  // point adds no wire structure, only the compile-time scaling convention
  // (STANDARD.md, fixed; serialize.go TestSerializeFixedMatchesInt64)
  local cases = [
    { integerBits = 64, fractionBits = 0, min = -5000000000, max = 5000000000,
      values = [-5000000000, -4999999999, -1, 0, 1, 12345678, 4999999999, 5000000000] },
    { integerBits = 32, fractionBits = 0, min = -100000, max = 100000,
      values = [-100000, -99999, -1, 0, 1, 54321, 99999, 100000] },
    { integerBits = 16, fractionBits = 16, min = -30000, max = 30000,
      values = [-1966080000, -180224, 0, 32768, 809041921, 1966080000] },
  ];
  foreach (cfg in cases) {
    local rmin = rawMin64(cfg);
    local rmax = rawMax64(cfg);
    foreach (value in cfg.values) {
      local fs = serialize.WriteStream(blob(16));
      check(fs.serializeFixed64({ value = value }, cfg.integerBits, cfg.fractionBits, cfg.min, cfg.max) == true,
        "fixed write " + value);
      fs.flush();
      local is = serialize.WriteStream(blob(16));
      check(is.serializeInt64({ value = value }, rmin, rmax) == true, "int64 write " + value);
      is.flush();
      check(fs.bitsProcessed() == is.bitsProcessed(), "fixed/int64 bit count " + value);
      check(blobToHex(fs.data()) == blobToHex(is.data()), "fixed/int64 bytes " + value);
    }
  }
}
