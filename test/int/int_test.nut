// TestSerializeInt: the int family card of serialize-squirrel-int (DESIGN.md
// (i), the runner; the card's TEST line). It runs every record of
// conformance/int.txt, int64.txt and int128.txt as the runner must (value, bits
// consumed, canonical bytes, refusal with destination untouched and the stream
// terminal), prints the record count per file and fails unless it equals the
// file's count; plus serialize.go's TestBitsRequired, TestBitsRequired64 and
// TestSerializeInt64FullRange edge cases, and the writer's ValueOutOfRange
// latch for a value one past each bound. A test throws to fail.

local check = function(cond, what) {
  if (!cond) throw "TestSerializeInt: " + what;
};

local MIN64 = 0x8000000000000000;

// --- 128-bit number parsing and comparison helpers (for the vectors' values,
// which reach 128 bits; never a reimplementation of the codec) --------------
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

local hexDig = function(c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw "TestSerializeInt: bad hex digit " + c;
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
  local v = (t.len() >= 2 && t.slice(0, 2) == "0x") ? hexTo128(t.slice(2)) : parseDec(t);
  if (neg) v = neg128(v);
  return v;
};

local to64 = function(x) { return x[0]; };

local cmpVal = function(got, expected, is128) {
  if (is128) return got[0] == expected[0] && got[1] == expected[1];
  return got == expected;
};

// bitlen64(x): the number of bits needed to represent the unsigned 64-bit
// value x (0 for zero, 64 when the top bit is set). Used for the known-answer
// width checks below (serialize.go TestBitsRequired / TestBitsRequired64).
local bitlen64 = function(x) {
  if (x == 0) return 0;
  if (x < 0) return 64;
  local n = 1;
  local v = x;
  if (v >= 0x100000000) { n += 32; v = v >>> 32; }
  if (v >= 0x10000) { n += 16; v = v >>> 16; }
  if (v >= 0x100) { n += 8; v = v >>> 8; }
  if (v >= 0x10) { n += 4; v = v >>> 4; }
  if (v >= 0x4) { n += 2; v = v >>> 2; }
  if (v >= 0x2) { n += 1; }
  return n;
};

local br32 = function(min, max) {
  if (min == max) return 0;
  return bitlen64((max - min) & 0xFFFFFFFF);
};

local br64 = function(min, max) {
  if (min == max) return 0;
  return bitlen64(max - min);
};

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

// --- the runner --------------------------------------------------------------
local runRead = function(serialize, op, rec, is128) {
  local rs = serialize.ReadStream(blobOf(rec["bytes"]));
  local sentinel = is128 ? [0x1111222233334444, 0x5555666677778888] : 123456789;
  local h = { value = sentinel };
  local ok;
  if (op == "int") ok = rs.serializeInt(h, to64(rec.param_min), to64(rec.param_max));
  else if (op == "int64") ok = rs.serializeInt64(h, to64(rec.param_min), to64(rec.param_max));
  else ok = rs.serializeInt128(h, rec.param_min, rec.param_max);

  if (rec.expect[0] == "refused") {
    check(ok == false, rec.name + ": refused read returned true");
    check(rs.error() != null, rec.name + ": no error latched");
    check(cmpVal(h.value, sentinel, is128), rec.name + ": a refusal changed the destination");
    local before = rs.bitsProcessed();
    local h2 = { value = sentinel };
    local ok2;
    if (op == "int") ok2 = rs.serializeInt(h2, to64(rec.param_min), to64(rec.param_max));
    else if (op == "int64") ok2 = rs.serializeInt64(h2, to64(rec.param_min), to64(rec.param_max));
    else ok2 = rs.serializeInt128(h2, rec.param_min, rec.param_max);
    check(ok2 == false, rec.name + ": the stream is not terminal");
    check(rs.bitsProcessed() == before, rec.name + ": a terminal read consumed bits");
    check(cmpVal(h2.value, sentinel, is128), rec.name + ": a terminal read changed its destination");
  } else {
    check(ok == true, rec.name + ": accepted read returned false (" + rs.error() + ")");
    local expected = is128 ? rec.expect[1] : to64(rec.expect[1]);
    check(cmpVal(h.value, expected, is128), rec.name + ": decoded value mismatch");
    check(rs.bitsProcessed() == rec.consumed, rec.name + ": consumed " + rs.bitsProcessed() + ", want " + rec.consumed);
  }
};

local runWriter = function(serialize, op, rec, is128) {
  local ws = serialize.WriteStream(blob(64));
  local h = { value = is128 ? rec.expect[1] : to64(rec.expect[1]) };
  local ok;
  if (op == "int") ok = ws.serializeInt(h, to64(rec.param_min), to64(rec.param_max));
  else if (op == "int64") ok = ws.serializeInt64(h, to64(rec.param_min), to64(rec.param_max));
  else ok = ws.serializeInt128(h, rec.param_min, rec.param_max);
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
    local is128 = rec.operation == "int128";
    runRead(serialize, rec.operation, rec, is128);
    if ("writer" in rec && rec.writer == "canonical") runWriter(serialize, rec.operation, rec, is128);
  }
  print(name + ": " + recs.len() + " records\n");
};

function TestSerializeInt() {
  local serialize = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);

  // the conformance corpus (DESIGN.md (i)): every vector of the int family
  runFile(serialize, "int");
  runFile(serialize, "int64");
  runFile(serialize, "int128");

  // serialize.go TestBitsRequired (known answers, in the uint32 domain)
  local br = [
    [0, 0, 0], [0, 1, 1], [0, 2, 2], [0, 3, 2], [0, 4, 3], [0, 5, 3], [0, 6, 3],
    [0, 7, 3], [0, 8, 4], [0, 255, 8], [0, 65535, 16], [0, 4294967295, 32]
  ];
  foreach (c in br) {
    local got = br32(c[0], c[1]);
    check(got == c[2], "bitsRequired(" + c[0] + "," + c[1] + ") = " + got + ", want " + c[2]);
  }

  // serialize.go TestBitsRequired64 (known answers, in the uint64 domain)
  local br64cases = [
    [0, 0, 0], [0, 1, 1], [0, 255, 8], [0, 4294967295, 32], [0, 4294967296, 33],
    [0, 1099511627776, 41], [0, -1, 64],
    [0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 64],
    [-5000000000, 5000000000, 34]
  ];
  foreach (c in br64cases) {
    local got = br64(c[0], c[1]);
    check(got == c[2], "bitsRequired64(" + c[0] + "," + c[1] + ") = " + got + ", want " + c[2]);
  }

  // serialize.go TestSerializeInt64FullRange: ranges wider than 2^63, spans
  // over 32 bits, and a small range
  local fullMin = 0x8000000000000000;
  local fullMax = 0x7FFFFFFFFFFFFFFF;
  local fullVals = [fullMin, fullMin + 1, -1, 0, 1, fullMax - 1, fullMax];
  foreach (expected in fullVals) {
    local ws = serialize.WriteStream(blob(16));
    check(ws.serializeInt64({ value = expected }, fullMin, fullMax) == true, "write int64 full range " + expected);
    ws.flush();
    local rs = serialize.ReadStream(ws.data());
    local rh = { value = 0 };
    check(rs.serializeInt64(rh, fullMin, fullMax) == true, "read int64 full range " + expected);
    check(rh.value == expected, "int64 full range round trip " + expected + " got " + rh.value);
  }
  local minv = -5000000000;
  local maxv = 5000000000;
  local vals = [minv, minv + 1, -1, 0, 1, 4123456789, maxv - 1, maxv];
  foreach (expected in vals) {
    local ws = serialize.WriteStream(blob(16));
    check(ws.serializeInt64({ value = expected }, minv, maxv) == true, "write int64 span " + expected);
    ws.flush();
    local rs = serialize.ReadStream(ws.data());
    local rh = { value = 0 };
    check(rs.serializeInt64(rh, minv, maxv) == true, "read int64 span " + expected);
    check(rh.value == expected, "int64 span round trip " + expected + " got " + rh.value);
  }
  local ws = serialize.WriteStream(blob(8));
  check(ws.serializeInt64({ value = 55 }, -100, 100) == true, "write int64 narrow 55");
  ws.flush();
  check(ws.bitsProcessed() == 8, "int64 narrow bits " + ws.bitsProcessed() + ", want 8");
  local rs = serialize.ReadStream(ws.data());
  local rh = { value = 0 };
  check(rs.serializeInt64(rh, -100, 100) == true, "read int64 narrow 55");
  check(rh.value == 55, "int64 narrow round trip " + rh.value);

  // the writer's ValueOutOfRange latch for a value one past each bound
  // (DESIGN.md (g)): the refusal latches and sticks
  local wsA = serialize.WriteStream(blob(8));
  check(wsA.serializeInt({ value = 2147483648 }, -2147483648, 2147483647) == false, "int max+1 not refused");
  check(wsA.error() == serialize.SerializeError.ValueOutOfRange, "int max+1 latched " + wsA.error());
  check(wsA.serializeInt({ value = 0 }, -2147483648, 2147483647) == false, "int latch is not sticky");
  local wsB = serialize.WriteStream(blob(8));
  check(wsB.serializeInt({ value = -2147483649 }, -2147483648, 2147483647) == false, "int min-1 not refused");
  check(wsB.error() == serialize.SerializeError.ValueOutOfRange, "int min-1 latched " + wsB.error());
  local wsC = serialize.WriteStream(blob(8));
  check(wsC.serializeInt64({ value = 101 }, -100, 100) == false, "int64 max+1 not refused");
  check(wsC.error() == serialize.SerializeError.ValueOutOfRange, "int64 max+1 latched " + wsC.error());
  local wsD = serialize.WriteStream(blob(8));
  check(wsD.serializeInt64({ value = -101 }, -100, 100) == false, "int64 min-1 not refused");
  check(wsD.error() == serialize.SerializeError.ValueOutOfRange, "int64 min-1 latched " + wsD.error());
  local wsE = serialize.WriteStream(blob(16));
  check(wsE.serializeInt128({ value = [101, 0] }, [0, 0], [100, 0]) == false, "int128 max+1 not refused");
  check(wsE.error() == serialize.SerializeError.ValueOutOfRange, "int128 max+1 latched " + wsE.error());
  local wsF = serialize.WriteStream(blob(16));
  check(wsF.serializeInt128({ value = [-1, 0xFFFFFFFFFFFFFFFF] }, [0, 0], [100, 0]) == false, "int128 min-1 not refused");
  check(wsF.error() == serialize.SerializeError.ValueOutOfRange, "int128 min-1 latched " + wsF.error());
}
