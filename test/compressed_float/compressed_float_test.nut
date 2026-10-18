// TestSerializeCompressedFloat: the compressed float card of serialize-squirrel
// (DESIGN.md (h), file layout: src/serialize_compressed_float.nut). It pins:
//
//   (1) every record of conformance/compressed_float.txt, read as a runner
//       must: the decoded value bit-exactly for an accepted record
//       (STANDARD.md compressed_float, "The reader's arithmetic is pinned the
//       same way"; every expectation is `expect bits`), the bits consumed, and
//       for a refused record the holder untouched and the stream terminal. The
//       record count is printed and must equal the file's count.
//   (2) serialize.go's TestCompressedFloatTopOfRangeClamp witnesses ([0,
//       8388609] and [0, 16777215] at resolution 1, writing max, through both
//       the derive and the precomputed entry points; STANDARD.md compressed_float,
//       "The integer clamp is normative").
//   (3) serialize.go's TestCompressedFloatValidation misuse rules: min >= max
//       or resolution <= 0 raises; precomputed constants that are not what
//       CompressedFloatParams derives raise; a non-finite value raises on
//       write and measure (DESIGN.md (e)); and the reader refuses an integer
//       above max_integer_value, which the refused vectors pin.
//
// A test passes by returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestSerializeCompressedFloat: " + what;
};

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

// hexBytes(s): a blob of the space-separated hexadecimal byte pairs of s.
local hexBytes = function(s) {
  local parts = split(s, " ");
  local b = blob(parts.len());
  for (local i = 0; i < parts.len(); i++) {
    if (parts[i] == "") continue;
    b[i] = (parts[i].tointeger(16));
  }
  return b;
};

// f32ToDouble(bits): the double holding the float32 pattern `bits`
// (the inverse of fround's widening; STANDARD.md float). All expected values
// in the corpus are finite.
local f32ToDouble = function(bits) {
  local sign = (bits >> 31) & 1;
  local e = (bits >> 23) & 0xFF;
  local m = bits & 0x7FFFFF;
  local mag;
  if (e == 0) mag = m * 1.401298464324817e-45;
  else {
    local mant = 1.0 + m / 8388608.0;
    mag = mant * pow(2.0, e - 127);
  }
  return sign == 1 ? -mag : mag;
};

// strip(s): leading and trailing ASCII whitespace removed (Squirrel strings
// have no trim built-in).
local strip = function(s) {
  local a = 0;
  local b = s.len();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
  return s.slice(a, b);
};

// parseRecords(text): the records of a conformance file, comment and blank
// lines dropped; each record is a table of key -> value.
local parseRecords = function(text) {
  local records = [];
  local cur = null;
  foreach (line in split(text, "\n")) {
    if (line.len() == 0) { if (cur != null) { records.append(cur); cur = null; } continue; }
    if (line.slice(0, 1) == "#") continue;
    if (cur == null) cur = {};
    if (line.len() >= 9 && line.slice(0, 9) == "operation ") {
      cur.operation <- line.slice(9);
      continue;
    }
    if (line.len() >= 6 && line.slice(0, 6) == "param ") {
      local rest = line.slice(6);
      local e = rest.find("=");
      local pn = strip(rest.slice(0, e));
      local pv = strip(rest.slice(e + 1));
      cur[pn] <- pv;
      continue;
    }
    local sp = line.find(" ");
    if (sp == null) { cur[line] <- ""; continue; }
    local key = line.slice(0, sp);
    local val = strip(line.slice(sp + 1));
    cur[key] <- val;
  }
  if (cur != null) records.append(cur);
  return records;
};

function TestSerializeCompressedFloat() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  // (1) the corpus
  local corpusText = readText(root + "/conformance/compressed_float.txt");
  local records = parseRecords(corpusText);
  local expectedCount = 29;
  print("record count " + records.len() + "\n");
  check(records.len() == expectedCount,
    "the corpus has " + records.len() + " records, want " + expectedCount);

  local runRecord = function(rec) {
    local min = rec.min.tofloat();
    local max = rec.max.tofloat();
    local res = rec.res.tofloat();
    local data = hexBytes(rec.bytes);
    local rs = serialize.ReadStream(data);
    local holder = { value = 0.5 };

    if ("expect" in rec) {
      if (rec.expect == "refused") {
        local ok = rs.serializeCompressedFloat(holder, min, max, res);
        check(ok == false, rec.name + ": a refused read succeeded");
        check(rs.error() != serialize.SerializeError.None, rec.name + ": no error latched");
        check(holder.value == 0.5, rec.name + ": a refused read changed its holder");
        // terminal: a further read also fails and consumes nothing
        local bitsBefore = rs.bitsProcessed();
        local h2 = { value = 0.25 };
        check(rs.serializeCompressedFloat(h2, min, max, res) == false,
          rec.name + ": the stream was not terminal after a refusal");
        check(h2.value == 0.25, rec.name + ": a read after the refusal changed its holder");
        check(rs.bitsProcessed() == bitsBefore, rec.name + ": a read after the refusal consumed bits");
        return;
      }
      // expect bits = 0x...
      local want = rec.expect.slice(rec.expect.find("0x") + 2);
      local wantBits = want.tointeger(16);
      local wantValue = f32ToDouble(wantBits);
      local ok = rs.serializeCompressedFloat(holder, min, max, res);
      check(ok == true, rec.name + ": an accepted read failed with " + rs.error());
      check(holder.value == wantValue,
        rec.name + ": decoded " + holder.value + ", want " + wantValue);
      if ("consumed" in rec) {
        check(rs.bitsProcessed() == rec.consumed.tointeger(),
          rec.name + ": consumed " + rs.bitsProcessed() + " bits, want " + rec.consumed);
      }
    } else {
      throw "TestSerializeCompressedFloat: record " + rec.name + " has no expect";
    }
  };

  foreach (rec in records) runRecord(rec);

  // (2) the top-of-range clamp witnesses (STANDARD.md compressed_float, "The
  // integer clamp is normative"); serialize.go TestCompressedFloatTopOfRangeClamp
  local witnesses = [ 8388609.0, 16777215.0 ];
  foreach (maxv in witnesses) {
    local write = serialize.WriteStream(blob(8));
    local h = { value = maxv };
    check(write.serializeCompressedFloat(h, 0.0, maxv, 1.0) == true, "write max " + maxv);
    write.flush();
    local rs = serialize.ReadStream(write.data());
    local out = { value = -1.0 };
    check(rs.serializeCompressedFloat(out, 0.0, maxv, 1.0) == true, "read max " + maxv);
    check(out.value == maxv, "clamp witness " + maxv + " decoded " + out.value);

    // the precomputed entry point reaches the same audited home
    local p = serialize.compressedFloatParams(0.0, maxv, 1.0);
    local write2 = serialize.WriteStream(blob(8));
    check(write2.serializeCompressedFloatPrecomputed(h, p.maxIntegerValue, p.bits, p.delta, 0.0) == true,
      "write max (precomputed) " + maxv);
    write2.flush();
    local rs2 = serialize.ReadStream(write2.data());
    local out2 = { value = -1.0 };
    check(rs2.serializeCompressedFloatPrecomputed(out2, p.maxIntegerValue, p.bits, p.delta, 0.0) == true,
      "read max (precomputed) " + maxv);
    check(out2.value == maxv, "clamp witness (precomputed) " + maxv + " decoded " + out2.value);
  }

  // (3) misuse rules (serialize.go TestCompressedFloatValidation; DESIGN.md (g))
  local ws = serialize.WriteStream(blob(8));
  local h = { value = 5.0 };

  // min >= max, resolution <= 0
  raises(function() { ws.serializeCompressedFloat(h, 10.0, 0.0, 1.0); },
    "serialize: compressed float requires min < max and resolution > 0",
    "min >= max");
  raises(function() { ws.serializeCompressedFloat(h, 0.0, 10.0, 0.0); },
    "serialize: compressed float requires min < max and resolution > 0",
    "resolution <= 0");

  // precomputed constants that are not what CompressedFloatParams derives
  raises(function() { ws.serializeCompressedFloatPrecomputed(h, 1000, 5, 10.0, 0.0); },
    "serialize: precomputed compressed float constants must be exactly what CompressedFloatParams derives",
    "wrong precomputed constants");
  raises(function() { ws.serializeCompressedFloatPrecomputed(h, 0, 0, 10.0, 0.0); },
    "serialize: precomputed compressed float constants must be exactly what CompressedFloatParams derives",
    "maxIntegerValue 0");

  // a non-finite value raises on write and on measure (DESIGN.md (e))
  local hNan = { value = (1.0 / 0.0) * 0.0 };
  raises(function() { ws.serializeCompressedFloat(hNan, 0.0, 10.0, 0.01); },
    "serialize: compressed float value is not finite", "a NaN value on write");
  local hInf = { value = 1.0 / 0.0 };
  raises(function() { ws.serializeCompressedFloat(hInf, 0.0, 10.0, 0.01); },
    "serialize: compressed float value is not finite", "an infinite value on write");
  local ms = serialize.MeasureStream();
  raises(function() { ms.serializeCompressedFloat(hNan, 0.0, 10.0, 0.01); },
    "serialize: compressed float value is not finite", "a NaN value on measure");

  // the reader refuses an integer above max_integer_value, which the refused
  // vectors already pin; also through the precomputed entry point. A malicious
  // packet can encode integer values above maxIntegerValue in the bit headroom.
  local bad = blob(2);
  bad[0] = 0xFF;
  bad[1] = 0xFF;
  local rs = serialize.ReadStream(bad);
  local p = serialize.compressedFloatParams(0.0, 10.0, 0.01);
  local out = { value = -1.0 };
  check(rs.serializeCompressedFloatPrecomputed(out, p.maxIntegerValue, p.bits, p.delta, 0.0) == false,
    "a code above maxIntegerValue was accepted");
  check(rs.error() == serialize.SerializeError.ValueOutOfRange, "the refused code latched " + rs.error());
  check(out.value == -1.0, "the refused code changed its holder");
}
