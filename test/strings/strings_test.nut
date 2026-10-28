// TestSerializeStrings: the bytes and string card of serialize-squirrel
// (DESIGN.md (h), file layout: src/serialize_bytes.nut), format 2.0. It pins,
// in this order:
//
//   (1) every record of conformance/bytes.txt and string.txt, read and
//       written as a runner must, each refusal for its stated reason, with the
//       record count per file printed and required to equal the file's
//       (STANDARD.md, Bytes and Strings; Reader Obligations; The Measure
//       Stream);
//   (2) the string length rule at the buffer boundary, and the buffer size
//       domain [1, 2^31);
//   (3) the strict writer: a string with a zero byte or that is not
//       well-formed UTF-8 raises on write and measure, in every stream state;
//   (4) the length is checked against the remaining bytes BEFORE the payload
//       is allocated, so a short stream claiming a huge length is past_end;
//   (5) the measure stream's conservative bound for bytes and string;
//   (6) accepted-string conversion across empty, ASCII, multibyte/high-bit
//       UTF-8, BOM, noncharacters, maximum agreed length, truncation, and
//       NUL/UTF-8 refusal precedence, plus the known-bad per-byte growing-prefix
//       source and behavior control.
//
// A test passes by returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestSerializeStrings: " + what;
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

local trim = function(s) {
  local a = 0;
  local b = s.len();
  while (a < b && (s[a] == 32 || s[a] == 9 || s[a] == 13)) a++;
  while (b > a && (s[b - 1] == 32 || s[b - 1] == 9 || s[b - 1] == 13)) b--;
  return s.slice(a, b);
};

local tokens = function(line) {
  local out = [];
  local cur = "";
  foreach (ch in line) {
    local c = ch & 0xff;
    if (c == 32 || c == 9 || c == 13) {
      if (cur.len() > 0) { out.append(cur); cur = ""; }
    } else {
      cur += c.tochar();
    }
  }
  if (cur.len() > 0) out.append(cur);
  return out;
};

local BYTE_CHARS = array(256);
for (local c = 0; c < 256; c++) BYTE_CHARS[c] = c.tochar();

local sliceBytesToString = null;
sliceBytesToString = function(bytes, lo, hi) {
  local span = hi - lo;
  if (span <= 4) {
    if (span == 4) {
      return (BYTE_CHARS[bytes[lo] & 0xff] + BYTE_CHARS[bytes[lo + 1] & 0xff]) +
          (BYTE_CHARS[bytes[lo + 2] & 0xff] + BYTE_CHARS[bytes[lo + 3] & 0xff]);
    }
    if (span == 3) {
      return BYTE_CHARS[bytes[lo] & 0xff] + BYTE_CHARS[bytes[lo + 1] & 0xff] +
          BYTE_CHARS[bytes[lo + 2] & 0xff];
    }
    if (span == 2) return BYTE_CHARS[bytes[lo] & 0xff] + BYTE_CHARS[bytes[lo + 1] & 0xff];
    if (span == 1) return BYTE_CHARS[bytes[lo] & 0xff];
    return "";
  }
  local mid = lo + (span >> 1);
  return sliceBytesToString(bytes, lo, mid) + sliceBytesToString(bytes, mid, hi);
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  return sliceBytesToString(b, 0, b.len());
};

local hexDigit = function(c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw "TestSerializeStrings: not a hex digit: " + c;
};

local parseHex = function(tok) {
  local v = 0;
  for (local i = 0; i < tok.len(); i++) v = v * 16 + hexDigit(tok[i]);
  return v;
};

local makeBlob = function(bytes) {
  local b = blob(bytes.len());
  for (local i = 0; i < bytes.len(); i++) b[i] = bytes[i] & 0xff;
  return b;
};

local sameBytes = function(got, want, what) {
  check(got.len() == want.len(), what + ": length " + got.len() + ", want " + want.len());
  for (local i = 0; i < want.len(); i++) {
    check((got[i] & 0xff) == (want[i] & 0xff),
      what + ": byte " + i + " is " + (got[i] & 0xff) + ", want " + (want[i] & 0xff));
  }
};

local sameArray = function(got, want, what) {
  check(got.len() == want.len(), what + ": length " + got.len() + ", want " + want.len());
  for (local i = 0; i < want.len(); i++) {
    check(got[i] == want[i], what + ": item " + i + " is " + got[i] + ", want " + want[i]);
  }
};

local stringFromBytes = function(bytes) {
  return sliceBytesToString(bytes, 0, bytes.len());
};

local bytesOfString = function(s) {
  local out = [];
  foreach (ch in s) out.append(ch & 0xff);
  return out;
};

// parseRecordFile(path): the records of a conformance vector file, as tables.
local parseRecordFile = function(path) {
  local records = [];
  local rec = null;
  foreach (raw in split(readText(path), "\n")) {
    local line = trim(raw);
    if (line.len() == 0) {
      if (rec != null) { records.append(rec); rec = null; }
      continue;
    }
    if (line[0] == '#') continue;
    local t = tokens(line);
    if (t[0] == "operation") {
      rec = { operation = t[1], name = "", params = {}, bytes = [],
              expect = "refused", reason = null, value = [], consumed = -1, writer = false };
    } else if (t[0] == "name") {
      rec.name = t[1];
    } else if (t[0] == "param") {
      rec.params[t[1]] <- t[3].tointeger();
    } else if (t[0] == "bytes") {
      for (local i = 1; i < t.len(); i++) rec.bytes.append(parseHex(t[i]));
    } else if (t[0] == "expect") {
      if (t[1] == "refused") {
        check(t.len() == 3, rec.name + ": `expect refused` must state one reason");
        rec.expect = "refused";
        rec.reason = t[2];
      } else {
        rec.expect = "value";
        for (local i = 3; i < t.len(); i++) rec.value.append(parseHex(t[i]));
      }
    } else if (t[0] == "consumed") {
      rec.consumed = t[1].tointeger();
    } else if (t[0] == "writer") {
      rec.writer = t[1] == "canonical";
    } else {
      throw "TestSerializeStrings: " + path + ": unknown record line: " + line;
    }
  }
  if (rec != null) records.append(rec);
  return records;
};

local param = function(rec, key, fallback) {
  return (key in rec.params) ? rec.params[key] : fallback;
};

// writePreceding(stream, bytes, n): the first n wire bits, LSB first, which
// place the operation at its bit index. They are the previous field's value,
// not padding.
local writePreceding = function(stream, bytes, n) {
  if (n == 0) return;
  local value = 0;
  for (local i = 0; i < n; i++) {
    if ((bytes[i >> 3] >>> (i & 7)) & 1) value = value | (1 << i);
  }
  check(stream._room(n), "preceding bits do not fit the writer");
  stream._put(value, n);
};

local readPreceding = function(stream, n) {
  if (n == 0) return;
  check(stream._room(n), "preceding bits do not fit the data");
  stream._take(n);
};

// runWriter(rec, serialize): the writer canonical bytes of a record.
local runWriter = function(rec, serialize) {
  local capacity = ((rec.bytes.len() + 7) / 8) * 8;
  if (capacity == 0) capacity = 8;
  local stream = serialize.WriteStream(blob(capacity));
  local preceding = param(rec, "preceding_bits", 0);
  writePreceding(stream, rec.bytes, preceding);

  local ok = false;
  if (rec.operation == "bytes") {
    local count = param(rec, "count", rec.value.len());
    check(rec.value.len() == count, rec.name + ": count " + count + " but " + rec.value.len() + " value bytes");
    ok = stream.serializeBytes(makeBlob(rec.value));
  } else if (rec.operation == "string") {
    local h = { value = stringFromBytes(rec.value) };
    ok = stream.serializeString(h, param(rec, "buffer_size", 0));
  } else {
    throw "TestSerializeStrings: writer: unknown operation " + rec.operation;
  }
  check(ok, rec.name + ": the writer refused");
  check(stream.error() == null, rec.name + ": the writer latched " + stream.error());
  stream.flush();
  sameBytes(stream.data(), rec.bytes, rec.name + ": writer bytes");
  check(stream.bitsProcessed() == rec.consumed,
    rec.name + ": writer processed " + stream.bitsProcessed() + " bits, want " + rec.consumed);
};

// expectedError(rec): the refusal reason the record states (format 2.0).
local expectedError = function(rec, serialize) {
  check(rec.reason != null, rec.name + ": a refused record states no reason");
  return rec.reason;
};

// runReader(rec, serialize): the read side of a record, accepted or refused.
local runReader = function(rec, serialize) {
  local stream = serialize.ReadStream(makeBlob(rec.bytes));
  local preceding = param(rec, "preceding_bits", 0);
  readPreceding(stream, preceding);

  if (rec.operation == "bytes") {
    local count = param(rec, "count", 0);
    local dest = blob(count);
    for (local i = 0; i < count; i++) dest[i] = 0xa5;
    local ok = stream.serializeBytes(dest);
    if (rec.expect == "value") {
      check(ok, rec.name + ": the reader refused");
      check(stream.error() == null, rec.name + ": the reader latched " + stream.error());
      sameBytes(dest, rec.value, rec.name + ": read bytes");
      check(stream.bitsProcessed() == rec.consumed,
        rec.name + ": reader processed " + stream.bitsProcessed() + " bits, want " + rec.consumed);
    } else {
      check(!ok, rec.name + ": the reader accepted refused data");
      check(stream.error() == expectedError(rec, serialize),
        rec.name + ": reader latched " + stream.error() + ", want " + expectedError(rec, serialize));
      for (local i = 0; i < count; i++) check(dest[i] == 0xa5, rec.name + ": refused read wrote byte " + i);
      local at = stream.bitsProcessed();
      check(!stream.serializeBytes(dest), rec.name + ": a latched stream read again");
      check(stream.bitsProcessed() == at, rec.name + ": a latched stream moved its bit index");
    }
  } else if (rec.operation == "string") {
    local h = { value = "untouched" };
    local ok = stream.serializeString(h, param(rec, "buffer_size", 0));
    if (rec.expect == "value") {
      check(ok, rec.name + ": the reader refused");
      check(stream.error() == null, rec.name + ": the reader latched " + stream.error());
      sameArray(bytesOfString(h.value), rec.value, rec.name + ": read string");
      check(stream.bitsProcessed() == rec.consumed,
        rec.name + ": reader processed " + stream.bitsProcessed() + " bits, want " + rec.consumed);
    } else {
      check(!ok, rec.name + ": the reader accepted refused data");
      check(stream.error() == expectedError(rec, serialize),
        rec.name + ": reader latched " + stream.error() + ", want " + expectedError(rec, serialize));
      check(h.value == "untouched", rec.name + ": a refused read modified the holder");
      local at = stream.bitsProcessed();
      check(!stream.serializeString(h, param(rec, "buffer_size", 0)), rec.name + ": a latched stream read again");
      check(stream.bitsProcessed() == at, rec.name + ": a latched stream moved its bit index");
      check(h.value == "untouched", rec.name + ": a latched read modified the holder");
    }
  } else {
    throw "TestSerializeStrings: reader: unknown operation " + rec.operation;
  }
};

// runLengthValidation: the string length at the buffer boundary. A length of
// bufferSize-1 fits, a length of bufferSize does not (STANDARD.md, string),
// and the length is compared at SQInteger width before any length field is
// written: the whole [1, 2^31) buffer domain is expressible, and one past it
// is misuse.
local runLengthValidation = function(serialize) {
  local s7 = "";
  local s8 = "";
  for (local i = 0; i < 7; i++) s7 += "a";
  for (local i = 0; i < 8; i++) s8 += "a";
  local ws = serialize.WriteStream(blob(64));
  check(ws.serializeString({ value = s7 }, 8), "a 7 byte string must fit buffer size 8");
  raises(function() { ws.serializeString({ value = s8 }, 8); }, "serialize: write misuse: ", "an 8 byte string in buffer size 8");
  check(ws.error() == null, "the 8 byte trap latched " + ws.error());

  local top = serialize.WriteStream(blob(8));
  check(top.serializeString({ value = "" }, 0x7fffffff), "buffer size 2^31-1 must be accepted");
  local tooBig = { value = "" };
  raises(function() { serialize.WriteStream(blob(8)).serializeString(tooBig, 0x80000000); },
    "serialize: string buffer size must be in [1,1<<31)", "buffer size 2^31");
  raises(function() { serialize.WriteStream(blob(8)).serializeString(tooBig, 0); },
    "serialize: string buffer size must be in [1,1<<31)", "buffer size 0");
  raises(function() { serialize.WriteStream(blob(8)).serializeString(tooBig, -1); },
    "serialize: string buffer size must be in [1,1<<31)", "buffer size -1");
};

// runStrictWriter: the writer is handed well-formed UTF-8 with no zero byte, as
// it is handed an int in its range (STANDARD.md, string); anything else is API
// misuse and traps before any bit moves, on the write and the measure stream,
// a full writer included (IMPLEMENTING.md U9; DESIGN.md (g)). Real text in every plane is
// accepted. Reversed witness: the format 1.1 writer wrote every one of them.
local runStrictWriter = function(serialize) {
  local nul = "serialize: a string must not contain a zero byte";
  local utf8 = "serialize: a string must be well-formed UTF-8";
  local cases = [
    { text = stringFromBytes([ 0x00 ]), panic = nul, what = "a lone NUL" },
    { text = stringFromBytes([ 0x61, 0x00, 0x62 ]), panic = nul, what = "an interior NUL" },
    { text = stringFromBytes([ 0x02, 0xff, 0x00 ]), panic = nul, what = "a NUL beside an invalid byte" },
    { text = stringFromBytes([ 0xc0, 0xaf ]), panic = utf8, what = "an overlong slash" },
    { text = stringFromBytes([ 0xed, 0xa0, 0x80 ]), panic = utf8, what = "an encoded surrogate" },
    { text = stringFromBytes([ 0xf4, 0x90, 0x80, 0x80 ]), panic = utf8, what = "a code point above 10FFFF" },
    { text = stringFromBytes([ 0xe7, 0xa2 ]), panic = utf8, what = "a truncated sequence" },
    { text = stringFromBytes([ 0x80 ]), panic = utf8, what = "a lone continuation byte" },
  ];
  foreach (c in cases) {
    local h = { value = c.text };
    local full = serialize.WriteStream(blob(8));
    full.serializeBits64({ value = 0 }, 64);
    foreach (stream in [serialize.WriteStream(blob(64)), serialize.MeasureStream(), full]) {
      local before = stream.bitsProcessed();
      raises(function() { stream.serializeString(h, 64); }, c.panic, "the writer handed " + c.what);
      check(stream.bitsProcessed() == before, c.what + ": the raising write moved the bit index");
    }
  }
  // real text travels: CJK, a combining mark, a BOM, U+FFFF and an astral emoji
  local text = stringFromBytes([ 0xe7, 0xa2, 0x81, 0x65, 0xcc, 0x81, 0xef, 0xbb, 0xbf, 0xef, 0xbf, 0xbf, 0xf0, 0x9f, 0x98, 0x80 ]);
  local ws = serialize.WriteStream(blob(64));
  check(ws.serializeString({ value = text }, 64), "real text was refused by the writer: " + ws.error());
  ws.flush();
  local back = { value = "" };
  check(serialize.ReadStream(ws.data()).serializeString(back, 64) && back.value == text, "real text did not round trip byte for byte");
};

// runAllocateAfterCheck: a string length is checked against the bytes that
// remain BEFORE the payload is allocated (STANDARD.md Reader Obligations; the
// 2026-10-22 port brief, allocate-before-check). Four bytes claiming a length
// near 2^31 are refused as past_end at once, never after a 2 GiB allocation.
local runAllocateAfterCheck = function(serialize) {
  local data = makeBlob([ 0xfe, 0xff, 0xff, 0x7f ]);
  local rs = serialize.ReadStream(data);
  local h = { value = "untouched" };
  // a platform may allocate a huge blob lazily, so the witness is the request
  // itself: the library's blob() resolves through the root table at call
  // time, so a counting wrapper sees every allocation the read makes
  local original = ::blob;
  local largest = 0;
  ::blob <- function(n = 0) {
    if (n > largest) largest = n;
    return original(n);
  };
  local accepted = rs.serializeString(h, 0x7fffffff);
  ::blob <- original;
  check(largest <= data.len(), "the read allocated " + largest + " bytes for a 4 byte stream before checking the claimed length");
  check(!accepted, "a 4 byte stream claiming a huge string was accepted");
  check(rs.error() == serialize.SerializeError.PastEnd, "the huge claimed length latched " + rs.error());
  check(h.value == "untouched", "the refused huge length modified the holder");
};

// runMeasure: the measure stream charges the worst case 7 bits per alignment
// and exact width otherwise (STANDARD.md, The Measure Stream).
local runMeasure = function(serialize) {
  local data = makeBlob([ 0xde, 0xad, 0xbe, 0xef ]);
  local m = serialize.MeasureStream();
  check(m.serializeBytes(data), "measure bytes refused");
  check(m.bitsProcessed() == 7 + 4 * 8,
    "measure bytes " + m.bitsProcessed() + " bits, want " + (7 + 32));

  local h = { value = "golden" };
  local ms = serialize.MeasureStream();
  check(ms.serializeString(h, 16), "measure string refused");
  check(ms.bitsProcessed() == 4 + 7 + 6 * 8,
    "measure string " + ms.bitsProcessed() + " bits, want " + (4 + 7 + 48));

  // a value over the buffer traps on a measure as on a write, latching
  // nothing (IMPLEMENTING.md U6, U9)
  local long = { value = "0123456789abcdef" };
  local mf = serialize.MeasureStream();
  raises(function() { mf.serializeString(long, 16); }, "serialize: write misuse: ", "a measure of a string that does not fit");
  check(mf.error() == null, "measure string trap latched " + mf.error());
};

local bitsRequiredValue = function(maxValue) {
  if (maxValue <= 0) return 0;
  local b = 0;
  local v = maxValue;
  while (v > 0) {
    b++;
    v = v >>> 1;
  }
  return b;
};

local roundTripStringCase = function(serialize, rawBytes, bufferSize, precedingBits, what) {
  local text = stringFromBytes(rawBytes);
  check(text.len() == rawBytes.len(), what + ": stringFromBytes length mismatch");
  local lenBits = bitsRequiredValue(bufferSize - 1);
  local padBits = (8 - ((precedingBits + lenBits) & 7)) & 7;
  local totalBits = precedingBits + lenBits + padBits + 8 * rawBytes.len();
  local capWords = ((totalBits + 63) / 64) * 8;
  if (capWords < 8) capWords = 8;

  local ws = serialize.WriteStream(blob(capWords));
  if (precedingBits > 0) {
    local pv = { value = (1 << precedingBits) - 1 };
    check(ws.serializeBits(pv, precedingBits), what + ": write preceding bits refused");
  }
  check(ws.serializeString({ value = text }, bufferSize), what + ": writer refused: " + ws.error());
  check(ws.bitsProcessed() == totalBits,
    what + ": writer bits " + ws.bitsProcessed() + ", want " + totalBits);
  ws.flush();

  local wire = ws.data();
  local headerBytes = (precedingBits + lenBits + padBits) / 8;
  for (local i = 0; i < rawBytes.len(); i++) {
    check((wire[headerBytes + i] & 0xff) == (rawBytes[i] & 0xff),
      what + ": wire payload byte " + i + " is " + (wire[headerBytes + i] & 0xff) + ", want " + (rawBytes[i] & 0xff));
  }

  local ms = serialize.MeasureStream();
  if (precedingBits > 0) {
    check(ms.serializeBits({ value = 0 }, precedingBits), what + ": measure preceding bits refused");
  }
  check(ms.serializeString({ value = text }, bufferSize), what + ": measure refused");
  check(ms.bitsProcessed() == precedingBits + lenBits + 7 + 8 * rawBytes.len(),
    what + ": measure bits " + ms.bitsProcessed());

  local rs = serialize.ReadStream(wire);
  if (precedingBits > 0) {
    local rv = { value = 0 };
    check(rs.serializeBits(rv, precedingBits), what + ": read preceding bits refused");
    check(rv.value == (1 << precedingBits) - 1, what + ": read preceding bits mismatch");
  }
  local out = { value = "untouched" };
  check(rs.serializeString(out, bufferSize), what + ": reader refused: " + rs.error());
  check(rs.error() == null, what + ": reader latched " + rs.error());
  check(rs.bitsProcessed() == totalBits,
    what + ": reader bits " + rs.bitsProcessed() + ", want " + totalBits);
  check(out.value == text, what + ": decoded string mismatch");
  sameArray(bytesOfString(out.value), rawBytes, what + ": decoded bytes");
};

// runConversionCorrectness: registered cases covering empty, ASCII across leaf
// and midpoint split boundaries, multibyte/high-bit UTF-8 straddling split
// boundaries, UTF-8 BOM, Unicode noncharacters, maximum agreed length
// (bufferSize - 1), truncation, and invalid NUL/UTF-8 with refusal precedence
// and holder preservation.
local runConversionCorrectness = function(serialize) {
  // (a) Empty string across buffer sizes and bit alignments.
  foreach (bufSize in [1, 2, 16, 65536]) {
    foreach (prec in [0, 1, 3, 7]) {
      roundTripStringCase(serialize, [], bufSize, prec,
        "empty bufSize=" + bufSize + " prec=" + prec);
    }
  }

  // (b) ASCII across 4-byte leaf and recursive midpoint split boundaries, with
  // position-dependent non-repeating bytes so any dropped, duplicated or
  // swapped slice fails byte comparison.
  local splitLengths = [
    1, 2, 3, 4, 5, 6, 7, 8, 9,
    15, 16, 17, 31, 32, 33, 63, 64, 65,
    127, 128, 129, 255, 256, 257,
    511, 512, 513, 1023, 1024, 1025, 4095, 4096,
  ];
  foreach (len in splitLengths) {
    local bytes = array(len);
    for (local i = 0; i < len; i++) {
      bytes[i] = 0x21 + ((i * 73 + 19) % 94);
    }
    roundTripStringCase(serialize, bytes, len + 1, len % 8,
      "ascii split len=" + len);
  }

  // (c) Multibyte / high-bit UTF-8 (2-, 3-, and 4-byte sequences) shifted by
  // 0..3 leading ASCII bytes so sequences straddle 4-byte leaf boundaries and
  // recursive midpoints.
  local utf8Units = [
    [ 0xc2, 0x80 ],                   // U+0080 (lowest 2-byte)
    [ 0xc2, 0xa2 ],                   // U+00A2
    [ 0xdf, 0xbf ],                   // U+07FF (highest 2-byte)
    [ 0xe0, 0xa0, 0x80 ],             // U+0800 (lowest 3-byte)
    [ 0xe2, 0x82, 0xac ],             // U+20AC
    [ 0xed, 0x9f, 0xbf ],             // U+D7FF (below surrogates)
    [ 0xee, 0x80, 0x80 ],             // U+E000 (above surrogates)
    [ 0xf0, 0x90, 0x80, 0x80 ],       // U+10000 (lowest 4-byte)
    [ 0xf0, 0x9f, 0x98, 0x80 ],       // U+1F600
    [ 0xf4, 0x8f, 0xbf, 0xbf ],       // U+10FFFF (highest Unicode scalar)
  ];
  for (local shift = 0; shift < 4; shift++) {
    local mixed = [];
    for (local s = 0; s < shift; s++) mixed.append(0x41 + s);
    for (local rep = 0; rep < 20; rep++) {
      foreach (u in utf8Units) {
        foreach (b in u) mixed.append(b);
      }
      mixed.append(0x30 + (rep % 10));
    }
    roundTripStringCase(serialize, mixed, mixed.len() + 17, shift * 2 + 1,
      "multibyte utf8 shift=" + shift + " len=" + mixed.len());
  }

  // (d) UTF-8 BOM (EF BB BF) at start, interior, end, and repeated across
  // split boundaries.
  local bomBytes = [
    0xef, 0xbb, 0xbf,
    0x61, 0x62, 0x63, 0x64, 0x65,
    0xef, 0xbb, 0xbf,
    0xe6, 0xbc, 0xa2, 0xf0, 0x9f, 0x98, 0x80,
    0xef, 0xbb, 0xbf,
  ];
  roundTripStringCase(serialize, bomBytes, 64, 0, "utf8-bom-boundaries");
  roundTripStringCase(serialize, bomBytes, 64, 5, "utf8-bom-unaligned");

  // (e) Unicode noncharacters (U+FDD0..U+FDEF, U+FFFE, U+FFFF, U+1FFFE,
  // U+1FFFF, U+10FFFE, U+10FFFF), all permitted in well-formed UTF-8.
  local nonchars = [
    0xef, 0xb7, 0x90,       // U+FDD0
    0xef, 0xb7, 0xaf,       // U+FDEF
    0xef, 0xbf, 0xbe,       // U+FFFE
    0xef, 0xbf, 0xbf,       // U+FFFF
    0xf0, 0x9f, 0xbf, 0xbe, // U+1FFFE
    0xf0, 0x9f, 0xbf, 0xbf, // U+1FFFF
    0xf4, 0x8f, 0xbf, 0xbe, // U+10FFFE
    0xf4, 0x8f, 0xbf, 0xbf, // U+10FFFF
  ];
  roundTripStringCase(serialize, nonchars, 64, 0, "unicode-noncharacters");
  roundTripStringCase(serialize, nonchars, 64, 3, "unicode-noncharacters-unaligned");

  // (f) Maximum agreed length (bufferSize - 1) accepted and round-tripped;
  // length == bufferSize refused as ValueOutOfRange with holder untouched.
  foreach (bufSize in [1, 2, 8, 256, 4096, 65536]) {
    local maxLen = bufSize - 1;
    local payload = array(maxLen);
    for (local i = 0; i < maxLen; i++) {
      payload[i] = 0x30 + ((i * 37 + 11) % 75);
    }
    roundTripStringCase(serialize, payload, bufSize, 0,
      "max-agreed-length bufSize=" + bufSize);

    // Wire length equal to bufferSize (when bufferSize - 1 is not already a
    // full power-of-two bit mask) must be refused as ValueOutOfRange on read.
    local bits = bitsRequiredValue(bufSize - 1);
    if (bits > 0 && bufSize < (1 << bits)) {
      local raw = serialize.WriteStream(blob(16));
      check(raw.serializeBits({ value = bufSize }, bits), "craft out-of-range length");
      raw.flush();
      local rs = serialize.ReadStream(raw.data());
      local h = { value = "untouched" };
      check(!rs.serializeString(h, bufSize), "reader accepted length == bufferSize");
      check(rs.error() == serialize.SerializeError.ValueOutOfRange,
        "length == bufferSize latched " + rs.error());
      check(h.value == "untouched", "refused length == bufferSize modified holder");
    }
  }

  // (g) Truncation: stream cut 1 byte short of claimed length is refused as
  // PastEnd before allocation / conversion, leaving holder untouched.
  foreach (claimed in [1, 5, 255, 4095]) {
    local bufSize = claimed + 16;
    local full = array(claimed, 0x61);
    local ws = serialize.WriteStream(blob(((claimed + 16) / 8 + 2) * 8));
    check(ws.serializeString({ value = stringFromBytes(full) }, bufSize), "write for truncation test");
    ws.flush();
    local wire = ws.data();
    local bits = bitsRequiredValue(bufSize - 1);
    local headerBytes = (bits + 7) / 8;
    local shortLen = headerBytes + claimed - 1;
    local truncated = blob(shortLen);
    for (local i = 0; i < shortLen; i++) truncated[i] = wire[i];

    local rs = serialize.ReadStream(truncated);
    local h = { value = "untouched" };
    check(!rs.serializeString(h, bufSize), "truncated payload of length " + claimed + " was accepted");
    check(rs.error() == serialize.SerializeError.PastEnd,
      "truncated payload latched " + rs.error() + ", want past_end");
    check(h.value == "untouched", "truncated payload modified holder");
  }

  // (h) Invalid NUL and UTF-8 refusal and NUL-before-UTF-8 precedence on
  // multi-chunk payloads, preserving holder and stream terminality.
  local buildRawStringPacket = function(payloadBytes, bufSize) {
    local bits = bitsRequiredValue(bufSize - 1);
    local cap = ((bits + 7) / 8 + payloadBytes.len() + 8) / 8 * 8;
    local ws = serialize.WriteStream(blob(cap));
    check(ws.serializeBits({ value = payloadBytes.len() }, bits), "raw length");
    check(ws.serializeBytes(makeBlob(payloadBytes)), "raw payload");
    ws.flush();
    return ws.data();
  };

  local trailingNulAfterBadUtf8 = array(512, 0x61);
  trailingNulAfterBadUtf8[3] = 0xff; // invalid UTF-8 in first leaf
  trailingNulAfterBadUtf8[511] = 0x00; // NUL in last leaf: EmbeddedNul still wins
  local trailingBadUtf8 = array(512, 0x61);
  trailingBadUtf8[511] = 0xe2; // truncated 3-byte sequence at end

  local refusalCases = [
    { bytes = [ 0x00 ], err = serialize.SerializeError.EmbeddedNul, what = "lone NUL" },
    { bytes = [ 0xff, 0x00 ], err = serialize.SerializeError.EmbeddedNul, what = "invalid UTF-8 then NUL" },
    { bytes = [ 0x00, 0xff ], err = serialize.SerializeError.EmbeddedNul, what = "NUL then invalid UTF-8" },
    { bytes = trailingNulAfterBadUtf8, err = serialize.SerializeError.EmbeddedNul, what = "512-byte invalid UTF-8 with trailing NUL" },
    { bytes = [ 0xc0, 0xaf ], err = serialize.SerializeError.InvalidUtf8, what = "overlong 2-byte" },
    { bytes = [ 0xe0, 0x80, 0x80 ], err = serialize.SerializeError.InvalidUtf8, what = "overlong 3-byte" },
    { bytes = [ 0xf0, 0x80, 0x80, 0x80 ], err = serialize.SerializeError.InvalidUtf8, what = "overlong 4-byte" },
    { bytes = [ 0xed, 0xa0, 0x80 ], err = serialize.SerializeError.InvalidUtf8, what = "surrogate U+D800" },
    { bytes = [ 0xed, 0xbf, 0xbf ], err = serialize.SerializeError.InvalidUtf8, what = "surrogate U+DFFF" },
    { bytes = [ 0xf4, 0x90, 0x80, 0x80 ], err = serialize.SerializeError.InvalidUtf8, what = "above U+10FFFF" },
    { bytes = [ 0x80 ], err = serialize.SerializeError.InvalidUtf8, what = "lone continuation" },
    { bytes = trailingBadUtf8, err = serialize.SerializeError.InvalidUtf8, what = "512-byte truncated UTF-8 tail" },
  ];
  foreach (rc in refusalCases) {
    local wire = buildRawStringPacket(rc.bytes, 1024);
    local rs = serialize.ReadStream(wire);
    local h = { value = "untouched" };
    check(!rs.serializeString(h, 1024), rc.what + ": accepted invalid payload");
    check(rs.error() == rc.err, rc.what + ": latched " + rs.error() + ", want " + rc.err);
    check(h.value == "untouched", rc.what + ": modified holder");
    local at = rs.bitsProcessed();
    check(!rs.serializeString(h, 1024), rc.what + ": latched stream read again");
    check(rs.bitsProcessed() == at, rc.what + ": latched stream advanced bits");
    check(h.value == "untouched", rc.what + ": second call on latched stream modified holder");
  }
};

// measureBytesModuleCalls(fn): runs fn() under setdebughook and returns the
// number of function calls and peak call depth inside serialize_bytes.nut.
local measureBytesModuleCalls = function(fn) {
  local calls = 0;
  local depth = 0;
  local maxDepth = 0;
  setdebughook(function(ev, src, line, func) {
    if (src == null || src.find("serialize_bytes.nut") == null) return;
    if (ev == 'c') {
      calls++;
      depth++;
      if (depth > maxDepth) maxDepth = depth;
    } else if (ev == 'r') {
      if (depth > 0) depth--;
    }
  });
  local err = null;
  try { fn(); } catch (e) { err = e; }
  setdebughook(null);
  if (err != null) throw err;
  return { calls = calls, maxDepth = maxDepth };
};

// verifyBoundedConversionBehavior(lib): deterministic structural check that
// accepted string conversion uses the balanced midpoint tree (2*(n/4) - 2
// internal sliceToString calls above n=1, with call depth growing by +1 per
// doubling n -> 2n -> 4n) and that refused reads never enter conversion.
local verifyBoundedConversionBehavior = function(lib) {
  local runAccepted = function(n) {
    local payload = array(n, 0x61);
    local cap = ((n + 32) / 8 + 2) * 8;
    local ws = lib.WriteStream(blob(cap));
    check(ws.serializeString({ value = stringFromBytes(payload) }, n + 16), "write n=" + n);
    ws.flush();
    local wire = ws.data();
    local h = { value = "" };
    local stats = measureBytesModuleCalls(function() {
      local rs = lib.ReadStream(wire);
      check(rs.serializeString(h, n + 16), "read n=" + n);
    });
    check(h.value.len() == n, "decoded len=" + h.value.len() + ", want " + n);
    return stats;
  };

  local s1 = runAccepted(1);
  local s64 = runAccepted(64);
  local s128 = runAccepted(128);
  local s256 = runAccepted(256);
  local s512 = runAccepted(512);
  local s1024 = runAccepted(1024);

  // For n = 4 * 2^k, balanced midpoint sliceToString makes 2*(n/4) - 1 calls
  // (versus 1 call for n = 1) and increases maxDepth by 1 per doubling.
  check(s64.calls - s1.calls == 30,
    "n=64 extra calls " + (s64.calls - s1.calls) + ", want 30");
  check(s128.calls - s1.calls == 62,
    "n=128 extra calls " + (s128.calls - s1.calls) + ", want 62");
  check(s256.calls - s1.calls == 126,
    "n=256 extra calls " + (s256.calls - s1.calls) + ", want 126");
  check(s512.calls - s1.calls == 254,
    "n=512 extra calls " + (s512.calls - s1.calls) + ", want 254");
  check(s1024.calls - s1.calls == 510,
    "n=1024 extra calls " + (s1024.calls - s1.calls) + ", want 510");

  check(s128.maxDepth - s64.maxDepth == 1,
    "depth(128)-depth(64) = " + (s128.maxDepth - s64.maxDepth) + ", want 1");
  check(s256.maxDepth - s128.maxDepth == 1,
    "depth(256)-depth(128) = " + (s256.maxDepth - s128.maxDepth) + ", want 1");
  check(s512.maxDepth - s256.maxDepth == 1,
    "depth(512)-depth(256) = " + (s512.maxDepth - s256.maxDepth) + ", want 1");
  check(s1024.maxDepth - s512.maxDepth == 1,
    "depth(1024)-depth(512) = " + (s1024.maxDepth - s512.maxDepth) + ", want 1");
  check(s1024.maxDepth <= s1.maxDepth + 8,
    "n=1024 maxDepth " + s1024.maxDepth + " exceeds logarithmic bound");

  // Refused reads must never enter blobToString / sliceToString.
  local badWire = blob(8);
  badWire[0] = 4; // length = 4 for bufferSize = 16
  badWire[1] = 0x61;
  badWire[2] = 0x00; // EmbeddedNul
  badWire[3] = 0x62;
  badWire[4] = 0x63;
  local refusedStats = measureBytesModuleCalls(function() {
    local rs = lib.ReadStream(badWire);
    local h = { value = "untouched" };
    check(!rs.serializeString(h, 16), "refused read accepted");
  });
  check(refusedStats.calls < s1.calls,
    "refused read entered blobToString (" + refusedStats.calls + " >= " + s1.calls + ")");
};

// runConversionCostControl: verifies that the known-bad per-byte immutable
// concatenation is absent from src/serialize_bytes.nut, that the live library
// satisfies verifyBoundedConversionBehavior across n, 2n, 4n, and that
// restoring the old per-byte growing-prefix loop (or an unbalanced split) in a
// sabotaged copy of src/serialize_bytes.nut fails the control.
local runConversionCostControl = function(root, serialize) {
  local srcText = readText(root + "/src/serialize_bytes.nut");
  local knownBadLoop = "for (local i = 0; i < b.len(); i++) s += (b[i] & 0xff).tochar();";
  check(srcText.find(knownBadLoop) == null,
    "src/serialize_bytes.nut still contains the known-bad per-byte growing-prefix loop");
  check(srcText.find("sliceToString") != null,
    "src/serialize_bytes.nut is missing sliceToString");

  verifyBoundedConversionBehavior(serialize);

  local sabotages = [
    {
      name = "growing-prefix-concat",
      needle = "local blobToString = function(b) {\n  return sliceToString(b, 0, b.len());\n};",
      patch = "local blobToString = function(b) {\n  local s = \"\";\n  for (local i = 0; i < b.len(); i++) s += (b[i] & 0xff).tochar();\n  return s;\n};",
    },
    {
      name = "unbalanced-linear-split",
      needle = "  local mid = lo + (span >> 1);",
      patch = "  local mid = lo + 1;",
    },
  ];

  foreach (sab in sabotages) {
    local dir = root + "/build/string-control-" + sab.name;
    check(system("rm -rf '" + dir + "' && mkdir -p '" + dir + "' && cp '" + root + "/src/'*.nut '" + dir + "/'") == 0,
      "could not populate " + dir);
    local idx = srcText.find(sab.needle);
    check(idx != null, sab.name + ": needle not found in src/serialize_bytes.nut");
    local content = srcText.slice(0, idx) + sab.patch + srcText.slice(idx + sab.needle.len());
    local out = file(dir + "/serialize_bytes.nut", "wb");
    local b = blob(content.len());
    for (local i = 0; i < content.len(); i++) b[i] = content[i] & 0xff;
    out.writeblob(b);
    out.close();
    local badLib = dofile(dir + "/serialize.nut", true);
    local failed = false;
    try {
      verifyBoundedConversionBehavior(badLib);
    } catch (e) {
      failed = true;
    }
    check(system("rm -rf '" + dir + "'") == 0, "could not remove " + dir);
    check(failed, "negative control " + sab.name + " did not fail verifyBoundedConversionBehavior");
  }
};

function TestSerializeStrings() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  // (1) every record of the two conformance files, read and written.
  local files = [
    { name = "bytes.txt", operation = "bytes", count = 12 },
    { name = "string.txt", operation = "string", count = 53 },
  ];
  foreach (spec in files) {
    local records = parseRecordFile(root + "/conformance/" + spec.name);
    check(records.len() == spec.count,
      spec.name + " has " + records.len() + " records, the file's count is " + spec.count);
    local ran = 0;
    local written = 0;
    foreach (rec in records) {
      check(rec.operation == spec.operation,
        spec.name + ": record " + rec.name + " is a " + rec.operation);
      runReader(rec, serialize);
      ran++;
      if (rec.writer) {
        runWriter(rec, serialize);
        written++;
      }
    }
    check(ran == records.len(), spec.name + ": ran " + ran + " of " + records.len() + " records");
    print("conformance/" + spec.name + ": " + ran + " records read, " + written + " written\n");
  }

  // (2) the length rule and the buffer size domain
  runLengthValidation(serialize);

  // (3) the strict writer
  runStrictWriter(serialize);

  // (4) the length checked before the payload is allocated
  runAllocateAfterCheck(serialize);

  // (5) the measure stream's bound
  runMeasure(serialize);

  // (6) accepted-string conversion across boundary and refusal cases, and the
  // known-bad per-byte growing-prefix source and behavior control
  runConversionCorrectness(serialize);
  runConversionCostControl(root, serialize);
}
