// TestSerializeStrings: the bytes, string and wstring card of
// serialize-squirrel (DESIGN.md (h), file layout: src/serialize_bytes.nut).
// It pins, in this order:
//
//   (1) every record of conformance/bytes.txt, string.txt and wstring.txt,
//       read and written as a runner must, with the record count per file
//       printed and required to equal the file's (STANDARD.md, Bytes and
//       Strings; Reader Obligations; The Measure Stream);
//   (2) serialize.go v1.15.1's TestSerializeWideStringFamilyPin bytes
//       ("\U0001F600A" against buffer size 8);
//   (3) serialize.go v1.15.1's TestWideStringLengthValidatedBeforeNarrowing
//       rule, at the Squirrel boundary: the UTF-16 length is compared with
//       bufferSize before any narrower length is written;
//   (4) the measure stream's conservative bound for bytes, string and wstring.
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

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  for (local i = 0; i < b.len(); i++) s += (b[i] & 0xff).tochar();
  return s;
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
  local s = "";
  for (local i = 0; i < bytes.len(); i++) s += (bytes[i] & 0xff).tochar();
  return s;
};

local bytesOfString = function(s) {
  local out = [];
  foreach (ch in s) out.append(ch & 0xff);
  return out;
};

local encodeCodepoint = function(cp) {
  local out = [];
  if (cp < 0x80) {
    out.append(cp);
  } else if (cp < 0x800) {
    out.append(0xc0 | (cp >>> 6));
    out.append(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out.append(0xe0 | (cp >>> 12));
    out.append(0x80 | ((cp >>> 6) & 0x3f));
    out.append(0x80 | (cp & 0x3f));
  } else {
    out.append(0xf0 | (cp >>> 18));
    out.append(0x80 | ((cp >>> 12) & 0x3f));
    out.append(0x80 | ((cp >>> 6) & 0x3f));
    out.append(0x80 | (cp & 0x3f));
  }
  return out;
};

local stringFromCodepoints = function(cps) {
  local bytes = [];
  foreach (cp in cps) foreach (b in encodeCodepoint(cp)) bytes.append(b);
  return stringFromBytes(bytes);
};

// utf8Codepoints(s): the code points of a well-formed UTF-8 Squirrel string.
// A malformed byte is U+FFFD and advances one byte, as Go's range does; the
// test only feeds it strings a conforming reader produced.
local utf8Codepoints = function(s) {
  local b = bytesOfString(s);
  local out = [];
  local i = 0;
  while (i < b.len()) {
    local c = b[i];
    local cp = 0xfffd;
    local n = 1;
    if (c < 0x80) {
      cp = c;
    } else if (c >= 0xc2 && c <= 0xdf && i + 1 < b.len() && (b[i + 1] & 0xc0) == 0x80) {
      cp = ((c & 0x1f) << 6) | (b[i + 1] & 0x3f);
      n = 2;
    } else if (c >= 0xe0 && c <= 0xef && i + 2 < b.len() &&
               (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80) {
      cp = ((c & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f);
      n = 3;
    } else if (c >= 0xf0 && c <= 0xf4 && i + 3 < b.len() &&
               (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80 && (b[i + 3] & 0xc0) == 0x80) {
      cp = ((c & 0x07) << 18) | ((b[i + 1] & 0x3f) << 12) |
           ((b[i + 2] & 0x3f) << 6) | (b[i + 3] & 0x3f);
      n = 4;
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
    } else {
      out.append(cp);
    }
  }
  return out;
};

local stringFromUnits = function(units) {
  local cps = [];
  local i = 0;
  while (i < units.len()) {
    local u = units[i];
    if (u >= 0xd800 && u <= 0xdbff) {
      check(i + 1 < units.len(), "stringFromUnits: a high surrogate with no low half");
      local low = units[i + 1];
      check(low >= 0xdc00 && low <= 0xdfff, "stringFromUnits: a high surrogate with no low half");
      cps.append(0x10000 + ((u - 0xd800) << 10) + (low - 0xdc00));
      i += 2;
    } else {
      cps.append(u);
      i++;
    }
  }
  return stringFromCodepoints(cps);
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
              expect = "refused", value = [], consumed = -1, writer = false };
    } else if (t[0] == "name") {
      rec.name = t[1];
    } else if (t[0] == "param") {
      rec.params[t[1]] <- t[3].tointeger();
    } else if (t[0] == "bytes") {
      for (local i = 1; i < t.len(); i++) rec.bytes.append(parseHex(t[i]));
    } else if (t[0] == "expect") {
      if (t[1] == "refused") {
        rec.expect = "refused";
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
  } else if (rec.operation == "wstring") {
    local h = { value = stringFromUnits(rec.value) };
    ok = stream.serializeWideString(h, param(rec, "buffer_size", 0));
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

// expectedError(rec): the refusal kind the record names.
local expectedError = function(rec, serialize) {
  if (rec.name.find("past-end") != null) return serialize.SerializeError.Overflow;
  if (rec.name.find("align-padding") != null) return serialize.SerializeError.Align;
  return serialize.SerializeError.ValueOutOfRange;
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
  } else if (rec.operation == "wstring") {
    local h = { value = "untouched" };
    local ok = stream.serializeWideString(h, param(rec, "buffer_size", 0));
    if (rec.expect == "value") {
      check(ok, rec.name + ": the reader refused");
      check(stream.error() == null, rec.name + ": the reader latched " + stream.error());
      sameArray(unitsFromString(h.value), rec.value, rec.name + ": read code units");
      check(stream.bitsProcessed() == rec.consumed,
        rec.name + ": reader processed " + stream.bitsProcessed() + " bits, want " + rec.consumed);
    } else {
      check(!ok, rec.name + ": the reader accepted refused data");
      check(stream.error() == expectedError(rec, serialize),
        rec.name + ": reader latched " + stream.error() + ", want " + expectedError(rec, serialize));
      check(h.value == "untouched", rec.name + ": a refused read modified the holder");
      local at = stream.bitsProcessed();
      check(!stream.serializeWideString(h, param(rec, "buffer_size", 0)), rec.name + ": a latched stream read again");
      check(stream.bitsProcessed() == at, rec.name + ": a latched stream moved its bit index");
      check(h.value == "untouched", rec.name + ": a latched read modified the holder");
    }
  } else {
    throw "TestSerializeStrings: reader: unknown operation " + rec.operation;
  }
};

// runFamilyPin: serialize.go v1.15.1's TestSerializeWideStringFamilyPin.
local runFamilyPin = function(serialize) {
  // the family's pinned bytes: length 3 in a 3 bit field, then 0xD83D, 0xDE00,
  // 0x0041 as 32 bit groups - 99 bits, 13 bytes
  local pinned = [ 0xeb, 0xc1, 0x06, 0x00, 0x00, 0xf0, 0x06, 0x00,
                   0x08, 0x02, 0x00, 0x00, 0x00 ];

  // the wire built from raw bit operations must reproduce the literal
  local raw = serialize.WriteStream(blob(16));
  raw._put(3, 3);
  raw._put(0xd83d, 32);
  raw._put(0xde00, 32);
  raw._put(0x0041, 32);
  raw.flush();
  check(raw.error() == null, "raw wstring pin latched " + raw.error());
  sameBytes(raw.data(), pinned, "raw wstring pin");

  // the wstring path must produce exactly the pinned bytes
  local ws = serialize.WriteStream(blob(16));
  local h = { value = stringFromCodepoints([ 0x1f600, 0x0041 ]) };
  check(ws.serializeWideString(h, 8), "wstring pin: the writer refused");
  ws.flush();
  check(ws.bitsProcessed() == 3 + 3 * 32,
    "wstring pin: " + ws.bitsProcessed() + " bits, want " + (3 + 3 * 32));
  sameBytes(ws.data(), pinned, "wstring pin");

  // and the read path recombines the pair into the same string
  local rs = serialize.ReadStream(makeBlob(pinned));
  local rh = { value = "untouched" };
  check(rs.serializeWideString(rh, 8), "wstring pin: the reader refused");
  check(rh.value == h.value, "wstring pin: read \"" + rh.value + "\", want \"" + h.value + "\"");
  check(rs.bitsProcessed() == 99, "wstring pin: read " + rs.bitsProcessed() + " bits, want 99");

  // an empty wstring is the zero-bit length field, no alignment anywhere
  local es = serialize.WriteStream(blob(8));
  local eh = { value = "" };
  check(es.serializeWideString(eh, 1), "wstring pin: empty write refused");
  es.flush();
  sameBytes(es.data(), [], "wstring pin: empty");
  check(es.bitsProcessed() == 0, "wstring pin: empty wrote " + es.bitsProcessed() + " bits");
};

// runLengthValidation: serialize.go v1.15.1's
// TestWideStringLengthValidatedBeforeNarrowing, at the SQInteger boundary.
local runLengthValidation = function(serialize) {
  local bs = 8;

  // a length of bufferSize-1 fits, a length of bufferSize does not: the
  // terminator the wire does not carry has nowhere to go
  local s7 = "";
  local s8 = "";
  for (local i = 0; i < 7; i++) s7 += "a";
  for (local i = 0; i < 8; i++) s8 += "a";
  local ws = serialize.WriteStream(blob(64));
  local h7 = { value = s7 };
  check(ws.serializeWideString(h7, bs), "a 7 unit string must fit buffer size 8");
  local h8 = { value = s8 };
  check(!ws.serializeWideString(h8, bs), "an 8 unit string must not fit buffer size 8");
  check(ws.error() == serialize.SerializeError.ValueOutOfRange,
    "the 8 unit refusal latched " + ws.error());

  // one astral code point is two UTF-16 units: buffer size 3 fits it, buffer
  // size 2 does not, so the check counts units, not code points
  local astral = { value = stringFromCodepoints([ 0x1f600 ]) };
  local a3 = serialize.WriteStream(blob(64));
  check(a3.serializeWideString(astral, 3), "one astral code point is two units and fits buffer size 3");
  local a2 = serialize.WriteStream(blob(64));
  check(!a2.serializeWideString(astral, 2), "one astral code point is two units and does not fit buffer size 2");
  check(a2.error() == serialize.SerializeError.ValueOutOfRange,
    "the astral refusal latched " + a2.error());

  // the check runs at SQInteger width before any length field is written: the
  // whole [1, 2^31) buffer domain is expressible, and one past it is misuse
  local empty = { value = "" };
  local top = serialize.WriteStream(blob(8));
  check(top.serializeWideString(empty, 0x7fffffff), "buffer size 2^31-1 must be accepted");
  local tooBig = { value = "" };
  raises(function() { serialize.WriteStream(blob(8)).serializeWideString(tooBig, 0x80000000); },
    "serialize: string buffer size must be in [1,1<<31)", "buffer size 2^31");
  raises(function() { serialize.WriteStream(blob(8)).serializeWideString(tooBig, 0); },
    "serialize: string buffer size must be in [1,1<<31)", "buffer size 0");
  raises(function() { serialize.WriteStream(blob(8)).serializeWideString(tooBig, -1); },
    "serialize: string buffer size must be in [1,1<<31)", "buffer size -1");
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

  local wh = { value = stringFromCodepoints([ 0x1f600, 0x0041 ]) };
  local mw = serialize.MeasureStream();
  check(mw.serializeWideString(wh, 8), "measure wstring refused");
  check(mw.bitsProcessed() == 3 + 3 * 32,
    "measure wstring " + mw.bitsProcessed() + " bits, want " + (3 + 96));

  // a value over the buffer latches ValueOutOfRange, exactly as Go's measure does
  local long = { value = "0123456789abcdef" };
  local mf = serialize.MeasureStream();
  check(!mf.serializeString(long, 16), "measure accepted a string that does not fit");
  check(mf.error() == serialize.SerializeError.ValueOutOfRange,
    "measure string refusal latched " + mf.error());
};

function TestSerializeStrings() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  // (1) every record of the three conformance files, read and written.
  local files = [
    { name = "bytes.txt", operation = "bytes", count = 11 },
    { name = "string.txt", operation = "string", count = 38 },
    { name = "wstring.txt", operation = "wstring", count = 28 },
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

  // (2) serialize.go's cross-family wstring pin
  runFamilyPin(serialize);

  // (3) serialize.go's length-before-narrowing rule
  runLengthValidation(serialize);

  // (4) the measure stream's bound
  runMeasure(serialize);
}
