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
//   (5) the measure stream's conservative bound for bytes and string.
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
  check(!ws.serializeString({ value = s8 }, 8), "an 8 byte string must not fit buffer size 8");
  check(ws.error() == serialize.SerializeError.ValueOutOfRange, "the 8 byte refusal latched " + ws.error());

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
// misuse and raises before any bit moves, on the write and the measure stream
// and in every stream state (DESIGN.md (g)). Real text in every plane is
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
    local latched = serialize.WriteStream(blob(8));
    latched._room(65);
    foreach (stream in [serialize.WriteStream(blob(64)), serialize.MeasureStream(), latched]) {
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
}
