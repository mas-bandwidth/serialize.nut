// The uniform behaviour rules, IMPLEMENTING.md U1 to U16 (serialize v2.1.1),
// one Test per rule this port proves here. None is a corpus vector: each is
// write-side, measure-side, API-shape or caller-misuse behaviour.
//
//   TestU1WriteBufferMultipleOf8   a write buffer that is not a multiple of 8
//                                  bytes raises (kept)
//   TestU5IntBoundsInt32           int bounds outside int32 raise on write and
//                                  measure, refuse on read
//   TestU7ReadNeverTraps           every bad declaration on read refuses
//                                  value_out_of_range before any bit moves,
//                                  never raises, and a failed stream keeps its
//                                  first reason (U7, U16)
//   TestU8OverWideWrite            a value wider than its bits traps on
//                                  write, never masked (U8, U9)
//   TestU10WholeOperationRoom      bytes and string write nothing ahead of a
//                                  payload that does not fit, and trap (U9)
//   TestU12EndOnWriteAndMeasure    end on a write or a measure is a no-op
//                                  returning true
//   TestU13Reset                   reset re-initialises every stream (kept)
//   TestU14FailAndRefusalName      a public fail(reason) and refusalName
//   TestU15CopyString              copyString, the reference's
//                                  serialize_copy_string
//   TestU9WriteMisuseTraps         every write misuse traps at the call and
//                                  latches nothing; fail and a refusing
//                                  object return false (2.1.1)
//   TestU6MeasureTraps             a measure makes every check a write makes
//                                  by the same trap, room aside (2.1.1)
//   TestU15CopyStringBackOff       copyString backs off to a whole character,
//                                  every reference vector (2.1.1)
//   TestU15Exports                 the API table exports only what U15's
//                                  ruling allows (2.1.1)
//
// Every test but U1 and U13 was red on the 2.1.0 src; the four 2.1.1 tests
// were red on the 2.1.0 release and green after the U6/U9/U15 change. A test passes by
// returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "uniform: " + what;
};

local raises = function(fn, what) {
  local got = null;
  try { fn(); } catch (e) { got = e; }
  check(got != null, what + ": did not raise");
};

local load = function() { return dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true); };

// traps(fn, what): fn() throws the library's own trap, a string starting with
// "serialize:" (U9: the trap is a thrown error in Squirrel). fn is called
// directly, never through .call or acall: sq prints a throw that crosses a
// native call to stderr even when it is caught (DESIGN.md (i)).
local traps = function(fn, what) {
  local got = null;
  try { fn(); } catch (e) { got = e; }
  check(got != null, what + ": did not trap");
  check(typeof got == "string" && got.len() >= 10 && got.slice(0, 10) == "serialize:", what + ": trapped with " + got + ", not the library's trap");
};

function TestU1WriteBufferMultipleOf8() {
  local serialize = load();
  foreach (n in [ 1, 4, 12, 63 ]) {
    raises(function() { serialize.WriteStream(blob(n)); }, "a " + n + "-byte write buffer");
  }
  serialize.WriteStream(blob(0));
  serialize.WriteStream(blob(16));
}

function TestU5IntBoundsInt32() {
  local serialize = load();
  local bounds = [ [ -0x80000001, 0 ], [ 0, 0x80000000 ], [ -0x100000000, 0x100000000 ], [ 0x100000000, 0x100000000 ] ];
  foreach (b in bounds) {
    local what = "[" + b[0] + ", " + b[1] + "]";
    raises(function() { serialize.WriteStream(blob(8)).serializeInt({ value = b[0] }, b[0], b[1]); }, "write over " + what);
    raises(function() { serialize.MeasureStream().serializeInt({ value = b[0] }, b[0], b[1]); }, "measure over " + what);
    local rs = serialize.ReadStream(blob(8));
    local h = { value = "untouched" };
    check(rs.serializeInt(h, b[0], b[1]) == false && rs.error() == "value_out_of_range" && h.value == "untouched" && rs.bitsProcessed() == 0,
      "read over " + what + " did not refuse value_out_of_range with nothing read");
  }
  // the int32 edges themselves are legal
  local ws = serialize.WriteStream(blob(8));
  check(ws.serializeInt({ value = -0x80000000 }, -0x80000000, 0x7FFFFFFF), "the full int32 range");
}

function TestU7ReadNeverTraps() {
  local serialize = load();
  local params = serialize.compressedFloatParams(0.0, 10.0, 0.01);
  local reads = [
    { what = "bits 0", call = function(rs, h) { return rs.serializeBits(h, 0); } },
    { what = "bits 33", call = function(rs, h) { return rs.serializeBits(h, 33); } },
    { what = "bits 3.5", call = function(rs, h) { return rs.serializeBits(h, 3.5); } },
    { what = "bits64 65", call = function(rs, h) { return rs.serializeBits64(h, 65); } },
    { what = "int min > max", call = function(rs, h) { return rs.serializeInt(h, 5, 4); } },
    { what = "int64 min > max", call = function(rs, h) { return rs.serializeInt64(h, 5, 4); } },
    { what = "int128 min > max", call = function(rs, h) { return rs.serializeInt128(h, [5, 0], [4, 0]); } },
    { what = "fixed64 Q format", call = function(rs, h) { return rs.serializeFixed64(h, 0, 0, 0, 0); } },
    { what = "fixed128 Q format", call = function(rs, h) { return rs.serializeFixed128(h, 64, 63, 0, 0); } },
    { what = "int_relative previous -1", call = function(rs, h) { return rs.serializeIntRelative(-1, h); } },
    { what = "string buffer size 0", call = function(rs, h) { return rs.serializeString(h, 0); } },
    { what = "string buffer size -1", call = function(rs, h) { return rs.serializeString(h, -1); } },
    { what = "string holder not a table", call = function(rs, h) { return rs.serializeString(null, 8); } },
    { what = "bytes into a non-blob", call = function(rs, h) { return rs.serializeBytes([1, 2]); } },
    { what = "compressed float min >= max", call = function(rs, h) { return rs.serializeCompressedFloat(h, 1.0, 1.0, 0.01); } },
    { what = "compressed float bits inconsistent", call = function(rs, h) { return rs.serializeCompressedFloatPrecomputed(h, params.maxIntegerValue, params.bits + 1, params.delta, 0.0); } },
    { what = "compressed float maxIntegerValue 0", call = function(rs, h) { return rs.serializeCompressedFloatPrecomputed(h, 0, 0, params.delta, 0.0); } },
    { what = "compressed float maxIntegerValue above 4294967040", call = function(rs, h) { return rs.serializeCompressedFloatPrecomputed(h, 0xFFFFFFFF, 32, params.delta, 0.0); } },
    { what = "compressed float delta 0", call = function(rs, h) { return rs.serializeCompressedFloatPrecomputed(h, params.maxIntegerValue, params.bits, 0.0, 0.0); } },
  ];
  foreach (r in reads) {
    local rs = serialize.ReadStream(blob(16));
    local h = { value = "untouched" };
    local got = null;
    local raised = null;
    try { got = r.call(rs, h); } catch (e) { raised = e; }
    check(raised == null, r.what + ": the read raised " + raised);
    check(got == false && rs.error() == "value_out_of_range", r.what + ": answered " + got + " with reason " + rs.error());
    check(rs.bitsProcessed() == 0 && h.value == "untouched", r.what + ": bits moved or the holder changed");

    // the failure state first: a failed stream keeps its first reason
    local rf = serialize.ReadStream(blob(0));
    rf.serializeBool({ value = false });
    raised = null;
    try { got = r.call(rf, { value = 0 }); } catch (e) { raised = e; }
    check(raised == null && got == false && rf.error() == "past_end", r.what + ": a failed stream's reason became " + rf.error());
  }
}

function TestU8OverWideWrite() {
  local serialize = load();
  local cases = [
    { what = "bits 3 of 8", call = function(ws) { return ws.serializeBits({ value = 8 }, 3); } },
    { what = "bits 3 of -1", call = function(ws) { return ws.serializeBits({ value = -1 }, 3); } },
    { what = "bits 32 of 2^32", call = function(ws) { return ws.serializeBits({ value = 0x100000000 }, 32); } },
    { what = "bits64 40 of 2^40", call = function(ws) { return ws.serializeBits64({ value = 0x10000000000 }, 40); } },
    { what = "uint8 of 256", call = function(ws) { return ws.serializeUint8({ value = 256 }); } },
    { what = "uint16 of 65536", call = function(ws) { return ws.serializeUint16({ value = 0x10000 }); } },
    { what = "uint32 of -1", call = function(ws) { return ws.serializeUint32({ value = -1 }); } },
  ];
  foreach (c in cases) {
    local ws = serialize.WriteStream(blob(16));
    traps(function() { c.call(ws); }, c.what);
    check(ws.error() == null && ws.bitsProcessed() == 0, c.what + ": the over-wide value latched or moved bits before the trap");
  }
  // the widest values that fit still write
  local ws = serialize.WriteStream(blob(32));
  check(ws.serializeBits({ value = 7 }, 3) && ws.serializeBits({ value = 0xFFFFFFFF }, 32) &&
    ws.serializeBits64({ value = -1 }, 64) && ws.serializeUint8({ value = 255 }) &&
    ws.serializeUint32({ value = 0xFFFFFFFF }) && ws.serializeUint64({ value = -1 }), "a value that fits was refused: " + ws.error());
}

function TestU10WholeOperationRoom() {
  local serialize = load();
  // 3 bits in: bytes would align 5 bits, then 8 bytes do not fit in 64 bits
  local ws = serialize.WriteStream(blob(8));
  check(ws.serializeBits({ value = 1 }, 3), "the lead bits");
  local data = blob(8);
  traps(function() { ws.serializeBytes(data); }, "bytes that do not fit");
  check(ws.error() == null && ws.bitsProcessed() == 3,
    "bytes wrote " + (ws.bitsProcessed() - 3) + " bits ahead of a payload that did not fit");
  // 56 bits in: a 5-bit length field fits, the 3-byte payload does not
  ws = serialize.WriteStream(blob(8));
  check(ws.serializeBits({ value = 0 }, 28) && ws.serializeBits({ value = 0 }, 28), "the lead bits");
  traps(function() { ws.serializeString({ value = "abc" }, 32); }, "a string that does not fit");
  check(ws.error() == null && ws.bitsProcessed() == 56,
    "string wrote " + (ws.bitsProcessed() - 56) + " bits ahead of a payload that did not fit");
  // and the same operations that fit still write the same bits
  ws = serialize.WriteStream(blob(16));
  check(ws.serializeBits({ value = 1 }, 3) && ws.serializeBytes(data) && ws.bitsProcessed() == 72, "bytes that fit");
  check(ws.serializeString({ value = "abc" }, 32) && ws.bitsProcessed() == 72 + 5 + 3 + 24, "a string that fits");
}

function TestU12EndOnWriteAndMeasure() {
  local serialize = load();
  local ws = serialize.WriteStream(blob(8));
  check(ws.serializeEnd() == true && ws.bitsProcessed() == 0, "a healthy writer's end");
  check(ws.serializeBits64({ value = 0 }, 64), "the full writer");
  traps(function() { ws.serializeBool({ value = true }); }, "the writer past its end");
  check(ws.serializeEnd() == true && ws.error() == null, "a full writer's end answered false or latched " + ws.error());
  local ms = serialize.MeasureStream();
  check(ms.serializeEnd() == true && ms.bitsProcessed() == 0, "a measure's end");
}

function TestU13Reset() {
  local serialize = load();
  local rs = serialize.ReadStream(blob(0));
  rs.serializeBool({ value = false });
  check(rs.error() == "past_end", "the read latched");
  rs.reset(blob(1));
  local h = { value = null };
  check(rs.error() == null && rs.serializeBool(h) && h.value == false, "reset did not clear the read latch");
  local ws = serialize.WriteStream(blob(8));
  ws.serializeBits({ value = 5 }, 3);
  ws.reset(blob(8));
  check(ws.error() == null && ws.bitsProcessed() == 0 && ws.serializeBool({ value = true }), "reset did not re-initialise the writer");
  local ms = serialize.MeasureStream();
  ms.serializeBool({ value = true });
  ms.reset();
  check(ms.bitsProcessed() == 0, "reset did not clear the measure");
}

function TestU14FailAndRefusalName() {
  local serialize = load();
  local E = serialize.SerializeError;
  check(serialize.refusalName(E.None) == "none", "refusalName(None) is not none");
  foreach (k, v in E) {
    if (v != null) check(serialize.refusalName(v) == v, "refusalName(" + k + ") is " + serialize.refusalName(v));
  }
  check(serialize.refusalName("bogus") == "unknown" && serialize.refusalName(7) == "unknown", "an unknown reason is not named unknown");

  // fail(reason) on read latches the reason, the first one wins
  local rs = serialize.ReadStream(blob(8));
  check(rs.fail(E.NonCanonical) == false && rs.error() == "non_canonical", "fail(non_canonical)");
  check(rs.fail(E.PastEnd) == false && rs.error() == "non_canonical", "a second fail changed the reason");
  check(rs.serializeBool({ value = false }) == false, "a read succeeded after fail");
  // no reason, or one outside the closed list, latches rejected, never none
  foreach (bad in [ null, "bogus", 3 ]) {
    rs = serialize.ReadStream(blob(8));
    local raised = null;
    try { check(rs.fail(bad) == false, "fail answered true"); } catch (e) { raised = e; }
    check(raised == null && rs.error() == "rejected", "fail(" + bad + ") latched " + rs.error() + " or raised " + raised);
  }
  rs = serialize.ReadStream(blob(8));
  check(rs.fail() == false && rs.error() == "rejected", "fail() latched " + rs.error());

  // on a write or a measure fail answers false and latches nothing (U6, U9)
  local ws = serialize.WriteStream(blob(8));
  check(ws.fail(E.PastEnd) == false && ws.error() == null && ws.serializeBool({ value = true }), "fail on a write");
  local ms = serialize.MeasureStream();
  check(ms.fail(E.PastEnd) == false && ms.error() == null && ms.serializeBool({ value = true }), "fail on a measure");
}

function TestU15CopyString() {
  local serialize = load();
  check(serialize.copyString("hello world!", 6) == "hello", "a truncating copy");
  check(serialize.copyString("hi", 16) == "hi", "a short copy");
  check(serialize.copyString("abc", 1) == "", "destSize 1 holds only the terminator");
  local withNul = "ab" + format("%c", 0) + "cd";
  check(withNul.len() == 5 && serialize.copyString(withNul, 16) == "ab", "the copy did not stop at the zero byte");
  raises(function() { serialize.copyString("abc", 0); }, "destSize 0");
}

// --- 2.1.1: U6, U9 and the U15 rulings (serialize v2.1.1 IMPLEMENTING.md) ---

local NAN = casti2f(0x7FF8000000000000);
local INF = casti2f(0x7FF0000000000000);

// every write misuse U9 names, as a call on a fresh stream of either kind.
// room is not here: a measure has none, and U10's room trap is its own case.
local misuses = function(serialize) {
  local p = serialize.compressedFloatParams(0.0, 10.0, 0.01);
  return [
    { what = "int above max", call = function(s) { return s.serializeInt({ value = 11 }, 0, 10); } },
    { what = "int below min", call = function(s) { return s.serializeInt({ value = -1 }, 0, 10); } },
    { what = "int degenerate range, other value", call = function(s) { return s.serializeInt({ value = 4 }, 5, 5); } },
    { what = "int64 above max", call = function(s) { return s.serializeInt64({ value = 0x100000000 }, 0, 0xFFFFFFFF); } },
    { what = "int128 above max", call = function(s) { return s.serializeInt128({ value = [11, 0] }, [0, 0], [10, 0]); } },
    { what = "fixed64 raw above max", call = function(s) { return s.serializeFixed64({ value = 0x7FFFFFFF }, 16, 16, -1, 1); } },
    { what = "fixed128 raw above max", call = function(s) { return s.serializeFixed128({ value = [0, 0x7FFFFFFF] }, 64, 64, -1, 1); } },
    { what = "int_relative current not above previous", call = function(s) { return s.serializeIntRelative(5, { value = 5 }); } },
    { what = "int_relative current past int32", call = function(s) { return s.serializeIntRelative(5, { value = 0x80000000 }); } },
    { what = "bits 3 of 8", call = function(s) { return s.serializeBits({ value = 8 }, 3); } },
    { what = "bits 3 of -1", call = function(s) { return s.serializeBits({ value = -1 }, 3); } },
    { what = "bits64 40 of 2^40", call = function(s) { return s.serializeBits64({ value = 0x10000000000 }, 40); } },
    { what = "uint8 of 256", call = function(s) { return s.serializeUint8({ value = 256 }); } },
    { what = "uint16 of 65536", call = function(s) { return s.serializeUint16({ value = 0x10000 }); } },
    { what = "uint32 of -1", call = function(s) { return s.serializeUint32({ value = -1 }); } },
    { what = "float NaN", call = function(s) { return s.serializeFloat({ value = NAN }); } },
    { what = "float +inf", call = function(s) { return s.serializeFloat({ value = INF }); } },
    { what = "float 1e39 (narrows to +inf)", call = function(s) { return s.serializeFloat({ value = 1e39 }); } },
    { what = "double NaN", call = function(s) { return s.serializeDouble({ value = NAN }); } },
    { what = "double -inf", call = function(s) { return s.serializeDouble({ value = -INF }); } },
    { what = "compressed float NaN", call = function(s) { return s.serializeCompressedFloat({ value = NAN }, 0.0, 10.0, 0.01); } },
    { what = "compressed float +inf", call = function(s) { return s.serializeCompressedFloat({ value = INF }, 0.0, 10.0, 0.01); } },
    { what = "compressed float precomputed NaN", call = function(s) { return s.serializeCompressedFloatPrecomputed({ value = NAN }, p.maxIntegerValue, p.bits, p.delta, 0.0); } },
    { what = "compressed float values not finite (0, 1e38, 1e-38)", call = function(s) { return s.serializeCompressedFloat({ value = 1.0 }, 0.0, 1e38, 1e-38); } },
    { what = "compressed float delta not finite (-3e38, 3e38)", call = function(s) { return s.serializeCompressedFloat({ value = 1.0 }, -3e38, 3e38, 1.0); } },
    { what = "compressed float resolution NaN", call = function(s) { return s.serializeCompressedFloat({ value = 1.0 }, 0.0, 10.0, NAN); } },
    { what = "compressed float min NaN", call = function(s) { return s.serializeCompressedFloat({ value = 1.0 }, NAN, 10.0, 0.01); } },
    { what = "string longer than bufferSize - 1", call = function(s) { return s.serializeString({ value = "abcd" }, 4); } },
    { what = "string with a NUL", call = function(s) { return s.serializeString({ value = "a" + (0).tochar() + "b" }, 8); } },
    { what = "string not UTF-8", call = function(s) { return s.serializeString({ value = "a" + (0xC3).tochar() }, 8); } },
    { what = "reject", call = function(s) { return s.reject(); } },
  ];
};

// U9: every write misuse traps at the call, latches nothing, and a later write
// emits exactly what it would have without it
function TestU9WriteMisuseTraps() {
  local serialize = load();
  local clean = serialize.WriteStream(blob(8));
  check(clean.serializeBits({ value = 5 }, 3) && clean.serializeBits({ value = 0x1234 }, 16), "the clean write");
  clean.flush();
  local want = clean.data();
  foreach (m in misuses(serialize)) {
    local ws = serialize.WriteStream(blob(8));
    check(ws.serializeBits({ value = 5 }, 3), m.what + ": the lead bits");
    traps(function() { m.call(ws); }, "write " + m.what);
    check(ws.error() == null && ws.ok(), "write " + m.what + ": latched " + ws.error());
    check(ws.bitsProcessed() == 3, "write " + m.what + ": wrote " + (ws.bitsProcessed() - 3) + " bits before trapping");
    check(ws.serializeBits({ value = 0x1234 }, 16), "write " + m.what + ": a later write failed");
    ws.flush();
    local got = ws.data();
    check(got.len() == want.len(), "write " + m.what + ": a later write's length changed");
    for (local i = 0; i < want.len(); i++) check(got[i] == want[i], "write " + m.what + ": a later write's bytes changed");
  }
  // U10: an operation that does not fit the room left traps, whole, with
  // nothing written; the buffer still takes what fits after it
  local rooms = [
    { what = "bits past the end", lead = 60, call = function(s) { return s.serializeBits({ value = 0 }, 5); } },
    { what = "bool past the end", lead = 64, call = function(s) { return s.serializeBool({ value = true }); } },
    { what = "uint64 past the end", lead = 1, call = function(s) { return s.serializeUint64({ value = 0 }); } },
    { what = "bytes past the end", lead = 3, call = function(s) { return s.serializeBytes(blob(8)); } },
    { what = "string past the end", lead = 56, call = function(s) { return s.serializeString({ value = "abc" }, 32); } },
    { what = "float past the end", lead = 40, call = function(s) { return s.serializeFloat({ value = 1.0 }); } },
    { what = "compressed float past the end", lead = 60, call = function(s) { return s.serializeCompressedFloat({ value = 1.0 }, 0.0, 10.0, 0.01); } },
  ];
  foreach (r in rooms) {
    local ws = serialize.WriteStream(blob(8));
    local lead = r.lead;
    while (lead > 0) { local n = lead > 32 ? 32 : lead; check(ws.serializeBits({ value = 0 }, n), r.what + ": the lead"); lead -= n; }
    traps(function() { r.call(ws); }, "write " + r.what);
    check(ws.error() == null && ws.bitsProcessed() == r.lead, "write " + r.what + ": latched " + ws.error() + " or wrote " + (ws.bitsProcessed() - r.lead) + " bits");
    if (r.lead < 64) check(ws.serializeBits({ value = 0 }, 1), "write " + r.what + ": a later write that fits failed");
  }
  // fail returns false, records nothing, never traps
  local E = serialize.SerializeError;
  local ws = serialize.WriteStream(blob(8));
  local raised = null;
  try { check(ws.fail(E.PastEnd) == false && ws.fail() == false, "fail on a write answered true"); } catch (e) { raised = e; }
  check(raised == null && ws.error() == null && ws.serializeBool({ value = true }), "fail on a write trapped or latched: " + raised);
  // a nested object returning false: the object op returns false, records nothing
  local refusing = { serialize = function(stream) { return false; } };
  ws = serialize.WriteStream(blob(8));
  check(ws.serializeObject(refusing) == false && ws.error() == null, "a refusing object on a write latched " + ws.error());
  check(ws.serializeBool({ value = true }) && ws.bitsProcessed() == 1, "a write after a refusing object failed");
}

// U6: a measure makes every check a write makes, except room and buffer size,
// by the same trap, and latches nothing
function TestU6MeasureTraps() {
  local serialize = load();
  foreach (m in misuses(serialize)) {
    local ms = serialize.MeasureStream();
    check(ms.serializeBits({ value = 5 }, 3), m.what + ": the lead bits");
    traps(function() { m.call(ms); }, "measure " + m.what);
    check(ms.error() == null && ms.ok(), "measure " + m.what + ": latched " + ms.error());
    check(ms.bitsProcessed() == 3, "measure " + m.what + ": charged " + (ms.bitsProcessed() - 3) + " bits before trapping");
    check(ms.serializeBits({ value = 0x1234 }, 16) && ms.bitsProcessed() == 19, "measure " + m.what + ": a later measure failed");
  }
  // no room to run out of: a measure never traps on size
  local ms = serialize.MeasureStream();
  for (local i = 0; i < 64; i++) check(ms.serializeBytes(blob(1024)), "a large measure refused");
  check(ms.error() == null, "a large measure latched " + ms.error());
  // fail returns false, records nothing, never traps; a refusing object the same
  local E = serialize.SerializeError;
  ms = serialize.MeasureStream();
  local raised = null;
  try { check(ms.fail(E.ValueOutOfRange) == false && ms.fail() == false, "fail on a measure answered true"); } catch (e) { raised = e; }
  check(raised == null && ms.error() == null && ms.serializeBool({ value = true }), "fail on a measure trapped or latched: " + raised);
  local refusing = { serialize = function(stream) { return false; } };
  check(ms.serializeObject(refusing) == false && ms.error() == null, "a refusing object on a measure latched " + ms.error());
  check(ms.serializeBool({ value = true }) && ms.bitsProcessed() == 2, "a measure after a refusing object failed");
}

// U15 copy_string (ruling, 2026-10-27): the bytes before the first NUL; past
// destSize - 1, keep the first destSize - 1 bytes and drop bytes from the end
// while the first byte left out is a continuation byte. Squirrel strings are
// bytes, so every vector of the reference's test_copy_string applies,
// the ill-formed ones included.
function TestU15CopyStringBackOff() {
  local serialize = load();
  local bytes = function(list) {
    local s = "";
    foreach (b in list) s += b.tochar();
    return s;
  };
  local e = bytes([ 0xC3, 0xA9 ]);
  local grin = bytes([ 0xF0, 0x9F, 0x98, 0x80 ]);
  local vectors = [
    [ "abc", 8, "abc" ],
    [ "a" + bytes([ 0 ]) + "bc", 8, "a" ],
    [ "abcdefghij", 4, "abc" ],
    [ e + e, 4, e ],
    [ e + e, 3, e ],
    [ "a" + grin, 3, "a" ],
    [ "a" + grin, 4, "a" ],
    [ "a" + grin, 5, "a" ],
    [ "a" + grin, 6, "a" + grin ],
    [ "ab" + bytes([ 0x80, 0x80 ]), 4, "a" ],
    [ e + bytes([ 0xA9, 0xA9 ]), 4, "" ],
    [ "abc", 1, "" ],
  ];
  foreach (i, v in vectors) {
    local got = serialize.copyString(v[0], v[1]);
    check(got == v[2], "copy_string vector " + i + " (destSize " + v[1] + ") gave " + got.len() + " bytes, want " + v[2].len());
  }
  traps(function() { serialize.copyString("abc", 0); }, "destSize 0");
  traps(function() { serialize.copyString("abc", -1); }, "destSize -1");
}

// U15 exports (ruling, 2026-10-27): the public surface is the reference
// operations, the streams, the refusal list and its name, copyString, the
// U15 extras, the reference's helpers and the language necessities; the
// loader's directory is internal and is not exported
function TestU15Exports() {
  local serialize = load();
  local allowed = {
    SerializeError = "refusal list", refusalName = "refusal name (U14)", copyString = "copy_string (U15)",
    WriteStream = "stream", ReadStream = "stream", MeasureStream = "stream",
    BitWriter = "reference helper", BitReader = "reference helper",
    bitsRequired = "reference helper", bitsRequired64 = "reference helper", bitsRequired128 = "reference helper",
    signedToUnsigned = "reference helper", unsignedToSigned = "reference helper",
    compressedFloatParams = "reference helper",
    fround = "language necessity: float32 rounding",
    int128From64 = "language necessity: 128-bit carrier", uint128From64 = "language necessity: 128-bit carrier",
    Continue = "U15 extra", Until = "U15 extra",
  };
  foreach (k, v in serialize) check(k in allowed, "the API table exports " + k + ", which U15 does not allow");
  foreach (k, v in allowed) check(k in serialize, "the API table lacks " + k);
}
