// The uniform behaviour rules, IMPLEMENTING.md U1 to U16 (serialize v2.1.0),
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
//   TestU8OverWideWrite            a value wider than its bits is caught on
//                                  write, never masked
//   TestU10WholeOperationRoom      bytes and string write nothing ahead of a
//                                  payload that does not fit
//   TestU12EndOnWriteAndMeasure    end on a write or a measure is a no-op
//                                  returning true
//   TestU13Reset                   reset re-initialises every stream (kept)
//   TestU14FailAndRefusalName      a public fail(reason) and refusalName
//   TestU15CopyString              copyString, the reference's
//                                  serialize_copy_string
//
// Every test but U1 and U13 was red on the 2.1.0 src. A test passes by
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
    check(c.call(ws) == false && ws.error() == "value_out_of_range" && ws.bitsProcessed() == 0,
      c.what + ": the over-wide value was not caught before any bit moved");
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
  check(ws.serializeBytes(data) == false && ws.error() == "past_end" && ws.bitsProcessed() == 3,
    "bytes wrote " + (ws.bitsProcessed() - 3) + " bits ahead of a payload that did not fit");
  // 56 bits in: a 5-bit length field fits, the 3-byte payload does not
  ws = serialize.WriteStream(blob(8));
  check(ws.serializeBits({ value = 0 }, 28) && ws.serializeBits({ value = 0 }, 28), "the lead bits");
  check(ws.serializeString({ value = "abc" }, 32) == false && ws.error() == "past_end" && ws.bitsProcessed() == 56,
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
  check(ws.serializeBits64({ value = 0 }, 64) && ws.serializeBool({ value = true }) == false, "the writer past its end");
  check(ws.serializeEnd() == true && ws.error() == "past_end", "a failed writer's end answered false or changed the reason");
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
  local ws = serialize.WriteStream(blob(0));
  ws.serializeBool({ value = true });
  ws.reset(blob(8));
  check(ws.error() == null && ws.serializeBool({ value = true }), "reset did not clear the write latch");
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
