// TestSerializeEnd: serializeEnd, format 2.0 (STANDARD.md end; serialize.go
// v2.0.0 SerializeEnd). The corpus's end.txt pins the wire through
// test/conformance; this pins the stream behaviour around it:
//
//   (1) the reader's order: a failed stream answers with its first reason; a
//       whole byte or more left is trailing_data, checked BEFORE the padding,
//       so `bits 3; end` over 0D 00 is trailing_data; otherwise a set bit in
//       the final byte's 0-7 unused bits is nonzero_padding, and the bits of
//       the last field are never examined;
//   (2) an accepted end leaves the stream exactly consumed (8 * bytes bits), a
//       further read of one bit is past_end, and a zero-bit read still succeeds;
//   (3) on a write and a measure the end emits nothing and costs nothing, and a
//       failed stream answers false.
//
// Reversed witnesses: without the end (format 1.1) every refused case here
// reads green, and an end that tests padding before trailing data reports
// nonzero_padding for 0D 00. A test passes by returning and fails by throwing
// (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestSerializeEnd: " + what;
};

local bytesOf = function(list) {
  local b = blob(list.len());
  for (local i = 0; i < list.len(); i++) b[i] = list[i];
  return b;
};

// readEnd(serialize, bytes, fieldBits): a field of fieldBits bits (none when 0),
// then the end; returns the stream
local readEnd = function(serialize, bytes, fieldBits) {
  local rs = serialize.ReadStream(bytesOf(bytes));
  if (fieldBits > 0) check(rs.serializeBits({ value = 0 }, fieldBits), "the field before the end was refused");
  rs.serializeEnd();
  return rs;
};

function TestSerializeEnd() {
  local serialize = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);
  local E = serialize.SerializeError;

  // (1) the order of the reader's rules
  local cases = [
    { bytes = [], field = 0, want = E.None, what = "the empty stream" },
    { bytes = [ 0x00 ], field = 0, want = E.TrailingData, what = "one zero byte after the empty object" },
    { bytes = [ 0x05 ], field = 3, want = E.None, what = "three bits with clean padding" },
    { bytes = [ 0x07 ], field = 3, want = E.None, what = "every field bit set" },
    { bytes = [ 0x0D ], field = 3, want = E.NonzeroPadding, what = "the lowest padding bit" },
    { bytes = [ 0x85 ], field = 3, want = E.NonzeroPadding, what = "the highest padding bit" },
    { bytes = [ 0x0D, 0x00 ], field = 3, want = E.TrailingData, what = "trailing data before set padding" },
    { bytes = [ 0x01 ], field = 1, want = E.None, what = "seven bits of padding" },
    { bytes = [ 0x81 ], field = 1, want = E.NonzeroPadding, what = "the seventh padding bit" },
    { bytes = [ 0xFF ], field = 8, want = E.None, what = "an aligned object" },
    { bytes = [ 0xFF, 0x00 ], field = 8, want = E.TrailingData, what = "a zero byte after an aligned object" },
  ];
  foreach (c in cases) {
    local rs = readEnd(serialize, c.bytes, c.field);
    check(rs.error() == c.want, c.what + ": the end answered " + rs.error() + ", want " + c.want);
    if (c.want == E.None) {
      // (2) exactly consumed: 8 * bytes, nothing more to read, zero bits still fine
      check(rs.bitsProcessed() == 8 * c.bytes.len(), c.what + ": consumed " + rs.bitsProcessed() + " bits");
      check(rs.serializeInt({ value = 7 }, 3, 3), c.what + ": a zero-bit read after the end failed");
      local h = { value = 9 };
      check(!rs.serializeBool(h) && rs.error() == E.PastEnd && h.value == 9, c.what + ": a one-bit read after the end answered " + rs.error());
    } else {
      // refused: terminal, the reason kept
      local at = rs.bitsProcessed();
      check(rs.serializeEnd() == false && rs.error() == c.want, c.what + ": a second end changed the reason to " + rs.error());
      check(rs.bitsProcessed() == at, c.what + ": a second end moved the bit index");
    }
  }

  // a failed stream answers its first reason: a range refusal, then the end
  local rf = serialize.ReadStream(bytesOf([ 0x0F ]));
  check(!rf.serializeInt({ value = 0 }, 0, 8), "the out of range field was accepted");
  check(rf.serializeEnd() == false && rf.error() == E.ValueOutOfRange, "the end replaced the first reason with " + rf.error());

  // (3) write and measure: nothing emitted, nothing charged
  local ws = serialize.WriteStream(blob(8));
  check(ws.serializeBits({ value = 5 }, 3) && ws.serializeEnd(), "the writer's end failed");
  check(ws.bitsProcessed() == 3, "the writer's end wrote " + (ws.bitsProcessed() - 3) + " bits");
  ws.flush();
  check(ws.data().len() == 1 && ws.data()[0] == 0x05, "the writer's end changed the bytes");
  local ms = serialize.MeasureStream();
  check(ms.serializeEnd() && ms.bitsProcessed() == 0, "the measure's end charged " + ms.bitsProcessed() + " bits");
  local wf = serialize.WriteStream(blob(8));
  wf._room(65);
  check(wf.serializeEnd() == false && wf.error() == E.PastEnd, "a failed writer's end answered " + wf.error());
}
