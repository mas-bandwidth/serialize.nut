// The 2026-10-27 audit's int findings (DESIGN.md (c), "the library never
// overflows"; the nut heading of the audit ledger), one Test per finding:
//
//   TestInt128WideRangeRead     a ranged int128 read over [1, 2^64] whose
//                               offset is 2^63 - 1 decodes to 2^63. Before
//                               the fix u128add's low-lane sum overflowed a
//                               SQInteger (C++ undefined behaviour driven by
//                               the wire); make test-ubsan halts on it.
//   TestInt64WideRange          the int64 ranges wider than 2^63 ([-1, 2^63 -
//                               1] and the full range) price, write, read and
//                               refuse exactly, and the narrow ranges beside
//                               them still take the plain path. Before the fix
//                               every `max - min` here overflowed in the VM.
//   TestFixed128ParamsShift     a Q60.68 declaration with a negative bound
//                               round-trips its raw bounds. Before the fix
//                               int128.lsh shifted the negative high lane
//                               (undefined in the VM).
//   TestInt128DegenerateCopies  a degenerate int128 read (min == max) hands
//                               back a copy of min, never the caller's array:
//                               editing the decoded value leaves the bound
//                               alone. Red on the pinned interpreter before
//                               the fix.
//
// The overflow witnesses are red only under the UBSan interpreter (make
// test-ubsan), where the VM reports the C++ overflow; on the plain pin the
// wrapped answer happened to be right. A test passes by returning and fails
// by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "int audit: " + what;
};

local MIN64 = 0x8000000000000000;
local MAX64 = 0x7FFFFFFFFFFFFFFF;

local bytesOf = function(list) {
  local b = blob(list.len());
  for (local i = 0; i < list.len(); i++) b[i] = list[i];
  return b;
};

local load = function() { return dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true); };

// roundTrip64(serialize, v, min, max): write v over [min, max], read it back,
// and return the decoded value; every leg must succeed
local roundTrip64 = function(serialize, v, min, max) {
  local ws = serialize.WriteStream(blob(16));
  check(ws.serializeInt64({ value = v }, min, max), "write " + v + " over [" + min + ", " + max + "]");
  ws.flush();
  local ms = serialize.MeasureStream();
  check(ms.serializeInt64({ value = v }, min, max), "measure " + v + " over [" + min + ", " + max + "]");
  check(ms.bitsProcessed() == serialize.bitsRequired64(min, max), "measure width over [" + min + ", " + max + "]");
  local rs = serialize.ReadStream(ws.data());
  local h = { value = null };
  check(rs.serializeInt64(h, min, max), "read " + v + " over [" + min + ", " + max + "]: " + rs.error());
  return h.value;
};

function TestInt128WideRangeRead() {
  local serialize = load();
  local rs = serialize.ReadStream(bytesOf([ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00 ]));
  local h = { value = null };
  check(rs.serializeInt128(h, [1, 0], [0, 1]), "the in-range offset 2^63 - 1 over [1, 2^64] refused as " + rs.error());
  check(h.value[0] == MIN64 && h.value[1] == 0, "1 + (2^63 - 1) decoded as [" + h.value[0] + ", " + h.value[1] + "], not 2^63");

  // the top of the range, written and read, over the same declaration
  local ws = serialize.WriteStream(blob(16));
  check(ws.serializeInt128({ value = [0, 1] }, [1, 0], [0, 1]), "write 2^64 over [1, 2^64]");
  ws.flush();
  rs = serialize.ReadStream(ws.data());
  h = { value = null };
  check(rs.serializeInt128(h, [1, 0], [0, 1]) && h.value[0] == 0 && h.value[1] == 1, "2^64 over [1, 2^64] did not round-trip");
  // the span is 2^64 - 1, 64 bits, so every offset is in range: all ones is
  // the top, 2^64
  rs = serialize.ReadStream(bytesOf([ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ]));
  h = { value = null };
  check(rs.serializeInt128(h, [1, 0], [0, 1]) && h.value[0] == 0 && h.value[1] == 1,
    "the offset 2^64 - 1 over [1, 2^64] did not decode to 2^64");
}

function TestInt64WideRange() {
  local serialize = load();

  check(serialize.bitsRequired64(-1, MAX64) == 64, "bitsRequired64(-1, 2^63 - 1) is not 64");
  check(serialize.bitsRequired64(MIN64, MAX64) == 64, "bitsRequired64 of the full range is not 64");
  check(serialize.bitsRequired64(MIN64 + 1, -1) == 63, "bitsRequired64(-2^63 + 1, -1) is not 63");

  foreach (v in [ -1, 0, 1, MAX64 - 1, MAX64 ]) {
    check(roundTrip64(serialize, v, -1, MAX64) == v, v + " over [-1, 2^63 - 1] did not round-trip");
  }
  foreach (v in [ MIN64, MIN64 + 1, -1, 0, MAX64 ]) {
    check(roundTrip64(serialize, v, MIN64, MAX64) == v, v + " over the full range did not round-trip");
  }
  // the narrow ranges beside them stay on the plain path, and stay exact
  foreach (v in [ MIN64, -1 ]) {
    check(roundTrip64(serialize, v, MIN64, -1) == v, v + " over [-2^63, -1] did not round-trip");
  }
  foreach (v in [ -2, 0, MAX64 - 1 ]) {
    check(roundTrip64(serialize, v, -2, MAX64 - 1) == v, v + " over [-2, 2^63 - 2] did not round-trip");
  }

  // all ones over [-1, 2^63 - 1] is the offset 2^64 - 1, above the span 2^63
  local rs = serialize.ReadStream(bytesOf([ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ]));
  local h = { value = 7 };
  check(!rs.serializeInt64(h, -1, MAX64) && rs.error() == "value_out_of_range" && h.value == 7,
    "the offset 2^64 - 1 over [-1, 2^63 - 1] was not refused with the holder untouched");
}

function TestFixed128ParamsShift() {
  local serialize = load();
  // Q60.68, bounds [-(2^58 + 3), 2^58 + 3]: each raw bound is the whole-unit
  // bound shifted left 68, a negative bound shifted in the high lane, so the
  // raw bounds are [0, -(2^62 + 48)] and [0, 2^62 + 48]
  local min = -0x400000000000003;
  local max = 0x400000000000003;
  foreach (v in [ [0, -0x4000000000000030], [0, 0x4000000000000030], [0x123456789ABCDEF0, 5] ]) {
    local ws = serialize.WriteStream(blob(32));
    check(ws.serializeFixed128({ value = v }, 60, 68, min, max), "write [" + v[0] + ", " + v[1] + "]: " + ws.error());
    ws.flush();
    local rs = serialize.ReadStream(ws.data());
    local h = { value = null };
    check(rs.serializeFixed128(h, 60, 68, min, max), "read [" + v[0] + ", " + v[1] + "]: " + rs.error());
    check(h.value[0] == v[0] && h.value[1] == v[1], "[" + v[0] + ", " + v[1] + "] did not round-trip");
  }
}

function TestInt128DegenerateCopies() {
  local serialize = load();
  local lim = [5, 0];
  local rs = serialize.ReadStream(blob(1));
  local h = { value = null };
  check(rs.serializeInt128(h, lim, lim), "the degenerate read refused as " + rs.error());
  check(h.value[0] == 5 && h.value[1] == 0, "the degenerate read decoded [" + h.value[0] + ", " + h.value[1] + "]");
  check(h.value != lim, "the degenerate read handed back the caller's min array itself");
  h.value[0] = 99;
  check(lim[0] == 5 && lim[1] == 0, "editing the decoded value changed the caller's min to [" + lim[0] + ", " + lim[1] + "]");
}
