// TestReject: the caller's own refusal, `rejected` (STANDARD.md, Refusal
// reasons; IMPLEMENTING.md U2, "The caller's refusal"). The corpus's reject
// vectors pin the wire side through test/conformance; this pins the API:
//
//   (1) SerializeError.Rejected is spelled "rejected";
//   (2) ReadStream.reject() latches Rejected and answers false, and the
//       stream is terminal from there: a later read of readable bits refuses,
//       consumes nothing and keeps the reason;
//   (3) the first reason wins: a reject on a stream a primitive already
//       refused keeps the primitive's reason;
//   (4) serializeObject latches Rejected when the object fails with nothing
//       latched, keeps a primitive's reason when one refused inside it, and
//       accepts an object that returns true;
//   (5) reject is read only: on a write or a measure it answers false and
//       latches nothing (U9).
//
// Reversed witnesses: the 2.0 port had no reject() at all, and its object
// latched value_out_of_range for the caller's refusal. A test passes by
// returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestReject: " + what;
};

local bytesOf = function(list) {
  local b = blob(list.len());
  for (local i = 0; i < list.len(); i++) b[i] = list[i];
  return b;
};

function TestReject() {
  local serialize = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);
  local E = serialize.SerializeError;

  // (1) the name
  check("Rejected" in E && E.Rejected == "rejected", "SerializeError.Rejected is not \"rejected\"");

  // (2) a top-level reject after well formed bits, then terminal
  local rs = serialize.ReadStream(bytesOf([ 0x05, 0xAB ]));
  local h = { value = 0 };
  check(rs.serializeBits(h, 4) && h.value == 5, "the four well formed bits were refused");
  check(rs.reject() == false, "reject() answered true");
  check(rs.error() == E.Rejected, "reject() latched " + rs.error());
  local at = rs.bitsProcessed();
  local later = { value = 77 };
  check(rs.serializeBits(later, 8) == false, "a read after the reject succeeded");
  check(later.value == 77 && rs.bitsProcessed() == at, "the read after the reject consumed bits or wrote its holder");
  check(rs.reject() == false && rs.error() == E.Rejected, "a second reject changed the reason to " + rs.error());
  check(rs.serializeEnd() == false && rs.error() == E.Rejected, "the end after the reject answered " + rs.error());

  // (3) the first reason wins over a later reject
  local rw = serialize.ReadStream(bytesOf([ 0xFD, 0xAB ]));
  check(rw.serializeBits({ value = 0 }, 3), "the three bits were refused");
  check(rw.serializeAlign() == false && rw.error() == E.NonzeroPadding, "the set padding latched " + rw.error());
  check(rw.reject() == false && rw.error() == E.NonzeroPadding, "the reject replaced nonzero_padding with " + rw.error());

  // (4) the object composition
  local failing = { serialize = function(stream) { return false; } };
  local ro = serialize.ReadStream(bytesOf([ 0x05 ]));
  check(ro.serializeObject(failing) == false && ro.error() == E.Rejected, "a failing object latched " + ro.error());
  local readsThenFails = { serialize = function(stream) { stream.serializeBits({ value = 0 }, 16); return false; } };
  local rp = serialize.ReadStream(bytesOf([ 0xFF ]));
  check(rp.serializeObject(readsThenFails) == false && rp.error() == E.PastEnd,
    "the object replaced past_end with " + rp.error());
  local accepting = { serialize = function(stream) { return stream.serializeBits({ value = 0 }, 4); } };
  local ra = serialize.ReadStream(bytesOf([ 0x05 ]));
  check(ra.serializeObject(accepting) && ra.ok(), "an accepting object refused as " + ra.error());

  // (5) read only
  local ws = serialize.WriteStream(blob(8));
  check(ws.reject() == false && ws.ok(), "reject() on a write stream latched " + ws.error());
  check(ws.serializeBits({ value = 1 }, 4), "the write stream refused after a reject");
  local ms = serialize.MeasureStream();
  check(ms.reject() == false && ms.ok(), "reject() on a measure stream latched " + ms.error());
}
