// TestBitpacker: the bit packer card of serialize-squirrel (DESIGN.md (h),
// file layout: src/serialize_bitpacker.nut). It pins, in this order:
//
//   (1) every width 1..32 at every starting bit offset 0..63, against an
//       independent bit-by-bit LSB-first oracle written here, never the code
//       under test (STANDARD.md, General Conventions);
//   (2) serialize.go v1.15.1's TestBitpacker sequence, byte for byte
//       (.ref/serialize.go/serialize_test.go);
//   (3) readBits round-trips (1);
//   (4) a read past the end is refused by wouldReadPastEnd and raises the bit
//       reader's misuse error, and data of 0..9 bytes never reads outside
//       itself (STANDARD.md, Reader Obligations);
//   (5) readAlign refuses a nonzero padding bit (STANDARD.md, align; Reader
//       Obligations, Refusal rules are part of the format).
//
// A test passes by returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestBitpacker: " + what;
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

// mask(bits): the low `bits` bits, as a positive SQInteger (DESIGN.md (c)).
local mask = function(bits) {
  return bits == 32 ? 0xffffffff : (1 << bits) - 1;
};

// makeBlob(bytes, n): a blob holding the first n entries of the array.
local makeBlob = function(bytes, n) {
  local b = blob(n);
  for (local i = 0; i < n; i++) b[i] = bytes[i];
  return b;
};

// sameBlob(got, want, n, what): got is a blob of exactly n bytes equal to want.
local sameBlob = function(got, want, n, what) {
  check(typeof got == "blob", what + ": data is " + typeof got + ", not a blob");
  check(got.len() == n, what + ": data has " + got.len() + " bytes, want " + n);
  for (local i = 0; i < n; i++) {
    check(got[i] == want[i], what + ": byte " + i + " is " + got[i] + ", want " + want[i]);
  }
};

// THE ORACLE: an independent bit-by-bit LSB-first byte array (never the code
// under test). oraclePut sets width bits of value at absolute bit position
// pos, the first value bit at the lowest address bit (STANDARD.md, General
// Conventions).
local oraclePut = function(bytes, pos, value, width) {
  for (local i = 0; i < width; i++) {
    if ((value >>> i) & 1) {
      local at = pos + i;
      bytes[at >> 3] = bytes[at >> 3] | (1 << (at & 7));
    }
  }
};

local zeroArray = function(n) {
  local a = [];
  for (local i = 0; i < n; i++) a.append(0);
  return a;
};

function TestBitpacker() {
  local serialize = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);
  local BitWriter = serialize.BitWriter;
  local BitReader = serialize.BitReader;

  // (1) and (3): every width at every starting bit offset. The prefix is
  // `off` zero bits (written in [1,32] groups), so the value begins at bit
  // `off`; the oracle places it there and nowhere else.
  for (local off = 0; off <= 63; off++) {
    for (local width = 1; width <= 32; width++) {
      local value = (0x9e3779b9 + off * 0x10001 + width * 0x101) & mask(width);
      local buffer = blob(16);
      local writer = BitWriter(buffer);
      local remaining = off;
      while (remaining > 0) {
        local group = remaining > 32 ? 32 : remaining;
        writer.writeBits(0, group);
        remaining -= group;
      }
      writer.writeBits(value, width);
      writer.flushBits();

      local total = off + width;
      local bytes = (total + 7) / 8;
      local want = zeroArray(bytes);
      oraclePut(want, off, value, width);

      local got = writer.data();
      sameBlob(got, want, bytes, "write width " + width + " at offset " + off);
      check(writer.bitsWritten() == total,
        "bitsWritten " + writer.bitsWritten() + ", want " + total);
      check(writer.bytesWritten() == bytes,
        "bytesWritten " + writer.bytesWritten() + ", want " + bytes);
      check(writer.bitsAvailable() == 16 * 8 - total,
        "bitsAvailable " + writer.bitsAvailable() + ", want " + (16 * 8 - total));

      // (3) readBits round-trips (1), from the writer's bytes and from the
      // independent oracle's bytes.
      local packets = [ got, makeBlob(want, bytes) ];
      foreach (at, packet in packets) {
        local reader = BitReader(packet);
        check(reader.bitsRead() == 0, "a fresh reader has read " + reader.bitsRead() + " bits");
        check(reader.bitsRemaining() == bytes * 8,
          "a fresh reader has " + reader.bitsRemaining() + " bits, want " + bytes * 8);
        local left = off;
        while (left > 0) {
          local group = left > 32 ? 32 : left;
          check(reader.readBits(group) == 0, "the zero prefix at offset " + off + " read nonzero");
          left -= group;
        }
        check(reader.readBits(width) == value,
          "read width " + width + " at offset " + off + " (packet " + at + ")");
        check(reader.bitsRead() == total, "bitsRead " + reader.bitsRead() + ", want " + total);
        check(reader.bitsRemaining() == bytes * 8 - total,
          "bitsRemaining " + reader.bitsRemaining() + ", want " + (bytes * 8 - total));
      }
    }
  }

  // (2) serialize.go v1.15.1's TestBitpacker sequence, byte for byte. The
  // expected bytes are the sequence's 76 bits packed LSB first:
  // 2a fc a3 0f 35 fc 67 89 09 00.
  local buffer = blob(256);
  local writer = BitWriter(buffer);
  check(writer.bitsWritten() == 0 && writer.bytesWritten() == 0 && writer.bitsAvailable() == 256 * 8,
    "bad initial writer state");
  writer.writeBits(0, 1);
  writer.writeBits(1, 1);
  writer.writeBits(10, 8);
  writer.writeBits(255, 8);
  writer.writeBits(1000, 10);
  writer.writeBits(50000, 16);
  writer.writeBits(9999999, 32);
  writer.flushBits();

  local bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;
  check(writer.bytesWritten() == 10, "expected 10 bytes written, got " + writer.bytesWritten());
  check(writer.bitsWritten() == bitsWritten, "expected " + bitsWritten + " bits written, got " + writer.bitsWritten());
  check(writer.bitsAvailable() == 256 * 8 - bitsWritten, "bad bits available");

  local want = [ 0x2a, 0xfc, 0xa3, 0x0f, 0x35, 0xfc, 0x67, 0x89, 0x09, 0x00 ];
  local got = writer.data();
  sameBlob(got, want, 10, "the serialize.go TestBitpacker sequence");

  local reader = BitReader(got);
  check(reader.bitsRead() == 0 && reader.bitsRemaining() == 10 * 8, "bad initial reader state");
  local a = reader.readBits(1);
  local b = reader.readBits(1);
  local c = reader.readBits(8);
  local d = reader.readBits(8);
  local e = reader.readBits(10);
  local f = reader.readBits(16);
  local g = reader.readBits(32);
  check(a == 0 && b == 1 && c == 10 && d == 255 && e == 1000 && f == 50000 && g == 9999999,
    "read values do not match written values: " + a + " " + b + " " + c + " " + d + " " + e + " " + f + " " + g);
  check(reader.bitsRead() == bitsWritten, "bad bits read");
  check(reader.bitsRemaining() == 10 * 8 - bitsWritten, "bad bits remaining");
  check(!reader.wouldReadPastEnd(reader.bitsRemaining()), "reading the remaining bits must not read past the end");
  check(reader.wouldReadPastEnd(reader.bitsRemaining() + 1), "reading past the remaining bits must report past the end");

  // (4) every exact data length 0..9 is read to its last bit without leaving
  // the blob; a read one bit past the end reports it and raises the bit
  // reader's misuse error (STANDARD.md, Reader Obligations).
  for (local n = 0; n <= 9; n++) {
    local bytes = [];
    for (local i = 0; i < n; i++) bytes.append((i * 37 + n * 11 + 0x80) & 0xff);
    local data = makeBlob(bytes, n);
    local all = n * 8;
    local r = BitReader(data);
    check(r.bitsRead() == 0 && r.bitsRemaining() == all,
      "a fresh " + n + "-byte reader has " + r.bitsRemaining() + " bits, want " + all);
    local pos = 0;
    while (pos < all) {
      local width = ((pos * 7 + n) % 32) + 1;
      local avail = all - pos;
      if (width > avail) width = avail;
      check(!r.wouldReadPastEnd(width), "a legal " + width + "-bit read at " + pos + " reports past the end");
      local v = r.readBits(width);
      check(v >= 0 && (v >>> width) == 0, "read " + v + " for width " + width + " at " + pos);
      pos += width;
    }
    check(r.bitsRead() == all && r.bitsRemaining() == 0,
      "the " + n + "-byte reader stopped at " + r.bitsRead() + ", want " + all);

    local r2 = BitReader(data);
    local left = all;
    while (left > 31) {
      r2.readBits(32);
      left -= 32;
    }
    check(!r2.wouldReadPastEnd(left), "reading the last " + left + " bits must not report past the end");
    check(r2.wouldReadPastEnd(left + 1), "reading " + (left + 1) + " bits must report past the end");
    local probe = left + 1;
    raises(function() { r2.readBits(probe); },
      "serialize: bit reader would read past the end of the buffer",
      "a " + probe + "-bit read of a " + n + "-byte blob");
  }

  // (5) readAlign accepts zero padding and refuses a nonzero padding bit
  // (STANDARD.md, align; Reader Obligations, Refusal rules are part of the
  // format). The padding bits are consumed either way, as serialize.go's
  // ReadAlign does.
  local zeroPad = blob(2);
  zeroPad[0] = 0x05; // bits 0..2 = 101, bits 3..7 zero
  zeroPad[1] = 0;
  local ar = BitReader(zeroPad);
  check(ar.readBits(3) == 5, "the value before zero padding");
  check(ar.alignBits() == 5, "alignBits " + ar.alignBits() + ", want 5");
  check(ar.readAlign(), "zero padding was refused");
  check(ar.bitsRead() == 8, "readAlign left the index at " + ar.bitsRead() + ", want 8");

  local badPad = blob(2);
  badPad[0] = 0x85; // bits 0..2 = 101, bit 7 nonzero padding
  badPad[1] = 0;
  local br = BitReader(badPad);
  check(br.readBits(3) == 5, "the value before nonzero padding");
  check(!br.readAlign(), "nonzero padding was accepted");
  check(br.bitsRead() == 8, "a refused readAlign left the index at " + br.bitsRead() + ", want 8");

  // The writer's align pads with zero and reports the alignment it wrote
  // (STANDARD.md, align; General Conventions, Bit index and alignment).
  local alignBuffer = blob(8);
  local aw = BitWriter(alignBuffer);
  aw.writeBits(5, 3);
  check(aw.alignBits() == 5, "writer alignBits " + aw.alignBits() + ", want 5");
  aw.writeAlign();
  check(aw.bitsWritten() == 8, "writeAlign left the index at " + aw.bitsWritten() + ", want 8");
  aw.writeBits(1, 1);
  aw.flushBits();
  local alignWant = [ 0x05, 0x01 ];
  sameBlob(aw.data(), alignWant, 2, "the writer's zero align");
  check(aw.alignBits() == 7, "writer alignBits after one bit is " + aw.alignBits() + ", want 7");

  // Writer API misuse raises serialize.go's panic texts; the direct bit
  // writer is Go's BitWriter, so a past-end write is a raise (DESIGN.md (g),
  // serialize.go serialize.go panic strings).
  raises(function() { BitWriter(blob(7)); },
    "serialize: bit writer buffer size must be a multiple of 8 bytes", "a 7-byte buffer");
  local mis = BitWriter(blob(8));
  raises(function() { mis.writeBits(0, 0); }, "serialize: bits must be in [1,32]", "writeBits 0 bits");
  raises(function() { mis.writeBits(0, 33); }, "serialize: bits must be in [1,32]", "writeBits 33 bits");
  mis.writeBits(0, 32);
  mis.writeBits(0, 32);
  raises(function() { mis.writeBits(1, 1); }, "serialize: bit writer overflow", "a write past the buffer");

  local unaligned = BitWriter(blob(8));
  unaligned.writeBits(1, 1);
  raises(function() { unaligned.writeBytes(blob(1), 0, 1); },
    "serialize: byte array serialization requires byte alignment", "an unaligned writeBytes");
  local tooBig = BitWriter(blob(8));
  local nine = blob(9);
  raises(function() { tooBig.writeBytes(nine, 0, 9); }, "serialize: bit writer overflow", "a 9-byte writeBytes");

  // Reader API misuse raises the same texts, and the data is read as bytes
  // (STANDARD.md, bytes; Reader Obligations).
  local rr = BitReader(blob(8));
  raises(function() { rr.readBits(0); }, "serialize: bits must be in [1,32]", "readBits 0 bits");
  raises(function() { rr.readBits(33); }, "serialize: bits must be in [1,32]", "readBits 33 bits");
  rr.readBits(1);
  raises(function() { rr.readBytes(blob(1), 0, 1); },
    "serialize: byte array serialization requires byte alignment", "an unaligned readBytes");
  local rr2 = BitReader(blob(1));
  raises(function() { rr2.readBytes(blob(2), 0, 2); },
    "serialize: bit reader would read past the end of the buffer", "a readBytes past the end");
}
