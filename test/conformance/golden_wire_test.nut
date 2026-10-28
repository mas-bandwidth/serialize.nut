// TestGoldenWireFormat: serialize-squirrel-conformance, format 2.0. It pins
// the golden message of STANDARD.md, "The whole message" (106 bytes, the
// twenty-nine operations ending in end; serialize.go v2.0.0's goldenWireBytes),
// pasted as literals: the golden message reads, ends exactly, and re-writes
// byte for byte, and every single-bit flip of the message, padding bits
// included, is refused or decoded differently. A test passes by returning and
// fails by throwing (DESIGN.md (i)).
//
// The golden message exercises every family of the wire, so its reader and
// writer legs cross the bits, int, int_relative, float, compressed_float,
// bytes, string and fixed modules. The single-bit-flip leg is the control
// STANDARD.md asks for: with the end, every bit of the message is meaningful
// (one value has exactly one byte sequence), so flipping any one, the final
// byte's padding included, must be refused or change the decoded value.

::GOLDEN_SOFT <- false;
local check = function(cond, what) {
  if (!cond) {
    if (::GOLDEN_SOFT) throw "GOLDEN_REFUSED";
    throw "TestGoldenWireFormat: " + what;
  }
};

local MIN64 = 0x8000000000000000;

// goldenWireBytes: verbatim from STANDARD.md, "The whole message" (106 bytes).
local GOLDEN_BYTES = 106;
local goldenWireBytes = blob(GOLDEN_BYTES);
{
  local raw = [
    0x5D, 0xDA, 0xF7, 0xE6, 0xD5, 0x77, 0xDF, 0x56, 0xEF, 0x9F, 0x75, 0x19,
    0x52, 0xBC, 0xDA, 0x0F, 0x49, 0x40, 0xF4, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0xFF, 0xFC, 0xD1, 0x48, 0xE0, 0x59, 0xD1, 0x48, 0xC0, 0x7B,
    0xF3, 0x6A, 0xE2, 0x59, 0xD1, 0x48, 0x84, 0xB7, 0x06, 0xDE, 0xAD, 0xBE,
    0xEF, 0xCA, 0xFE, 0x01, 0x06, 0x67, 0x6F, 0x6C, 0x64, 0x65, 0x6E, 0x06,
    0xE7, 0xA2, 0x81, 0xE7, 0x9F, 0xB3, 0xC0, 0x60, 0x00, 0x80, 0xA2, 0x7C,
    0xFC, 0xEC, 0x26, 0xCB, 0xFF, 0xFF, 0x4B, 0x1D, 0x1F, 0xEF, 0xD2, 0x1A,
    0x1F, 0x01, 0xE9, 0xFF, 0xFF, 0x09, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E,
    0x7F, 0x78, 0x6F, 0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x09, 0x04,
  ];
  check(raw.len() == GOLDEN_BYTES, "the golden literal has " + raw.len() + " bytes");
  for (local i = 0; i < GOLDEN_BYTES; i++) goldenWireBytes[i] = raw[i];
}

// goldenWireRead(serialize, stream): STANDARD.md's whole message, read over the
// 106 golden bytes and ended, returning a table of the decoded values.
local goldenWireRead = function(serialize, stream) {
  local relativeBase = 100;
  local d = {};
  local h = function() { return { value = 0 }; };
  local v = h(); check(stream.serializeBits(v, 4) == true, "bits4"); d.bits4 <- v.value;
  v = h(); check(stream.serializeBits(v, 11) == true, "bits11"); d.bits11 <- v.value;
  v = h(); check(stream.serializeBits(v, 24) == true, "bits24"); d.bits24 <- v.value;
  v = h(); check(stream.serializeBits(v, 32) == true, "bits32"); d.bits32 <- v.value;
  v = h(); check(stream.serializeInt(v, -100, 100) == true, "intSmall"); d.intSmall <- v.value;
  v = h(); check(stream.serializeInt(v, -2147483648, 2147483647) == true, "intFull"); d.intFull <- v.value;
  v = h(); check(stream.serializeBool(v) == true, "flag"); d.flag <- v.value;
  v = h(); check(stream.serializeFloat(v) == true, "floatValue"); d.floatValue <- v.value;
  v = h(); check(stream.serializeCompressedFloat(v, 0.0, 10.0, 0.01) == true, "compressedFloatValue"); d.compressedFloatValue <- v.value;
  v = h(); check(stream.serializeDouble(v) == true, "doubleValue"); d.doubleValue <- v.value;
  v = h(); check(stream.serializeUint8(v) == true, "uint8Value"); d.uint8Value <- v.value;
  v = h(); check(stream.serializeUint16(v) == true, "uint16Value"); d.uint16Value <- v.value;
  v = h(); check(stream.serializeUint32(v) == true, "uint32Value"); d.uint32Value <- v.value;
  v = h(); check(stream.serializeUint64(v) == true, "uint64Value"); d.uint64Value <- v.value;
  v = h(); check(stream.serializeIntRelative(relativeBase, v) == true, "relativeNear"); d.relativeNear <- v.value;
  v = h(); check(stream.serializeIntRelative(relativeBase, v) == true, "relativeFar"); d.relativeFar <- v.value;
  check(stream.serializeAlign() == true, "align1");
  local bytes = blob(7);
  check(stream.serializeBytes(bytes) == true, "bytes");
  d.bytes <- bytes;
  v = { value = "" }; check(stream.serializeString(v, 16) == true, "str"); d.str <- v.value;
  v = { value = "" }; check(stream.serializeString(v, 8) == true, "text"); d.text <- v.value;
  check(stream.serializeAlign() == true, "align2");
  v = h(); check(stream.serializeFixed64(v, 8, 8, -100, 100) == true, "fixedQ8_8"); d.fixedQ8_8 <- v.value;
  v = h(); check(stream.serializeFixed64(v, 16, 16, -2000, 2000) == true, "fixedQ16_16"); d.fixedQ16_16 <- v.value;
  v = h(); check(stream.serializeFixed64(v, 48, 16, -100000, 100000) == true, "fixedQ48_16"); d.fixedQ48_16 <- v.value;
  v = h(); check(stream.serializeFixed64(v, 16, 16, 0, 30000) == true, "fixedQ16_16Unsigned"); d.fixedQ16_16Unsigned <- v.value;
  check(stream.serializeAlign() == true, "align3");
  v = h(); check(stream.serializeFixed128(v, 112, 16, -144115188075855872, 144115188075855872) == true, "fixedQ112_16Wide"); d.fixedQ112_16Wide <- v.value;
  v = h(); check(stream.serializeFixed128(v, 64, 64, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF) == true, "fixedQ64_64Wide"); d.fixedQ64_64Wide <- v.value;
  // STANDARD.md, The whole message: the last field ends at bit 843, three bits
  // into byte 105; the end consumes the final byte's five bits of zero padding
  check(stream.bitsProcessed() == 843, "golden message fields consumed " + stream.bitsProcessed() + " bits");
  check(stream.serializeEnd() == true, "end");
  check(stream.bitsProcessed() == 848, "golden message consumed " + stream.bitsProcessed() + " bits with its end");
  return d;
};

local sameBytes = function(a, b) {
  if (a.len() != b.len()) return false;
  for (local i = 0; i < a.len(); i++) if ((a[i] & 0xff) != (b[i] & 0xff)) return false;
  return true;
};

local same128 = function(a, b) { return a[0] == b[0] && a[1] == b[1]; };
local sameBits = function(a, b) { return castf2i(a) == castf2i(b); };

// sameGolden compares decoded values by BIT PATTERN for the float families, as
// STANDARD.md requires (NaN compares unequal to itself in value space).
local sameGolden = function(a, b) {
  if (a.bits4 != b.bits4) return false;
  if (a.bits11 != b.bits11) return false;
  if (a.bits24 != b.bits24) return false;
  if (a.bits32 != b.bits32) return false;
  if (a.intSmall != b.intSmall) return false;
  if (a.intFull != b.intFull) return false;
  if (a.flag != b.flag) return false;
  if (!sameBits(a.floatValue, b.floatValue)) return false;
  if (!sameBits(a.compressedFloatValue, b.compressedFloatValue)) return false;
  if (!sameBits(a.doubleValue, b.doubleValue)) return false;
  if (a.uint8Value != b.uint8Value) return false;
  if (a.uint16Value != b.uint16Value) return false;
  if (a.uint32Value != b.uint32Value) return false;
  if (a.uint64Value != b.uint64Value) return false;
  if (a.relativeNear != b.relativeNear) return false;
  if (a.relativeFar != b.relativeFar) return false;
  if (!sameBytes(a.bytes, b.bytes)) return false;
  if (a.str != b.str) return false;
  if (a.text != b.text) return false;
  if (a.fixedQ8_8 != b.fixedQ8_8) return false;
  if (a.fixedQ16_16 != b.fixedQ16_16) return false;
  if (a.fixedQ48_16 != b.fixedQ48_16) return false;
  if (a.fixedQ16_16Unsigned != b.fixedQ16_16Unsigned) return false;
  if (!same128(a.fixedQ112_16Wide, b.fixedQ112_16Wide)) return false;
  if (!same128(a.fixedQ64_64Wide, b.fixedQ64_64Wide)) return false;
  return true;
};

function TestGoldenWireFormat() {
  local serialize = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);

  // the golden bytes read and re-write byte for byte
  local rs = serialize.ReadStream(goldenWireBytes);
  local d = goldenWireRead(serialize, rs);

  local ws = serialize.WriteStream(blob(256));
  local relativeBase = 100;
  local w = function(x) { return { value = x }; };
  check(ws.serializeBits(w(d.bits4), 4) == true, "write bits4");
  check(ws.serializeBits(w(d.bits11), 11) == true, "write bits11");
  check(ws.serializeBits(w(d.bits24), 24) == true, "write bits24");
  check(ws.serializeBits(w(d.bits32), 32) == true, "write bits32");
  check(ws.serializeInt(w(d.intSmall), -100, 100) == true, "write intSmall");
  check(ws.serializeInt(w(d.intFull), -2147483648, 2147483647) == true, "write intFull");
  check(ws.serializeBool(w(d.flag)) == true, "write flag");
  check(ws.serializeFloat(w(d.floatValue)) == true, "write floatValue");
  check(ws.serializeCompressedFloat(w(d.compressedFloatValue), 0.0, 10.0, 0.01) == true, "write compressedFloatValue");
  check(ws.serializeDouble(w(d.doubleValue)) == true, "write doubleValue");
  check(ws.serializeUint8(w(d.uint8Value)) == true, "write uint8Value");
  check(ws.serializeUint16(w(d.uint16Value)) == true, "write uint16Value");
  check(ws.serializeUint32(w(d.uint32Value)) == true, "write uint32Value");
  check(ws.serializeUint64(w(d.uint64Value)) == true, "write uint64Value");
  check(ws.serializeIntRelative(relativeBase, w(d.relativeNear)) == true, "write relativeNear");
  check(ws.serializeIntRelative(relativeBase, w(d.relativeFar)) == true, "write relativeFar");
  check(ws.serializeAlign() == true, "write align1");
  local goldenBytesField = blob(7);
  for (local i = 0; i < 7; i++) goldenBytesField[i] = goldenWireBytes[45 + i];
  check(ws.serializeBytes(goldenBytesField) == true, "write bytes");
  check(ws.serializeString(w(d.str), 16) == true, "write str");
  check(ws.serializeString(w(d.text), 8) == true, "write text");
  check(ws.serializeAlign() == true, "write align2");
  check(ws.serializeFixed64(w(d.fixedQ8_8), 8, 8, -100, 100) == true, "write fixedQ8_8");
  check(ws.serializeFixed64(w(d.fixedQ16_16), 16, 16, -2000, 2000) == true, "write fixedQ16_16");
  check(ws.serializeFixed64(w(d.fixedQ48_16), 48, 16, -100000, 100000) == true, "write fixedQ48_16");
  check(ws.serializeFixed64(w(d.fixedQ16_16Unsigned), 16, 16, 0, 30000) == true, "write fixedQ16_16Unsigned");
  check(ws.serializeAlign() == true, "write align3");
  check(ws.serializeFixed128(w(d.fixedQ112_16Wide), 112, 16, -144115188075855872, 144115188075855872) == true, "write fixedQ112_16Wide");
  check(ws.serializeFixed128(w(d.fixedQ64_64Wide), 64, 64, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF) == true, "write fixedQ64_64Wide");
  check(ws.serializeEnd() == true, "write end");
  ws.flush();
  check(ws.bytesProcessed() == GOLDEN_BYTES, "re-write produced " + ws.bytesProcessed() + " bytes");
  local got = ws.data();
  check(got.len() == GOLDEN_BYTES, "re-write length " + got.len());
  for (local i = 0; i < GOLDEN_BYTES; i++) check(got[i] == goldenWireBytes[i], "re-write byte " + i);
  check(d.text == "\xe7\xa2\x81\xe7\x9f\xb3", "the CJK string decoded to other bytes");

  // a byte past the message is trailing data, refused by the end
  local longer = blob(GOLDEN_BYTES + 1);
  for (local i = 0; i < GOLDEN_BYTES; i++) longer[i] = goldenWireBytes[i];
  local lr = serialize.ReadStream(longer);
  local refusedLonger = false;
  ::GOLDEN_SOFT = true;
  try { goldenWireRead(serialize, lr); } catch (e) { if (e == "GOLDEN_REFUSED") refusedLonger = true; else throw e; }
  ::GOLDEN_SOFT = false;
  check(refusedLonger && lr.error() == serialize.SerializeError.TrailingData, "a zero byte past the message was not refused as trailing_data");

  // every single-bit flip of the message, the final byte's padding included, is
  // refused or decodes differently: with the end, one value has one byte sequence
  for (local bit = 0; bit < 8 * GOLDEN_BYTES; bit++) {
    local byteIndex = bit >> 3;
    local mask = 1 << (bit & 7);
    local original = goldenWireBytes[byteIndex] & 0xff;
    goldenWireBytes[byteIndex] = original ^ mask;
    local refused = false;
    local differs = false;
    local err = null;
    ::GOLDEN_SOFT = true;
    try {
      local flipped = goldenWireRead(serialize, serialize.ReadStream(goldenWireBytes));
      differs = !sameGolden(d, flipped);
    } catch (e) {
      err = e;
    }
    ::GOLDEN_SOFT = false;
    goldenWireBytes[byteIndex] = original;
    if (err != null) {
      if (err == "GOLDEN_REFUSED") refused = true;
      else throw err;
    }
    check(refused || differs, "bit " + bit + " flip was neither refused nor decoded differently");
  }
}
