// TestSerializeFloat: the float and double arms of serialize-squirrel-float
// (DESIGN.md (e), (g), (h); the card's TEST line). It runs every record of
// conformance/float.txt and double.txt comparing BIT PATTERNS, never values
// (STANDARD.md float and double, "Conformance vectors ... must compare bit
// patterns, not values"), prints the record count per file and fails unless it
// equals the file's count; and it checks fround against a table of edges
// computed by Go's float32() (pasted in as literals, never computed here): ties
// both ways, the largest subnormal and smallest normal, MaxFloat32 and
// MaxFloat32 + half an ulp, negative zero, and 64 seeded random doubles. A
// test passes by returning and fails by throwing.

local check = function(cond, what) {
  if (!cond) throw "TestSerializeFloat: " + what;
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  foreach (c in b) s += c.tochar();
  return s;
};

local parseHex = function(s) {
  s = s.slice(2);
  local v = 0;
  foreach (ch in s) {
    local d;
    if (ch >= '0' && ch <= '9') d = ch - '0';
    else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
    else throw "bad hex " + s;
    v = (v << 4) | d;
  }
  return v;
};

// parseVectors(): parse a conformance file into records. Each record is a
// table: op, name, bytes (an array), expect (a 32- or 64-bit integer, or null
// when the record expects refusal), consumed, writer (bool).
local parseVectors = function(root, name) {
  local lines = split(readText(root + "/conformance/" + name + ".txt"), "\n");
  local records = [];
  local cur = null;
  foreach (line in lines) {
    if (line.len() == 0 || line.slice(0, 1) == "#") {
      if (line.len() == 0 && cur != null) { records.append(cur); cur = null; }
      continue;
    }
    local words = split(line, " ");
    if (cur == null) cur = { op = "", name = "", bytes = [], expect = null, consumed = 0, writer = false };
    if (words[0] == "operation") cur.op = words[1];
    else if (words[0] == "name") cur.name = words[1];
    else if (words[0] == "bytes") {
      cur.bytes = [];
      for (local i = 1; i < words.len(); i++) cur.bytes.append(parseHex("0x" + words[i]));
    }
    else if (words[0] == "expect") {
      if (words[1] == "refused") cur.expect = null;
      else cur.expect = parseHex(words[3]);
    }
    else if (words[0] == "consumed") cur.consumed = words[1].tointeger();
    else if (words[0] == "writer") cur.writer = (words[1] == "canonical");
  }
  if (cur != null) records.append(cur);
  return records;
};

// the fround edge table, computed by Go's float32() (a tiny Go program in
// .ref; pasted here as literals). Each line: the double's 64 bits, then the
// float32 result's 32 bits.
local froundTable = [
  [0x380fffffc0000000, 0x007fffff],
  [0x3810000000000000, 0x00800000],
  [0x47efffffe0000000, 0x7f7fffff],
  [0x8000000000000000, 0x80000000],
  [0x47f0000000000000, 0x7f800000],
  [0x47effffff0000000, 0x7f800000],
  [0x47effffff0000000, 0x7f800000],
  [0x47efffffe8000000, 0x7f7fffff],
  [0x3ff0000010000000, 0x3f800000],
  [0x3ff0000030000000, 0x3f800002],
  [0x400921fb70000000, 0x40490fdc],
  [0x380fffff60000000, 0x007ffffe],
  [0x3810000030000000, 0x00800002],
  [0x47efffffd0000000, 0x7f7ffffe],
  [0x36a8000000000000, 0x00000002],
  [0x3fe0000010000000, 0x3f000000],
  [0x3feffffff0000000, 0x3f800000],
  [0x3ff0000010000000, 0x3f800000],
  [0x400921fb50000000, 0x40490fda],
  [0x380fffff20000000, 0x007ffffc],
  [0x3810000010000000, 0x00800000],
  [0x47efffffb0000000, 0x7f7ffffe],
  [0x3690000000000000, 0x00000000],
  [0x3fdffffff0000000, 0x3f000000],
  [0x3690000000000000, 0x00000000],
  [0x42b77b898c86228e, 0x55bbdc4c],
  [0xc1d29662f284b2e9, 0xce94b318],
  [0x3c406d2c54965bab, 0x22036963],
  [0xc0e11f3ca2b2e37c, 0xc708f9e5],
  [0x3c8e2cbda8ec0c0f, 0x247165ed],
  [0xbc0203b7d8991602, 0xa0101dbf],
  [0x423647a4b31feea2, 0x51b23d26],
  [0xbfe1455237298f3f, 0xbf0a2a92],
  [0xbf92cf7733bf2810, 0xbc967bba],
  [0x3dcacccdc3b73bbd, 0x2e56666e],
  [0xc2620b6d87c8a8a9, 0xd3105b6c],
  [0x3dc403b07443085f, 0x2e201d84],
  [0x4171523f6ed2f6c1, 0x4b8a91fb],
  [0xbefbd6ba7097f4d2, 0xb7deb5d4],
  [0x3f7ed8696a709b5f, 0x3bf6c34b],
  [0xbf3038896dd9124f, 0xb981c44b],
  [0x4040ee1c92f9f1ac, 0x420770e5],
  [0x41a6b40ecc7931e5, 0x4d35a076],
  [0xbc865b86e7d32bce, 0xa432dc37],
  [0x40962d466b60a86b, 0x44b16a33],
  [0xbe4ebffe10bf62a5, 0xb275fff1],
  [0xc0982d142c85aebc, 0xc4c168a1],
  [0xc0e83b0ee720136a, 0xc741d877],
  [0xbd7df301a05a10f7, 0xabef980d],
  [0xbceb373c61a16379, 0xa759b9e3],
  [0x4269bed1a0ba4e6c, 0x534df68d],
  [0x41c26509b1ac68be, 0x4e13284e],
  [0xc08725564a4c2e95, 0xc4392ab2],
  [0x3e63bcd2639b31bc, 0x331de693],
  [0x3e71430c36b094aa, 0x338a1862],
  [0x402c6bffa0ced520, 0x41635ffd],
  [0x3c82d033ad28566e, 0x2416819d],
  [0x42918ca6294a8c38, 0x548c6531],
  [0xbcce4c317948676f, 0xa672618c],
  [0x3e347072c03cba39, 0x31a38396],
  [0xc33c7ceab5a8d5ee, 0xd9e3e756],
  [0xbceaeceb650f54df, 0xa757675b],
  [0xbc105f676f14195b, 0xa082fb3b],
  [0x3cf85347bb11739c, 0x27c29a3e],
  [0xbdc16e5859da73dd, 0xae0b72c3],
  [0xc112f208a7fa0f26, 0xc8979045],
  [0x3d8e1c20e042a11e, 0x2c70e107],
  [0xbcf413982859eafb, 0xa7a09cc1],
  [0xc333e1749b101e6b, 0xd99f0ba5],
  [0xbfa7f1049979dfbe, 0xbd3f8825],
  [0x41e6703ff61da14b, 0x4f338200],
  [0x3c6d0febaa0b45d0, 0x23687f5d],
  [0xbd3aa491598d62f0, 0xa9d5248b],
  [0xc356bc794cc769b7, 0xdab5e3ca],
  [0x43a0a72037621603, 0x5d053902],
  [0x43305cf54d966c1d, 0x5982e7aa],
  [0x3cc9e05eaeee5f54, 0x264f02f5],
  [0x40f83b99f5439eb1, 0x47c1dcd0],
  [0x3cbc3e5538268359, 0x25e1f2aa],
  [0x3eb12aa4b0049d37, 0x35895526],
  [0xbd72b241b503962a, 0xab95920e],
  [0xc3fc17d633a58931, 0xdfe0beb2],
  [0xbd9adfde7eb2d910, 0xacd6fef4],
  [0x40b91ff451b400b0, 0x45c8ffa3],
  [0xbfed66cc1003b469, 0xbf6b3661],
  [0xc08e7b51c9dc2a19, 0xc473da8e],
  [0x4145b38abdab51fe, 0x4a2d9c56],
  [0x3bed20102f5cf2c5, 0x1f690081],
  [0xc14d26c38a918517, 0xca69361c],
];

function TestSerializeFloat() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);
  // the float family module, loaded the way the closed loader does
  // (DESIGN.md (f)): vargv[0] is the exports table, vargv[1] the require
  local m = {};
  local fn = loadfile(root + "/src/serialize_float.nut", true).bindenv(::getroottable());
  fn(m, function(name, who = null) { return null; });
  local fround = m.fround;
  local float32Bits = m.float32Bits;
  local float32FromBits = m.float32FromBits;

  // the fround edge table
  check(froundTable.len() == 89, "fround table has " + froundTable.len() + " rows, want 89");
  foreach (row in froundTable) {
    local bits = row[0];
    local want = row[1];
    local v = casti2f(bits);
    local got = float32Bits(fround(v));
    if (got != want) throw "TestSerializeFloat: fround 0x" + format("%016x", bits) +
      " = 0x" + format("%08x", got) + ", want 0x" + format("%08x", want);
  }

  // the conformance files, comparing bit patterns
  local runFile = function(file, bitsOf, serializeRead, serializeWrite, width) {
    local records = parseVectors(root, file);
    print(file + " " + records.len() + " records\n");
    local expectCount = 0;
    local lines = split(readText(root + "/conformance/" + file + ".txt"), "\n");
    foreach (line in lines) if (line.len() >= 9 && line.slice(0, 9) == "operation") expectCount++;
    check(records.len() == expectCount, file + ": processed " + records.len() + ", file has " + expectCount);

    foreach (rec in records) {
      local b = blob(rec.bytes.len());
      for (local i = 0; i < rec.bytes.len(); i++) b[i] = rec.bytes[i];
      if (rec.expect == null) {
        // expect refused: reading past the end must fail, latch Overflow, and
        // leave the holder untouched (STANDARD.md Reader Obligations)
        local rs = serialize.ReadStream(b);
        local holder = { value = 12345 };
        check(serializeRead(rs, holder) == false, file + "/" + rec.name + " refused read did not fail");
        check(rs.error() == serialize.SerializeError.Overflow, file + "/" + rec.name + " refused read latched " + rs.error());
        check(holder.value == 12345, file + "/" + rec.name + " refused read touched the holder");
      } else {
        // write: writer canonical, the bytes must match exactly
        local ws = serialize.WriteStream(blob(8));
        local val = (width == 4) ? float32FromBits(rec.expect) : casti2f(rec.expect);
        check(serializeWrite(ws, { value = val }), file + "/" + rec.name + " write failed");
        ws.flush();
        local data = ws.data();
        check(data.len() == rec.bytes.len(), file + "/" + rec.name + " wrote " + data.len() + " bytes");
        for (local i = 0; i < rec.bytes.len(); i++)
          check(data[i] == rec.bytes[i], file + "/" + rec.name + " byte " + i + " = " + data[i] + ", want " + rec.bytes[i]);
        // read: the holder must hold the exact pattern
        local rs = serialize.ReadStream(b);
        local holder = { value = 0 };
        check(serializeRead(rs, holder), file + "/" + rec.name + " read failed");
        local got = bitsOf(holder.value);
        check(got == rec.expect, file + "/" + rec.name + " read pattern 0x" + format("%x", got) + ", want 0x" + format("%x", rec.expect));
        check(rs.bitsProcessed() == rec.consumed, file + "/" + rec.name + " consumed " + rs.bitsProcessed() + ", want " + rec.consumed);
      }
    }
  };

  runFile("float", float32Bits,
    function(rs, h) { return rs.serializeFloat(h); },
    function(ws, h) { return ws.serializeFloat(h); }, 4);

  runFile("double",
    function(v) { return castf2i(v); },
    function(rs, h) { return rs.serializeDouble(h); },
    function(ws, h) { return ws.serializeDouble(h); }, 8);
}
