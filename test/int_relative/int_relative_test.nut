// TestSerializeIntRelative: the int_relative family (serialize-squirrel-int-relative).
// It runs every record of conformance/int_relative.txt as the runner must — the domain
// and ordering refusals, each bounded tier's payload range, the absolute tier's unsigned
// 32 bits, and reading past the end — printing the record count and failing unless it
// equals the file's count, plus serialize.go's TestIntRelativeValidation cases. A test
// throws to fail.

local check = function(cond, what) {
  if (!cond) throw "TestSerializeIntRelative: " + what;
};

local raises = function(fn, prefix, what) {
  local got = null;
  try { fn(); } catch (e) { got = e; }
  check(got != null, what + ": did not raise");
  check(typeof got == "string" && got.len() >= prefix.len() && got.slice(0, prefix.len()) == prefix,
    what + ": raised " + got + ", want " + prefix);
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  foreach (c in b) s += c.tochar();
  return s;
};

local blobFromHex = function(hex) {
  if (hex.len() == 0) return blob(0);
  local parts = split(hex, " ");
  local b = blob(parts.len());
  for (local i = 0; i < parts.len(); i++) b[i] = parts[i].tointeger(16);
  return b;
};

local blobEquals = function(a, b) {
  if (a.len() != b.len()) return false;
  for (local i = 0; i < a.len(); i++) if (a[i] != b[i]) return false;
  return true;
};

local trim = function(str) {
  local a = 0;
  local b = str.len();
  while (a < b && str[a] <= ' ') a++;
  while (b > a && str[b - 1] <= ' ') b--;
  return str.slice(a, b);
};

// parse conformance/int_relative.txt into a list of record tables, each with
// operation, name, previous, bytes (a blob), expect ("refused" or a number),
// consumed (bits, or null) and writer ("canonical" or null).
local parseRecords = function(text) {
  local recs = [];
  local cur = null;
  foreach (line in split(text, "\n")) {
    if (line.len() == 0) {
      if (cur != null) { recs.append(cur); cur = null; }
      continue;
    }
    if (line.slice(0, 1) == "#") continue;
    local sp = line.find(" ");
    local k = sp == null ? line : line.slice(0, sp);
    local v = sp == null ? "" : line.slice(sp + 1);
    if (k == "param") {
      local eq = v.find("=");
      local pname = trim(v.slice(0, eq));
      local pval = trim(v.slice(eq + 1));
      if (pname == "previous") {
        if (cur == null) cur = {};
        cur.previous <- pval.tointeger();
      }
    } else {
      if (cur == null) cur = {};
      if (k == "bytes") cur.bytes <- blobFromHex(v);
      else if (k == "expect") {
        // format 2.0: `expect refused <reason>`, or `expect value = <n>`
        if (v.len() >= 8 && v.slice(0, 8) == "refused ") { cur.expect <- null; cur.reason <- trim(v.slice(8)); }
        else cur.expect <- trim(v.slice(v.find("=") + 1)).tointeger();
      }
      else if (k == "consumed") cur.consumed <- v.tointeger();
      else if (k == "writer") cur.writer <- (v == "canonical");
      else cur[k] <- v;
    }
  }
  if (cur != null) recs.append(cur);
  return recs;
};

function TestSerializeIntRelative() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  // ---- the conformance corpus ----
  local text = readText(root + "/conformance/int_relative.txt");
  local recs = parseRecords(text);

  local opLines = 0;
  foreach (line in split(text, "\n")) {
    if (line.find("operation ") == 0) opLines++;
  }
  check(recs.len() == opLines, "parsed " + recs.len() + " records, the file has " + opLines + " operation lines");
  print("int_relative conformance records: " + recs.len() + "\n");

  foreach (rec in recs) {
    check(rec.operation == "int_relative", rec.name + ": operation " + rec.operation);
    local previous = rec.previous;
    local bytes = rec.bytes;
    local rs = serialize.ReadStream(bytes);
    local holder = { value = -12345 };
    local ok = rs.serializeIntRelative(previous, holder);

    if (rec.expect == null) {
      // refused: the read fails, the destination is untouched, the stream is terminal
      check(ok == false, rec.name + ": a refused read succeeded");
      check(rs.error() == rec.reason, rec.name + ": refused as " + rs.error() + ", the corpus states " + rec.reason);
      check(holder.value == -12345, rec.name + ": a refused read wrote the destination to " + holder.value);
      local h2 = { value = 999 };
      local ok2 = rs.serializeIntRelative(previous, h2);
      check(ok2 == false, rec.name + ": the stream is not terminal after a refusal");
      check(h2.value == 999, rec.name + ": a terminal call wrote the destination to " + h2.value);
    } else {
      check(ok == true, rec.name + ": an accepted read failed with error " + rs.error());
      check(holder.value == rec.expect, rec.name + ": decoded " + holder.value + ", want " + rec.expect);
      check(rs.bitsProcessed() == rec.consumed,
        rec.name + ": consumed " + rs.bitsProcessed() + " bits, want " + rec.consumed);
      if ("writer" in rec && rec.writer) {
        local ws = serialize.WriteStream(blob(8));
        local w = ws.serializeIntRelative(previous, { value = rec.expect });
        check(w == true, rec.name + ": the canonical write failed with error " + ws.error());
        ws.flush();
        local out = ws.data();
        check(blobEquals(out, bytes), rec.name + ": the canonical writer's bytes differ");
      }
    }
  }

  // ---- serialize.go's TestIntRelativeValidation (serialize_test.go) ----

  // the 32-bit fallback must reject a value that violates the previous < current
  // contract: six false flags then current = 50
  {
    local bw = serialize.BitWriter(blob(8));
    bw.writeBits(0, 6);
    bw.writeBits(50, 32);
    bw.flushBits();
    local rs = serialize.ReadStream(bw.data());
    local h = { value = -1 };
    check(rs.serializeIntRelative(100, h) == false, "fallback did not refuse previous < current");
    check(h.value == -1, "fallback wrote the destination to " + h.value);
    check(rs.error() == serialize.SerializeError.ValueOutOfRange, "fallback latched " + rs.error());
  }

  // a legitimate fallback round trip still succeeds
  {
    local ws = serialize.WriteStream(blob(8));
    local written = 100000;
    check(ws.serializeIntRelative(100, { value = written }) == true, "fallback write failed");
    ws.flush();
    local rs = serialize.ReadStream(ws.data());
    local h = { value = 0 };
    check(rs.serializeIntRelative(100, h) == true, "fallback read failed");
    check(h.value == written, "fallback read " + h.value + ", want " + written);
  }

  // the widest gap the domain allows: 0 to 2^31 - 1 takes the absolute tier
  {
    local ws = serialize.WriteStream(blob(8));
    local written = 2147483647;
    check(ws.serializeIntRelative(0, { value = written }) == true, "widest-gap write failed");
    ws.flush();
    local rs = serialize.ReadStream(ws.data());
    local h = { value = 0 };
    check(rs.serializeIntRelative(0, h) == true, "widest-gap read failed");
    check(h.value == written, "widest-gap read " + h.value + ", want " + written);
  }

  // reconstruction is checked in every tier: a previous at the top of the domain
  // leaves no room for any difference, so every tier refuses and leaves the
  // destination unwritten (STANDARD.md int_relative; one per tier below the
  // absolute one)
  {
    local diffs = [1, 5, 10, 100, 1000, 10000];
    foreach (diff in diffs) {
      local ws = serialize.WriteStream(blob(8));
      local written = 10 + diff;
      check(ws.serializeIntRelative(10, { value = written }) == true, "tier write failed for difference " + diff);
      ws.flush();
      local rs = serialize.ReadStream(ws.data());
      local h = { value = -1 };
      check(rs.serializeIntRelative(2147483647, h) == false, "difference " + diff + " past the domain top was accepted");
      check(h.value == -1, "difference " + diff + " past the domain top wrote " + h.value);
    }
  }

  // THE CANONICAL TIER (format 2.0, STANDARD.md int_relative): the absolute
  // tier carrying a current no more than 69914 above previous is a second
  // encoding of a value a bounded tier carries, refused as non_canonical; one
  // more is the first difference the absolute tier owns. The domain and order
  // come first (value_out_of_range), and the difference is formed in 64 bits,
  // so a current past the domain is out of range whatever its difference.
  // Reversed witness: the format 1.1 reader accepted every absolute current
  // above previous.
  {
    local absolute = function(previous, current) {
      local bw = serialize.BitWriter(blob(8));
      bw.writeBits(0, 6);
      bw.writeBits(current, 32);
      bw.flushBits();
      local rs = serialize.ReadStream(bw.data());
      local h = { value = -1 };
      local ok = rs.serializeIntRelative(previous, h);
      return { ok = ok, error = rs.error(), value = h.value };
    };
    foreach (diff in [1, 2, 6, 7, 69913, 69914]) {
      local r = absolute(1000, 1000 + diff);
      check(!r.ok && r.error == serialize.SerializeError.NonCanonical && r.value == -1,
        "an absolute difference of " + diff + " was " + (r.ok ? "accepted" : "refused as " + r.error));
    }
    local first = absolute(1000, 1000 + 69915);
    check(first.ok && first.value == 1000 + 69915, "the first absolute difference, 69915, was refused as " + first.error);
    local top = absolute(2147483647 - 69915, 2147483647);
    check(top.ok && top.value == 2147483647, "the domain maximum from the last tier boundary was refused as " + top.error);
    local past = absolute(2147483647 - 5, 0x80000001);
    check(!past.ok && past.error == serialize.SerializeError.ValueOutOfRange,
      "a current past the domain with a small difference was " + (past.ok ? "accepted" : "refused as " + past.error));
    local below = absolute(1000, 999);
    check(!below.ok && below.error == serialize.SerializeError.ValueOutOfRange, "a current below previous was refused as " + below.error);
  }

  // a current past the domain is write misuse on write and measure: a 64-bit
  // SQInteger holds it, and its 32 bits would be refused by the reader. It
  // traps and latches nothing (IMPLEMENTING.md U6, U9).
  // Reversed witness: the format 1.1 writer wrote 0x80000000.
  foreach (stream in [serialize.WriteStream(blob(8)), serialize.MeasureStream()]) {
    raises(function() { stream.serializeIntRelative(100, { value = 0x80000000 }); }, "serialize: write misuse: ", "a current past the domain");
    check(stream.error() == null && stream.bitsProcessed() == 0,
      "a current past the domain latched " + stream.error() + " after " + stream.bitsProcessed() + " bits");
  }

  // a previous outside the int_relative domain is API misuse on every stream
  {
    local v = { value = 5 };
    raises(function() { serialize.WriteStream(blob(8)).serializeIntRelative(-1, v); },
      "serialize: int relative previous must be in [0,2147483647]", "write previous outside the domain");
    // on read a previous outside the domain refuses ValueOutOfRange, the
    // holder untouched, never a raise (IMPLEMENTING.md U7, U16; reversed
    // witness: the 2.1.0 port raised)
    foreach (prev in [ -1, 0x80000000 ]) {
      local h = { value = 0 };
      local rs = serialize.ReadStream(blob(8));
      check(rs.serializeIntRelative(prev, h) == false && rs.error() == "value_out_of_range" && h.value == 0 && rs.bitsProcessed() == 0,
        "read previous " + prev + " outside the domain did not refuse value_out_of_range untouched");
    }
    raises(function() { serialize.MeasureStream().serializeIntRelative(-1, v); },
      "serialize: int relative previous must be in [0,2147483647]", "measure previous outside the domain");
  }
}
