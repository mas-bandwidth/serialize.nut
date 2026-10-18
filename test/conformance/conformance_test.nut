// TestConformanceCorpus: serialize-squirrel-conformance (DESIGN.md (i), the
// runner). It discovers every conformance/*.txt (never a fixed list), runs
// every record as the runner must (STANDARD.md, "What a runner checks"; "The
// vector format"), and fails unless every record ran. A test passes by
// returning and fails by throwing (DESIGN.md (i)).

local check = function(cond, what) {
  if (!cond) throw "TestConformanceCorpus: " + what;
};

local MIN64 = 0x8000000000000000;

// --- 128-bit number parsing (for the vectors' values; never a codec
// reimplementation) -----------------------------------------------------------
local ucmp = function(a, b) {
  local ax = a[1] ^ MIN64;
  local ay = b[1] ^ MIN64;
  if (ax < ay) return -1;
  if (ax > ay) return 1;
  local lx = a[0] ^ MIN64;
  local ly = b[0] ^ MIN64;
  if (lx < ly) return -1;
  if (lx > ly) return 1;
  return 0;
};

local usub = function(a, b) {
  local lo = a[0] - b[0];
  local br = ucmp([a[0], 0], [b[0], 0]) < 0 ? 1 : 0;
  local hi = a[1] - b[1] - br;
  return [lo, hi];
};

local uadd = function(a, b) {
  local lo = a[0] + b[0];
  local ca = ucmp([a[0], 0], [lo, 0]) > 0 ? 1 : 0;
  local hi = a[1] + b[1] + ca;
  return [lo, hi];
};

local lsh = function(x, n) {
  if (n == 0) return x;
  if (n < 64) return [(x[0] << n), ((x[1] << n) | (x[0] >>> (64 - n)))];
  return [0, x[0] << (n - 64)];
};

local mul10 = function(x) { return uadd(lsh(x, 3), lsh(x, 1)); };
local neg128 = function(x) { return usub([0, 0], x); };

local hexDig = function(c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw "bad hex digit " + c;
};

local hexVal16 = function(h) {
  local v = 0;
  foreach (c in h) v = (v << 4) | hexDig(c);
  return v;
};

local hexTo128 = function(s) {
  while ((s.len() % 16) != 0) s = "0" + s;
  local lo = hexVal16(s.slice(s.len() - 16));
  local hi = s.len() > 16 ? hexVal16(s.slice(0, s.len() - 16)) : 0;
  return [lo, hi];
};

local parseDec = function(s) {
  local num = [0, 0];
  foreach (c in s) {
    local d = c - '0';
    num = uadd(mul10(num), [d, 0]);
  }
  return num;
};

local parseNumber = function(tok) {
  local t = tok;
  local neg = false;
  if (t.len() > 0 && t.slice(0, 1) == "-") { neg = true; t = t.slice(1); }
  local v = (t.len() >= 2 && t.slice(0, 2) == "0x") ? hexTo128(t.slice(2)) : parseDec(t);
  if (neg) v = neg128(v);
  return v;
};

// --- text and bytes helpers --------------------------------------------------
local strip = function(s) {
  local a = 0, b = s.len();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
  return s.slice(a, b);
};

local tokens = function(line) {
  local out = [];
  local cur = "";
  foreach (ch in line) {
    local c = ch & 0xff;
    if (c == 32 || c == 9 || c == 13) {
      if (cur.len() > 0) { out.append(cur); cur = ""; }
    } else cur += c.tochar();
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

local blobOfHexs = function(hexs) {
  local words = [];
  foreach (w in split(hexs, " ")) if (w.len() > 0) words.append(w);
  local b = blob(words.len());
  for (local i = 0; i < words.len(); i++) b[i] = (hexDig(words[i][0]) << 4) | hexDig(words[i][1]);
  return b;
};

local blobOfValues = function(vals) {
  local b = blob(vals.len());
  for (local i = 0; i < vals.len(); i++) {
    check(vals[i].len() == 2, "a byte value must be two hex digits, got " + vals[i]);
    b[i] = (hexDig(vals[i][0]) << 4) | hexDig(vals[i][1]);
  }
  return b;
};

local hexValue = function(tok) {
  local v = 0;
  foreach (c in tok) v = (v << 4) | hexDig(c);
  return v;
};

local sameBytes = function(got, want, what) {
  check(got.len() == want.len(), what + ": length " + got.len() + ", want " + want.len());
  for (local i = 0; i < want.len(); i++) {
    check((got[i] & 0xff) == (want[i] & 0xff), what + ": byte " + i);
  }
};

local sameArray = function(got, want, what) {
  check(got.len() == want.len(), what + ": length " + got.len() + ", want " + want.len());
  for (local i = 0; i < want.len(); i++) check(got[i] == want[i], what + ": item " + i);
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

local encodeCodepoint = function(cp) {
  local out = [];
  if (cp < 0x80) out.append(cp);
  else if (cp < 0x800) { out.append(0xc0 | (cp >>> 6)); out.append(0x80 | (cp & 0x3f)); }
  else if (cp < 0x10000) { out.append(0xe0 | (cp >>> 12)); out.append(0x80 | ((cp >>> 6) & 0x3f)); out.append(0x80 | (cp & 0x3f)); }
  else { out.append(0xf0 | (cp >>> 18)); out.append(0x80 | ((cp >>> 12) & 0x3f)); out.append(0x80 | ((cp >>> 6) & 0x3f)); out.append(0x80 | (cp & 0x3f)); }
  return out;
};

local stringFromCodepoints = function(cps) {
  local bytes = [];
  foreach (cp in cps) foreach (b in encodeCodepoint(cp)) bytes.append(b);
  return stringFromBytes(bytes);
};

local utf8Codepoints = function(s) {
  local b = bytesOfString(s);
  local out = [];
  local i = 0;
  while (i < b.len()) {
    local c = b[i];
    local cp = 0xfffd;
    local n = 1;
    if (c < 0x80) cp = c;
    else if (c >= 0xc2 && c <= 0xdf && i + 1 < b.len() && (b[i + 1] & 0xc0) == 0x80) {
      cp = ((c & 0x1f) << 6) | (b[i + 1] & 0x3f); n = 2;
    } else if (c >= 0xe0 && c <= 0xef && i + 2 < b.len() &&
      (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80) {
      cp = ((c & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f); n = 3;
    } else if (c >= 0xf0 && c <= 0xf4 && i + 3 < b.len() &&
      (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80 && (b[i + 3] & 0xc0) == 0x80) {
      cp = ((c & 0x07) << 18) | ((b[i + 1] & 0x3f) << 12) | ((b[i + 2] & 0x3f) << 6) | (b[i + 3] & 0x3f); n = 4;
    }
    out.append(cp);
    i += n;
  }
  return out;
};

local unitsFromString = function(s) {
  local out = [];
  foreach (cp in utf8Codepoints(s)) {
    if (cp >= 0x10000) {
      local v = cp - 0x10000;
      out.append(0xd800 + (v >>> 10));
      out.append(0xdc00 + (v & 0x3ff));
    } else out.append(cp);
  }
  return out;
};

local stringFromUnits = function(units) {
  local cps = [];
  local i = 0;
  while (i < units.len()) {
    local u = units[i];
    if (u >= 0xd800 && u <= 0xdbff) {
      check(i + 1 < units.len(), "stringFromUnits: a high surrogate with no low half");
      local low = units[i + 1];
      check(low >= 0xdc00 && low <= 0xdfff, "stringFromUnits: a high surrogate with no low half");
      cps.append(0x10000 + ((u - 0xd800) << 10) + (low - 0xdc00));
      i += 2;
    } else { cps.append(u); i++; }
  }
  return stringFromCodepoints(cps);
};

// --- the vector parser --------------------------------------------------------
local parseRecords = function(text) {
  local recs = [];
  local rec = null;
  foreach (line in split(text, "\n")) {
    line = strip(line);
    if (line.len() == 0) {
      if (rec != null && ("operation" in rec)) recs.append(rec);
      rec = null;
      continue;
    }
    if (line[0] == '#') continue;
    if (rec == null) rec = { params = {}, steps = {} };
    local t = tokens(line);
    if (t[0] == "operation") rec.operation <- t[1];
    else if (t[0] == "name") rec.name <- t[1];
    else if (t[0] == "param") {
      if (t[1] == "step") rec.steps[rec.steps.len()] <- t.slice(2);
      else rec.params[t[1]] <- parseNumber(t[3]);
    } else if (t[0] == "bytes") {
      local hexs = "";
      for (local i = 1; i < t.len(); i++) { if (i > 1) hexs += " "; hexs += t[i]; }
      rec.bytes <- hexs;
    } else if (t[0] == "expect") {
      if (t[1] == "refused") rec.expect <- "refused";
      else if (t[1] == "bits") { rec.expect <- "bits"; rec.bitpattern <- parseNumber(t[3]); }
      else {
        rec.expect <- "value";
        local vals = [];
        for (local i = 3; i < t.len(); i++) vals.append(t[i]);
        rec.values <- vals;
      }
    } else if (t[0] == "consumed") rec.consumed <- t[1].tointeger();
    else if (t[0] == "writer") rec.writer <- t[1];
    else if (t[0] == "measure_at_least") rec.measure_at_least <- t[1].tointeger();
    else throw "unknown record key: " + line;
  }
  if (rec != null && ("operation" in rec)) recs.append(rec);
  return recs;
};

local countOps = function(text) {
  local n = 0;
  foreach (line in split(text, "\n")) {
    local s = strip(line);
    if (s.len() >= 9 && s.slice(0, 9) == "operation") n++;
  }
  return n;
};

// --- discover the corpus directory (never a fixed list): the pinned
// interpreter has no directory-listing builtin, so list through system() into a
// scratch file and read it. A file added to conformance/ is picked up with no
// edit here.
local discoverCorpusFiles = function(root) {
  local scratch = root + "/build/conformance-listing.txt";
  local rc = system("ls -1 " + root + "/conformance > " + scratch);
  check(rc == 0, "could not list the corpus directory");
  local names = [];
  foreach (line in split(strip(readText(scratch)), "\n")) {
    if (line.len() == 0) continue;
    if (line.len() < 4 || line.slice(line.len() - 4) != ".txt") continue;
    names.append(line);
  }
  names.sort();
  check(names.len() > 0, "empty corpus directory");
  return names;
};

// --- the single-operation runner ----------------------------------------------
// openStream(op, stream, holder): call the read method for op, returning the
// boolean result.
local doRead = function(op, stream, h) {
  if (op == "int") return stream.serializeInt(h, h.min, h.max);
  if (op == "int64") return stream.serializeInt64(h, h.min, h.max);
  if (op == "int128") return stream.serializeInt128(h, h.min, h.max);
  if (op == "uint128") return stream.serializeUint128(h);
  if (op == "int_relative") return stream.serializeIntRelative(h.prev, h);
  if (op == "bool") return stream.serializeBool(h);
  if (op == "float") return stream.serializeFloat(h);
  if (op == "double") return stream.serializeDouble(h);
  if (op == "bytes") return stream.serializeBytes(h.dest);
  if (op == "string") return stream.serializeString(h, h.buffer_size);
  if (op == "wstring") return stream.serializeWideString(h, h.buffer_size);
  return null;
};

// The runner for a record of the operations this port implements. Returns
// { handled = true } when it ran; the autonomy of the run is checked here.
local runSingle = function(serialize, rec) {
  local op = rec.operation;
  if (op == "bits" || op == "bits64" || op == "uint8" || op == "uint16" ||
      op == "uint32" || op == "uint64" || op == "align" || op == "fixed64" ||
      op == "fixed128" || op == "compressed_float" || op == "compressed_float_precomputed" ||
      op == "sequence" || op == "object") {
    return { handled = false };
  }

  local is128 = (op == "int128" || op == "uint128");
  local bytes = blobOfHexs(rec.bytes);
  local rs = serialize.ReadStream(bytes);
  local sentinel = is128 ? [0x1111222233334444, 0x5555666677778888] : 123456789;
  local h = { value = sentinel };
  if (op == "int" || op == "int64") { h.min <- rec.params.min[0]; h.max <- rec.params.max[0]; }
  else if (op == "int128") { h.min <- rec.params.min; h.max <- rec.params.max; }
  else if (op == "int_relative") h.prev <- rec.params.previous[0];
  else if (op == "bytes") {
    local count = ("count" in rec.params) ? rec.params.count[0] : 0;
    h.dest <- blob(count);
    for (local i = 0; i < count; i++) h.dest[i] = 0xa5;
  }
  else if (op == "string" || op == "wstring") h.buffer_size <- ("buffer_size" in rec.params) ? rec.params.buffer_size[0] : 0;

  local prec = ("preceding_bits" in rec.params) ? rec.params.preceding_bits[0] : 0;
  if (prec > 0) {
    check(rs._room(prec), rec.name + ": preceding bits do not fit the data");
    rs._take(prec);
  }

  local ok = doRead(op, rs, h);

  if (rec.expect == "refused") {
    check(ok == false, rec.name + ": refused read returned true");
    check(rs.error() != null, rec.name + ": no error latched");
    if (op != "bytes") {
      check(rs.error() == serialize.SerializeError.ValueOutOfRange ||
            rs.error() == serialize.SerializeError.Align ||
            rs.error() == serialize.SerializeError.Overflow,
        rec.name + ": latched a non-refusal " + rs.error());
    }
    // the stream is terminal: a further read of the same record fails, consumes
    // no bits, and writes nothing
    local before = rs.bitsProcessed();
    local h2 = { value = sentinel };
    if (op == "int" || op == "int64") { h2.min <- h.min; h2.max <- h.max; }
    else if (op == "int128") { h2.min <- h.min; h2.max <- h.max; }
    else if (op == "int_relative") h2.prev <- h.prev;
    else if (op == "bytes") h2.dest <- h.dest;
    else if (op == "string" || op == "wstring") h2.buffer_size <- h.buffer_size;
    local ok2 = doRead(op, rs, h2);
    check(ok2 == false, rec.name + ": the stream is not terminal");
    check(rs.bitsProcessed() == before, rec.name + ": a terminal read consumed bits");
    return { handled = true };
  }

  check(ok == true, rec.name + ": accepted read returned false (" + rs.error() + ")");
  check(rs.error() == null, rec.name + ": accepted read latched " + rs.error());
  check(rs.bitsProcessed() == rec.consumed, rec.name + ": consumed " + rs.bitsProcessed() + ", want " + rec.consumed);

  // value equality
  if (rec.expect == "bits") {
    // compare by round-tripping the decoded value through the library's own
    // writer (the reader widened the wire bits exactly, so writing the value
    // back must reproduce the record's bit pattern, byte for byte)
    local ws = serialize.WriteStream(blob(16));
    local wr;
    if (op == "float") wr = ws.serializeFloat({ value = h.value });
    else wr = ws.serializeDouble({ value = h.value });
    check(wr == true, rec.name + ": writer refused the decoded value");
    ws.flush();
    local got = ws.data();
    local n = (op == "float") ? 4 : 8;
    check(got.len() == n, rec.name + ": writer produced " + got.len() + " bytes");
    for (local i = 0; i < n; i++) {
      check((got[i] & 0xff) == ((rec.bitpattern[0] >> (8 * i)) & 0xff), rec.name + ": bit byte " + i);
    }
  } else {
    if (op == "int" || op == "int64") {
      local exp = rec.values[0];
      check(h.value == parseNumber(exp)[0], rec.name + ": decoded " + h.value + ", want " + exp);
    } else if (op == "int128" || op == "uint128") {
      local e = parseNumber(rec.values[0]);
      check(h.value[0] == e[0] && h.value[1] == e[1], rec.name + ": decoded 128 mismatch");
    } else if (op == "int_relative") {
      local exp = rec.values[0];
      check(h.value == parseNumber(exp)[0], rec.name + ": decoded " + h.value + ", want " + exp);
    } else if (op == "bytes") {
      sameBytes(h.dest, blobOfValues(rec.values), rec.name + ": bytes");
    } else if (op == "string") {
      sameArray(bytesOfString(h.value), bytesOfString(stringFromBytes(blobOfValues(rec.values))), rec.name + ": string");
    } else if (op == "wstring") {
      local units = [];
      foreach (t in rec.values) units.append(hexValue(t));
      sameArray(unitsFromString(h.value), units, rec.name + ": wstring");
    }
  }
  return { handled = true };
};

local blobToHex = function(b) {
  local hex = "0123456789ABCDEF";
  local o = "";
  for (local i = 0; i < b.len(); i++) {
    if (i > 0) o += " ";
    o += hex[(b[i] >> 4) & 15].tochar();
    o += hex[b[i] & 15].tochar();
  }
  return o;
};

// runWriter(serialize, rec): the writer-canonical leg of a record (STANDARD.md
// "What a runner checks": for a vector carrying writer = canonical, the bytes a
// writer emits for that value, byte for byte).
local runWriter = function(serialize, rec) {
  local op = rec.operation;
  local ws = serialize.WriteStream(blob(64));
  local prec = ("preceding_bits" in rec.params) ? rec.params.preceding_bits[0] : 0;
  if (prec > 0) {
    local bytes = blobOfHexs(rec.bytes);
    local value = 0;
    for (local i = 0; i < prec; i++) {
      if (((bytes[i >> 3] >>> (i & 7)) & 1)) value = value | (1 << i);
    }
    check(ws._room(prec), rec.name + ": preceding bits do not fit the writer");
    ws._put(value, prec);
  }
  local ok;
  if (op == "int" || op == "int64") {
    local v = parseNumber(rec.values[0])[0];
    if (op == "int") ok = ws.serializeInt({ value = v }, rec.params.min[0], rec.params.max[0]);
    else ok = ws.serializeInt64({ value = v }, rec.params.min[0], rec.params.max[0]);
  } else if (op == "int128") {
    local e = parseNumber(rec.values[0]);
    ok = ws.serializeInt128({ value = e }, rec.params.min, rec.params.max);
  } else if (op == "uint128") {
    local e = parseNumber(rec.values[0]);
    ok = ws.serializeUint128({ value = e });
  } else if (op == "int_relative") {
    local v = parseNumber(rec.values[0])[0];
    ok = ws.serializeIntRelative(rec.params.previous[0], { value = v });
  } else if (op == "bytes") {
    ok = ws.serializeBytes(blobOfValues(rec.values));
  } else if (op == "string") {
    ok = ws.serializeString({ value = stringFromBytes(blobOfValues(rec.values)) }, ("buffer_size" in rec.params) ? rec.params.buffer_size[0] : 0);
  } else if (op == "wstring") {
    local units = [];
    foreach (t in rec.values) units.append(hexValue(t));
    ok = ws.serializeWideString({ value = stringFromUnits(units) }, ("buffer_size" in rec.params) ? rec.params.buffer_size[0] : 0);
  } else if (op == "float") {
    local rs = serialize.ReadStream(blobOfHexs(rec.bytes));
    local h = { value = 0.0 };
    check(rs.serializeFloat(h) == true && rs.bitsProcessed() == rec.consumed, rec.name + ": float canonical read failed");
    ok = ws.serializeFloat({ value = h.value });
  } else if (op == "double") {
    local rs = serialize.ReadStream(blobOfHexs(rec.bytes));
    local h = { value = 0.0 };
    check(rs.serializeDouble(h) == true && rs.bitsProcessed() == rec.consumed, rec.name + ": double canonical read failed");
    ok = ws.serializeDouble({ value = h.value });
  } else {
    return;
  }
  check(ok == true, rec.name + ": the writer refused its canonical value");
  check(ws.error() == null, rec.name + ": the writer latched " + ws.error());
  ws.flush();
  check(blobToHex(ws.data()) == rec.bytes, rec.name + ": writer bytes " + blobToHex(ws.data()) + ", want " + rec.bytes);
};

local runFile = function(serialize, name) {
  local text = readText(::SERIALIZE_ROOT + "/conformance/" + name);
  local recs = parseRecords(text);
  check(recs.len() == countOps(text), name + ": parsed " + recs.len() + " records, " + countOps(text) + " operations");
  foreach (rec in recs) {
    local r = runSingle(serialize, rec);
    check(r.handled, rec.name + ": operation " + rec.operation + " has no runner");
    if ("writer" in rec && rec.writer == "canonical") runWriter(serialize, rec);
  }
  print(name + ": " + recs.len() + " records\n");
};

function TestConformanceCorpus() {
  local root = ::SERIALIZE_ROOT;
  local serialize = dofile(root + "/src/serialize.nut", true);

  local files = discoverCorpusFiles(root);
  local total = 0;
  foreach (f in files) {
    runFile(serialize, f);
    total += countOps(readText(root + "/conformance/" + f));
  }
  print("corpus: " + files.len() + " files, " + total + " records\n");

  // The controls (STANDARD.md, "A gate nobody has seen go red is a claim, not
  // a measurement"): a corpus file whose operation has no runner is REJECTED,
  // never skipped. Feed a scratch copy with an unknown operation and require it
  // is rejected.
  local scratch = root + "/conformance/zz_control_unknown.txt";
  local f = file(scratch, "wb");
  local body = "operation not_a_real_operation\nname control\nbytes 00\nexpect value = 0\nconsumed 1\n";
  foreach (c in body) f.writen(c, 'b');
  f.close();
  local rejected = false;
  try { runFile(serialize, "zz_control_unknown.txt"); } catch (e) { rejected = true; }
  system("rm -f " + scratch);
  check(rejected, "an unknown operation was not rejected");
}
