// TestSerializeBits (serialize-squirrel-bits): runs every record of the bits,
// bool, uint128, align and object conformance files (STANDARD.md, The vector
// format, What a runner checks), plus serialize.go's TestContinue and TestUntil
// cases and MeasureStream's bit counts. A test passes by returning and fails by
// throwing (DESIGN.md (i)).

local S = null;   // the API table, set by TestSerializeBits

local check = function(cond, what) {
  if (!cond) throw "TestSerializeBits: " + what;
};

local trim = function(s) {
  local a = 0, b = s.len();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
  return s.slice(a, b);
};

local fields = function(s) {
  local out = [];
  local cur = "";
  foreach (c in s) {
    if (c == ' ' || c == '\t') {
      if (cur != "") { out.append(cur); cur = ""; }
    } else {
      cur += c.tochar();
    }
  }
  if (cur != "") out.append(cur);
  return out;
};

local readText = function(path) {
  local f = file(path, "rb");
  local b = f.readblob(f.len());
  f.close();
  local s = "";
  foreach (c in b) s += c.tochar();
  return s;
};

local hexDigits = "0123456789ABCDEF";
local hexBytes = function(b) {
  local parts = [];
  for (local i = 0; i < b.len(); i++) {
    parts.append(hexDigits[(b[i] >> 4) & 0xf].tochar() + hexDigits[b[i] & 0xf].tochar());
  }
  local s = "";
  for (local i = 0; i < parts.len(); i++) {
    if (i > 0) s += " ";
    s += parts[i];
  }
  return s;
};

// parseUint128(text): a decimal or hex number up to 128 bits, as [lo, hi]
// (STANDARD.md, The vector format, Lexical rules). null on any malformed input.
local parseUint128 = function(text) {
  text = trim(text);
  local radix = 10;
  if (text.len() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    radix = 16;
    text = text.slice(2);
  }
  if (text == "") return null;
  local limbs = [0, 0, 0, 0];
  local mulAdd = function(m, d) {
    local carry = d;
    for (local i = 0; i < 4; i++) {
      local t = limbs[i] * m + carry;
      limbs[i] = t & 0xffffffff;
      carry = t >>> 32;
    }
    return carry == 0;
  };
  foreach (c in text) {
    local v = -1;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else return null;
    if (v >= radix) return null;
    if (!mulAdd(radix, v)) return null;
  }
  return [limbs[0] | (limbs[1] << 32), limbs[2] | (limbs[3] << 32)];
};

local parseByte = function(pair) {
  local hi = -1, lo = -1;
  foreach (i, c in pair) {
    local v = -1;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    if (v < 0) throw "TestSerializeBits: bad hex byte " + pair;
    if (i == 0) hi = v; else lo = v;
  }
  return hi * 16 + lo;
};

local newRecord = function(fname) {
  return {
    file = fname, operation = "", name = "", params = {}, steps = [],
    bytes = blob(0), expectKind = "", expect = "", reason = null,
    consumed = 0, hasConsumed = false,
    measureAtLeast = 0, hasMeasure = false,
    writerCanonical = false,
  };
};

local parseVectors = function(fname, text) {
  local records = [];
  local cur = null;
  foreach (raw in split(text, "\n")) {
    if (raw.len() > 0 && raw[0] == '#') continue;
    local line = trim(raw);
    if (line == "") {
      if (cur != null) { records.append(cur); cur = null; }
      continue;
    }
    if (cur == null) cur = newRecord(fname);
    local sp = line.find(" ");
    local key = sp == null ? line : line.slice(0, sp);
    local rest = sp == null ? "" : trim(line.slice(sp + 1));
    if (key == "operation") cur.operation = rest;
    else if (key == "name") cur.name = rest;
    else if (key == "param") {
      local eq = rest.find("=");
      if (eq == null) throw "TestSerializeBits: " + fname + ": param needs `name = value`";
      local pn = trim(rest.slice(0, eq));
      local pv = trim(rest.slice(eq + 1));
      if (pn == "step") cur.steps.append(pv);
      else cur.params[pn] <- pv;
    }
    else if (key == "bytes") {
      local pairs = fields(rest);
      if (pairs.len() > 0) {
        local b = blob(pairs.len());
        for (local i = 0; i < pairs.len(); i++) b[i] = parseByte(pairs[i]);
        cur.bytes = b;
      }
    }
    else if (key == "expect") {
      local ew = fields(rest);
      if (ew.len() > 0 && ew[0] == "refused") {
        // format 2.0: `expect refused <reason>`, the closed list's spelling
        if (ew.len() != 2) throw "TestSerializeBits: " + fname + ": `expect refused` must state one reason";
        cur.expectKind = "refused";
        cur.reason = ew[1];
      }
      else {
        local eq = rest.find("=");
        if (eq == null) throw "TestSerializeBits: " + fname + ": expect needs `refused` or `value = ...`";
        local kind = trim(rest.slice(0, eq));
        local value = trim(rest.slice(eq + 1));
        if (kind == "value") { cur.expectKind = "value"; cur.expect = value; }
        else if (kind == "bits") { cur.expectKind = "bits"; cur.expect = value; }
        else throw "TestSerializeBits: " + fname + ": unknown expect kind " + kind;
      }
    }
    else if (key == "consumed") { cur.consumed = rest.tointeger(); cur.hasConsumed = true; }
    else if (key == "measure_at_least") { cur.measureAtLeast = rest.tointeger(); cur.hasMeasure = true; }
    else if (key == "writer") {
      if (rest == "canonical") cur.writerCanonical = true;
      else throw "TestSerializeBits: unknown writer mode " + rest;
    }
    else throw "TestSerializeBits: " + fname + ": unknown key " + key;
  }
  if (cur != null) records.append(cur);
  return records;
};

local newStep = function(kind, width) {
  return { kind = kind, width = width, pattern = [0, 0], boolean = false, data = null };
};

local stepFromWords = function(text) {
  local w = fields(text);
  if (w.len() == 0) throw "TestSerializeBits: empty step";
  if (w[0] == "bool" && w.len() == 1) return newStep("bool", 0);
  if (w[0] == "align" && w.len() == 1) return newStep("align", 0);
  if (w[0] == "uint128" && w.len() == 1) return newStep("uint128", 0);
  if (w[0] == "bits" && w.len() == 2) return newStep("bits", w[1].tointeger());
  if (w[0] == "object" && w.len() == 2) return newStep("object", w[1].tointeger());
  if (w[0] == "bytes" && w.len() == 2) return newStep("bytes", w[1].tointeger());
  throw "TestSerializeBits: no runner for step " + text;
};

local buildSteps = function(r) {
  local steps = [];
  if (r.operation == "sequence") {
    foreach (t in r.steps) steps.append(stepFromWords(t));
    return steps;
  }
  if ("preceding_bits" in r.params) {
    local w = parseUint128(r.params["preceding_bits"]);
    if (w != null && w[0] > 0) steps.append(newStep("bits", w[0]));
  }
  if (r.operation == "bits") steps.append(newStep("bits", r.params["bits"].tointeger()));
  else if (r.operation == "bool") steps.append(newStep("bool", 0));
  else if (r.operation == "uint128") steps.append(newStep("uint128", 0));
  else if (r.operation == "align") steps.append(newStep("align", 0));
  else throw "TestSerializeBits: no runner for operation " + r.operation;
  return steps;
};

local stepSpan = function(steps, i) {
  return steps[i].kind == "object" ? 1 + steps[i].width : 1;
};

local runStep = function(stream, st) {
  if (st.kind == "bits") {
    local h = { value = st.pattern[0] };
    local ok = stream.serializeBits64(h, st.width);
    st.pattern = [h.value, 0];
    return ok;
  }
  if (st.kind == "bool") {
    local h = { value = st.boolean };
    local ok = stream.serializeBool(h);
    st.boolean = h.value;
    return ok;
  }
  if (st.kind == "uint128") {
    local h = { value = st.pattern };
    local ok = stream.serializeUint128(h);
    st.pattern = h.value;
    return ok;
  }
  if (st.kind == "align") return stream.serializeAlign();
  if (st.kind == "bytes") {
    if (st.data == null || st.data.len() != st.width) st.data = blob(st.width);
    return stream.serializeBytes(st.data);
  }
  throw "TestSerializeBits: no runner for step kind " + st.kind;
};

local runRange = null;
runRange = function(stream, steps, lo, hi, state) {
  local i = lo;
  while (i < hi) {
    local st = steps[i];
    if (st.kind == "object") {
      local start = i + 1;
      local end = i + 1 + st.width;
      local inner = { serialize = null };
      inner.serialize <- function(s) { return runRange(s, steps, start, end, state) == end ? true : false; };
      if (stream.serializeObject(inner) != true) { state.failed <- i; return i; }
      i = end;
    } else {
      if (!runStep(stream, st)) { state.failed <- i; return i; }
      i++;
    }
  }
  return hi;
};

local SENTINEL_LO = 0xCAFEF00D;
local seedSentinels = function(steps) {
  foreach (st in steps) {
    if (st.kind == "bits" || st.kind == "uint128") st.pattern = [SENTINEL_LO, 0];
    else if (st.kind == "bool") st.boolean = true;
    else st.data = null;
  }
};

local expectationMatches = function(st, expected) {
  if (st.kind == "bits" || st.kind == "uint128") {
    local want = parseUint128(expected);
    if (want == null) return false;
    return want[0] == st.pattern[0] && want[1] == st.pattern[1];
  }
  if (st.kind == "bool") return (expected == "true") == st.boolean;
  if (st.kind == "align") return expected == "0";
  if (st.kind == "bytes") return hexBytes(st.data) == expected;
  return false;
};

local checkTerminal = function(stream, name) {
  local after = { value = 0xFFFFFFFF };
  local before = stream.bitsProcessed();
  if (stream.serializeBits(after, 8) != false) throw name + ": the stream accepted a read after the refusal";
  if (after.value != 0xFFFFFFFF) throw name + ": the read after the refusal wrote its destination";
  if (stream.bitsProcessed() != before) throw name + ": the read after the refusal consumed bits";
};

local runReader = function(r, steps) {
  seedSentinels(steps);
  local stream = S.ReadStream(r.bytes);
  local state = {};
  local stoppedAt = runRange(stream, steps, 0, steps.len(), state);

  if (r.expectKind == "refused") {
    if (stoppedAt >= steps.len()) throw r.name + ": the read succeeded, the corpus requires refusal";
    if (stream.error() != r.reason) throw r.name + ": refused as " + stream.error() + ", the corpus states " + r.reason;
    local fs = steps[state.failed];
    if (fs.kind == "bits" || fs.kind == "uint128") {
      if (fs.pattern[0] != SENTINEL_LO || fs.pattern[1] != 0) throw r.name + ": the refused read wrote the destination";
    }
    if (fs.kind == "bool") {
      if (!fs.boolean) throw r.name + ": the refused read wrote the destination";
    }
    for (local i = stoppedAt + stepSpan(steps, stoppedAt); i < steps.len(); i += stepSpan(steps, i)) {
      local span = stepSpan(steps, i);
      local s2 = {};
      if (runRange(stream, steps, i, i + span, s2) == i + span) {
        throw r.name + ": a step after a refusal succeeded, failure must be terminal";
      }
    }
    checkTerminal(stream, r.name);
    return;
  }

  if (stoppedAt != steps.len()) throw r.name + ": the read was refused, the corpus requires acceptance";

  local entries = [];
  foreach (e in split(r.expect, "|")) entries.append(trim(e));
  local offset = steps.len() - entries.len();
  if (offset < 0) throw r.name + ": the expect list states more values than the vector has steps";
  for (local i = 0; i < entries.len(); i++) {
    if (entries[i] == "-") continue;
    local st = steps[offset + i];
    if (!expectationMatches(st, entries[i])) {
      throw r.name + ": step " + (offset + i + 1) + " decoded " + hexBytes(blob(0)) + ", the corpus states " + entries[i];
    }
  }

  if (r.hasConsumed && stream.bitsProcessed() != r.consumed) {
    throw r.name + ": consumed " + stream.bitsProcessed() + " bits, the corpus states " + r.consumed;
  }
};

local runWriter = function(r, steps) {
  local bufsize = (r.bytes.len() + 64) / 8 * 8 + 8;
  local ws = S.WriteStream(blob(bufsize));
  local state = {};
  if (runRange(ws, steps, 0, steps.len(), state) != steps.len()) {
    throw r.name + ": the writer refused a canonical vector";
  }
  ws.flush();
  local data = ws.data();
  if (data.len() != r.bytes.len()) {
    throw r.name + ": the writer emitted " + data.len() + " bytes, the corpus states " + r.bytes.len();
  }
  for (local i = 0; i < data.len(); i++) {
    if (data[i] != r.bytes[i]) throw r.name + ": the writer emitted " + hexBytes(data) + ", the corpus states " + hexBytes(r.bytes);
  }
};

local runMeasure = function(r, steps) {
  local ms = S.MeasureStream();
  local state = {};
  if (runRange(ms, steps, 0, steps.len(), state) != steps.len()) {
    throw r.name + ": the measure refused a step, a measure refuses nothing at runtime";
  }
  if (ms.bitsProcessed() < r.measureAtLeast) {
    throw r.name + ": measured " + ms.bitsProcessed() + " bits, the corpus requires at least " + r.measureAtLeast;
  }
};

local runRecord = function(r) {
  local steps = buildSteps(r);
  runReader(r, steps);
  if (r.writerCanonical && r.expectKind != "refused") runWriter(r, steps);
  if (r.hasMeasure && r.expectKind != "refused") runMeasure(r, steps);
};

local runFile = function(root, fname) {
  local text = readText(root + "/conformance/" + fname);
  local records = parseVectors(fname, text);
  foreach (r in records) runRecord(r);
  return records.len();
};

function TestSerializeBits() {
  S = dofile(::SERIALIZE_ROOT + "/src/serialize.nut", true);

  // the conformance corpus: every record of each file, printed per file
  local files = ["bits.txt", "bool.txt", "uint128.txt", "align.txt", "object.txt"];
  foreach (f in files) {
    local n = runFile(::SERIALIZE_ROOT, f);
    print(f + ": " + n + " records\n");
  }

  // MeasureStream bit counts for each operation (STANDARD.md, The Measure Stream)
  local ms = S.MeasureStream();
  check(ms.serializeBits({value = 0}, 5) && ms.bitsProcessed() == 5, "measure bits");
  check(ms.serializeBits64({value = 0}, 33) && ms.bitsProcessed() == 38, "measure bits64");
  check(ms.serializeBool({value = true}) && ms.bitsProcessed() == 39, "measure bool");
  check(ms.serializeUint8({value = 0}) && ms.bitsProcessed() == 47, "measure uint8");
  check(ms.serializeUint16({value = 0}) && ms.bitsProcessed() == 63, "measure uint16");
  check(ms.serializeUint32({value = 0}) && ms.bitsProcessed() == 95, "measure uint32");
  check(ms.serializeUint64({value = 0}) && ms.bitsProcessed() == 159, "measure uint64");
  check(ms.serializeAlign() && ms.bitsProcessed() == 166, "measure align (worst case 7)");
  check(ms.serializeUint128({value = [0, 0]}) && ms.bitsProcessed() == 294, "measure uint128");

  // serialize.go's TestContinue: a continuation-bit round trip
  local items = [10, 20, 30, 40, 50];
  local buffer = blob(64);
  local ws = S.WriteStream(buffer);
  {
    local i = 0;
    local hasNext = items.len() > 0;
    while (S.Continue(ws, {value = hasNext})) {
      ws.serializeBits({value = items[i]}, 8);
      i++;
      hasNext = i < items.len();
    }
  }
  check(ws.ok(), "continue write latched an error");
  ws.flush();
  local rs = S.ReadStream(ws.data());
  {
    local read = [];
    local hasNext = true;
    while (S.Continue(rs, {value = hasNext})) {
      local h = {value = 0};
      rs.serializeBits(h, 8);
      read.append(h.value);
    }
    check(rs.ok(), "continue read latched an error");
    check(read.len() == items.len(), "continue read wrong item count");
    for (local i = 0; i < items.len(); i++) check(read[i] == items[i], "continue item mismatch");
  }

  // serialize.go's TestUntil: a done-bit round trip
  local buffer2 = blob(64);
  local ws2 = S.WriteStream(buffer2);
  {
    local i = 0;
    local done = items.len() == 0;
    while (S.Until(ws2, {value = done})) {
      ws2.serializeBits({value = items[i]}, 8);
      i++;
      done = i == items.len();
    }
  }
  check(ws2.ok(), "until write latched an error");
  ws2.flush();
  check(ws2.bitsProcessed() == items.len() * 9 + 1, "until bit count");
  local rs2 = S.ReadStream(ws2.data());
  {
    local read = [];
    local done = false;
    while (S.Until(rs2, {value = done})) {
      local h = {value = 0};
      rs2.serializeBits(h, 8);
      read.append(h.value);
    }
    check(rs2.ok(), "until read latched an error");
    check(read.len() == items.len(), "until read wrong item count");
    for (local i = 0; i < items.len(); i++) check(read[i] == items[i], "until item mismatch");
  }
  // an empty sequence is a single terminating bit
  ws2.reset(buffer2);
  {
    local done = true;
    while (S.Until(ws2, {value = done})) throw "TestSerializeBits: the loop body ran for an empty sequence";
  }
  check(ws2.bitsProcessed() == 1, "an empty until sequence should cost 1 bit");
}
