// serialize_compressed_float.nut: the compressed float family of serialize
// (serialize-squirrel-compressed-float; DESIGN.md (h)). A module of the closed
// loader (DESIGN.md (f)): vargv[0] is this module's exports table and vargv[1]
// the loader's require.
//
// STANDARD.md compressed_float: a float quantized to a resolution. Let
// delta = max - min and values = delta / res, clamped to [1, 4294967040] (the
// largest float below 2^32). Then max_integer_value = ceil(values) and
// bits = bits_required(0, max_integer_value). The writer clamps
// (value - min) / delta to [0,1], multiplies by max_integer_value, adds 0.5,
// floors, clamps the integer to max_integer_value, and writes it in `bits`
// bits; the reader divides by max_integer_value, multiplies by delta, adds min,
// and refuses an integer above max_integer_value. The arithmetic is float32
// with EVERY STEP ROUNDING (STANDARD.md compressed_float; DESIGN.md (e)):
// the double result of each +, -, *, / of two float32 values goes through
// fround before the next step (two roundings around the 0.5, never one; a
// step is never widened to double before the floor).
local _M = vargv[0];
local require = vargv[1];

// fround (DESIGN.md (e)) narrows a double to the float32 Go's float32() gives.
// DESIGN (h): compressed_float reaches serialize_float's fround. When that
// dependency has not landed, the same narrow (bit-identical to the float
// card's) is embedded so this family still runs; once serialize_float exists it
// is used.
local fround;
try {
  fround = require("serialize_float", "fround");
} catch (e) {
  local froundPattern = function(v) {
    local bits = castf2i(v);
    local sign = bits & 0x8000000000000000;
    local exp = (bits >>> 52) & 0x7FF;
    local frac = bits & 0xFFFFFFFFFFFFF;
    local p;
    if (exp == 0x7FF) {
      if (frac == 0) p = sign >>> 32 | 0x7F800000;
      else p = sign >>> 32 | 0x7F800000 | ((frac >>> 29) & 0x7FFFFF);
    } else if (exp == 0) {
      p = sign >>> 32;
    } else {
      local m53 = 0x10000000000000 | frac;
      local fe = exp - 896;
      if (fe > 254) {
        p = sign >>> 32 | 0x7F800000;
      } else if (fe >= 1) {
        local dropped = m53 & 0x1FFFFFFF;
        local m24 = m53 >>> 29;
        local m = m24;
        if (dropped > 0x10000000) m = m24 + 1;
        else if (dropped == 0x10000000 && (m24 & 1) == 1) m = m24 + 1;
        if (m == 0x1000000) { m = 0x800000; fe++; }
        if (fe > 254) p = sign >>> 32 | 0x7F800000;
        else p = sign >>> 32 | (fe << 23) | (m - 0x800000);
      } else {
        local t = exp - 926;
        local num;
        if (t < -52) {
          if (exp == 873 && m53 > 0x10000000000000) num = 1; else num = 0;
        } else {
          local shift = 926 - exp;
          local dropped = m53 & ((0x1 << shift) - 1);
          local half = 0x1 << (shift - 1);
          local m24 = m53 >>> shift;
          local m = m24;
          if (dropped > half) m = m24 + 1;
          else if (dropped == half && (m24 & 1) == 1) m = m24 + 1;
          if (m >= 0x800000) num = 0x800000; else num = m;
        }
        p = sign >>> 32 | num;
      }
    }
    return p;
  };
  local float32FromBits = function(i) {
    local sign = (i & 0x80000000) << 32;
    local e = (i >>> 23) & 0xFF;
    local m = i & 0x7FFFFF;
    local db;
    if (e == 0xFF) {
      if (m == 0) db = sign | 0x7FF0000000000000;
      else db = sign | 0x7FF0000000000000 | (m << 29);
    } else if (e == 0) {
      if (m == 0) db = sign;
      else {
        local k = 0;
        local t = m;
        while (t > 1) { t = t >>> 1; k++; }
        db = sign | ((874 + k) << 52) | ((m << (52 - k)) & 0xFFFFFFFFFFFFF);
      }
    } else {
      db = sign | ((e + 896) << 52) | (m << 29);
    }
    return casti2f(db);
  };
  fround = function(x) { return float32FromBits(froundPattern(x)); };
}

// bitLen(n): the number of bits to represent the positive integer n
// (serialize.go bits.Len32); bits_required(0, n) for n > 0 (STANDARD.md).
local bitLen = function(n) {
  local b = 0;
  while (n > 0) { b++; n = n >>> 1; }
  return b;
};

// isNotFinite(x): x, after fround, is NaN, +inf or -inf (its double exponent
// field is all ones). DESIGN.md (e) raises before any bit moves on such a
// value; the read path is untouched.
local isNotFinite = function(x) {
  return ((castf2i(x) >>> 52) & 0x7FF) == 0x7FF;
};

// compressedFloatParams(min, max, resolution) (serialize.go CompressedFloatParams):
// derive the wire constants. Returns { maxIntegerValue, bits, delta }. Every
// float32 step rounds (DESIGN.md (e)). min >= max or resolution <= 0 is API
// misuse and raises serialize.go's panic text.
local compressedFloatParams = function(min, max, resolution) {
  if (!(min < max) || !(resolution > 0)) {
    throw "serialize: compressed float requires min < max and resolution > 0";
  }
  local delta = fround(max - min);
  local values = fround(delta / resolution);
  if (!(values >= 1.0)) values = 1.0;
  else if (values > 4294967040.0) values = 4294967040.0;
  local maxIntegerValue = ceil(values).tointeger();
  return { maxIntegerValue = maxIntegerValue, bits = bitLen(maxIntegerValue), delta = delta };
};

// validateConstants(maxIntegerValue, bits, delta): API misuse raises serialize.go's
// panic text (serialize.go validateCompressedFloatConstants). The delta-delta
// term catches a non-finite delta; !(delta > 0) catches NaN, zero and negative.
local validateConstants = function(maxIntegerValue, bits, delta) {
  if (maxIntegerValue == 0 || bits != bitLen(maxIntegerValue) || !(delta > 0) || delta - delta != 0) {
    throw "serialize: precomputed compressed float constants must be exactly what CompressedFloatParams derives";
  }
};

// the write arm's audited home (serialize.go compressedFloat32Precomputed)
local writePrecomputed = function(s, h, maxIntegerValue, bits, delta, min) {
  validateConstants(maxIntegerValue, bits, delta);
  local value = fround(h.value);
  if (isNotFinite(value)) {
    throw "serialize: compressed float value is not finite";
  }
  local normalizedValue = fround((value - min) / delta);
  if (!(normalizedValue >= 0)) normalizedValue = 0;
  else if (!(normalizedValue <= 1)) normalizedValue = 1;
  local mf = fround(maxIntegerValue);
  local product = fround(normalizedValue * mf);
  local sum = fround(product + 0.5);
  local integerValue = floor(sum).tointeger();
  if (integerValue > maxIntegerValue) integerValue = maxIntegerValue;
  if (!s._room(bits)) return false;
  s._put(integerValue, bits);
  return true;
};

// the read arm's audited home (serialize.go compressedFloat32Precomputed)
local readPrecomputed = function(s, h, maxIntegerValue, bits, delta, min) {
  validateConstants(maxIntegerValue, bits, delta);
  if (!s._room(bits)) return false;
  local integerValue = s._take(bits);
  if (integerValue > maxIntegerValue) return s._fail("value_out_of_range");
  local mf = fround(maxIntegerValue);
  local normalizedValue = fround(fround(integerValue) / mf);
  local product = fround(normalizedValue * delta);
  local result = fround(product + min);
  h.value <- result;
  return true;
};

local write = {
  serializeCompressedFloat = function(s, h, min, max, resolution) {
    local p = compressedFloatParams(min, max, resolution);
    return writePrecomputed(s, h, p.maxIntegerValue, p.bits, p.delta, min);
  },
  serializeCompressedFloatPrecomputed = function(s, h, maxIntegerValue, bits, delta, min) {
    return writePrecomputed(s, h, maxIntegerValue, bits, delta, min);
  },
};

local read = {
  serializeCompressedFloat = function(s, h, min, max, resolution) {
    local p = compressedFloatParams(min, max, resolution);
    return readPrecomputed(s, h, p.maxIntegerValue, p.bits, p.delta, min);
  },
  serializeCompressedFloatPrecomputed = function(s, h, maxIntegerValue, bits, delta, min) {
    return readPrecomputed(s, h, maxIntegerValue, bits, delta, min);
  },
};

local measure = {
  serializeCompressedFloat = function(s, h, min, max, resolution) {
    local p = compressedFloatParams(min, max, resolution);
    local value = fround(h.value);
    if (isNotFinite(value)) throw "serialize: compressed float value is not finite";
    s._put(0, p.bits);
    return true;
  },
  serializeCompressedFloatPrecomputed = function(s, h, maxIntegerValue, bits, delta, min) {
    validateConstants(maxIntegerValue, bits, delta);
    local value = fround(h.value);
    if (isNotFinite(value)) throw "serialize: compressed float value is not finite";
    s._put(0, bits);
    return true;
  },
};

_M.compressedFloatParams <- compressedFloatParams;
_M.write <- write;
_M.read <- read;
_M.measure <- measure;
