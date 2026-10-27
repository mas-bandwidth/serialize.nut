# serialize.nut: the design

This page is the Squirrel port's design, the one every later card of the
`serialize-squirrel` stream copies. It names the API, the wire rules, the
number model, the byte buffers, the float32 rule, the loader, the writer and
reader model, the file layout with each file's card and exports, and the test
runner. Each family card creates one file and decides nothing this page
already decides.

**Pins.**

| what | pin |
|---|---|
| the reference | `mas-bandwidth/serialize.go` tag `v2.0.0` (`a3ffd9136906dfc4db5b2fb6d146181d749b00c5`, module `github.com/mas-bandwidth/serialize.go/v2`), read, never imported by the library (the fuzz differential imports it) |
| the closest worked example | `mas-bandwidth/serialize.js` main at `ff765a1a89a89dc3f6e818e553baabf189241b4e` (`src/index.js`, `src/streams.js`), read, never imported |
| the wire's authority | `STANDARD.md`, `IMPLEMENTING.md`, `conformance/*.txt` and `conformance-controls/`, vendored VERBATIM from `mas-bandwidth/serialize` commit `3617d3606db9c5686018d6568f0aa761869083c5` (main after `3f40cb5f`, read terminality across `serialize_object`: the format 2.0.1 corpus, which is v2.0.0's plus a `param step = object 0` successor in two `object.txt` vectors and one `sequence.txt` vector; STANDARD.md unchanged since v2.0.0; `tools/revendor.sh <tag or sha>` re-vendors them) |
| the number, byte, float32 and loading rules | `mas-bandwidth/schema` `docs/PORT-SQUIRREL.md` at `f676cb9adc8a653abcdce38034e99ec3c3aad6b8` (branch `sprint/schema-squirrel-port-design.w1.g1.e21`), restated in (c) to (f) with no change of substance |
| the interpreter | Squirrel 3.2, built `sq64` with `-DSQUSEDOUBLE` (`make dist-squirrel`) |

**The vendored copies are the reference's copies.** `diff -r` of this
repository's `STANDARD.md`, `IMPLEMENTING.md`, `conformance/` and
`conformance-controls/` against serialize's at the pinned commit is empty (the corpus job in
CI holds them to it), so the Go oracle and this port read the same 18 vector
files and the same standard, byte for byte.

**Format 2.0** (STANDARD.md, Format version): the wire carries only integers
and bytes, and every value has exactly one encoding. Against format 1.1 this
port: refuses for one of eight named reasons (a); carries finite floats and
doubles only (e); refuses a compressed float decode that is not finite (e);
refuses the int_relative absolute tier carrying a bounded difference; refuses a
string's zero byte before its encoding, each for its own reason; has
`serializeEnd` (a), which a packet reader calls after its top-level object; and
has no wstring.

Squirrel is a sibling of the Luau and Lua ports and of schema's Squirrel leg:
schema's Squirrel type wire calls this library instead of a private bit reader
and writer, so (c) to (f) are exactly schema's rules, and schema can vendor
these files unchanged.

## (a) THE API

`dofile(dir + "/serialize.nut", true)` returns the API table. Every type,
function and stream method serialize.go v2.0.0 exports is here, in
serialize.js's spelling, with Squirrel's deviations named below with their
reasons.

**Holders.** Squirrel has no pointers and no ref parameters, so a value is
passed in a holder, a table `{ value = ... }`, exactly as serialize.js passes
`{ value }`: on write `.value` is consumed; on a successful read `.value` is
assigned; on a failed read it is LEFT UNMODIFIED; on measure it is ignored.
Holders can be reused; a stream never keeps one. `serializeBytes(data)` takes
the blob itself (Go and JS pass the slice): on read it is filled in place,
untouched on failure.

**Returns.** Every serialize method returns `true` on success and `false` on
failure; the failure's kind is `stream.error()`. Go returns `error`, JS
returns a boolean; this is JS's model.

**The refusal reasons** are STANDARD.md's closed list of eight ("Refusal
reasons"), each value spelled exactly as the standard spells it, and
serialize.go v2's `Refusal` sentinels, latched on the stream:

| `SerializeError.` | serialize.go | meaning |
|---|---|---|
| `None` (`null`) | `nil` | the stream is healthy |
| `PastEnd` (`"past_end"`) | `ErrPastEnd` | a read past the end of the data, or a write past the end of the buffer |
| `ValueOutOfRange` (`"value_out_of_range"`) | `ErrValueOutOfRange` | a ranged offset past its span, a string length past its buffer, a compressed integer past `max_integer_value`, an int_relative outside its domain or not increasing; on write, a value outside its range |
| `NonzeroPadding` (`"nonzero_padding"`) | `ErrNonzeroPadding` | a set bit in an align's padding (align, bytes, string), or in the final byte's unused bits at the end |
| `TrailingData` (`"trailing_data"`) | `ErrTrailingData` | a whole byte or more after the end of the object |
| `NonFiniteFloat` (`"non_finite_float"`) | `ErrNonFiniteFloat` | a float or double that is NaN or an infinity, or a compressed float decode that is not finite; on write and measure, a non-finite float or double |
| `InvalidUtf8` (`"invalid_utf8"`) | `ErrInvalidUTF8` | a string payload that is not well-formed UTF-8 |
| `EmbeddedNul` (`"embedded_nul"`) | `ErrEmbeddedNul` | a zero byte among a string's bytes, checked before the encoding |
| `NonCanonical` (`"non_canonical"`) | `ErrNonCanonical` | the int_relative absolute tier carrying a difference a bounded tier carries |

The FIRST refusal sticks: every later call fails with that same reason (its
echoes keep it), consumes nothing and writes nothing to its holder or
destination, zero-bit calls included (an aligned align, a degenerate range, a
zero-count bytes, an object, an end). Only `reset` clears it. A refusal is
never a bare boolean: `error()` names the rule.

**The names.** The smoke test reads the block below and requires every name
in it to exist (`api` on the table the entry returns, `method` on every
stream, `write` on WriteStream).

```
api SerializeError
api WriteStream
api ReadStream
api MeasureStream
api BitWriter
api BitReader
api bitsRequired
api bitsRequired64
api bitsRequired128
api signedToUnsigned
api unsignedToSigned
api int128From64
api uint128From64
api compressedFloatParams
api fround
api Continue
api Until
method isWriting
method isReading
method serializeBits
method serializeBits64
method serializeInt
method serializeInt64
method serializeInt128
method serializeUint128
method serializeFixed64
method serializeFixed128
method serializeUint8
method serializeUint16
method serializeUint32
method serializeUint64
method serializeBool
method serializeFloat
method serializeDouble
method serializeCompressedFloat
method serializeCompressedFloatPrecomputed
method serializeBytes
method serializeString
method serializeAlign
method serializeObject
method serializeEnd
method serializeIntRelative
method alignBits
method bitsProcessed
method bytesProcessed
method error
method ok
method setContext
method context
method reset
write flush
write data
```

| Squirrel | serialize.go v1.15.1 | value domain |
|---|---|---|
| `WriteStream(buffer)` | `NewWriteStream(buffer)` | `buffer` a blob, length a multiple of 8 |
| `ReadStream(data)` | `NewReadStream(data)` | `data` a blob, any length |
| `MeasureStream()` | `NewMeasureStream()` | |
| `BitWriter(buffer)`, `BitReader(data)` | `NewBitWriter`, `NewBitReader` | the bit packer, (h) |
| `bitsRequired(min, max)` | `BitsRequired` | uint32 in an integer |
| `bitsRequired64(min, max)` | `BitsRequired64` | uint64 as its 64 bits, (c) |
| `bitsRequired128(min, max)` | `BitsRequired128` | `[lo, hi]` |
| `signedToUnsigned(n)`, `unsignedToSigned(n)` | `SignedToUnsigned`, `UnsignedToSigned` | int32 / uint32 in an integer |
| `int128From64(x)`, `uint128From64(x)` | `Int128From64`, `Uint128From64` | returns `[lo, hi]` |
| `compressedFloatParams(min, max, resolution)` | `CompressedFloatParams` | returns `{ maxIntegerValue, bits, delta }` |
| `fround(x)` | Go's `float32(x)` conversion | a double narrowed to the float32 it rounds to, (e) |
| `Continue(stream, more)`, `Until(stream, done)` | `Continue`, `Until` | holders of a bool |
| `s.isWriting()`, `s.isReading()` | `IsWriting`, `IsReading` | |
| `s.serializeBits(h, bits)` | `SerializeBits` | bits in [1,32] |
| `s.serializeBits64(h, bits)` | `SerializeBits64` | bits in [1,64] |
| `s.serializeInt(h, min, max)` | `SerializeInt` | int32 |
| `s.serializeInt64(h, min, max)` | `SerializeInt64` | int64 |
| `s.serializeInt128(h, min, max)` | `SerializeInt128` | `[lo, hi]` |
| `s.serializeUint128(h)` | `SerializeUint128` | `[lo, hi]` |
| `s.serializeFixed64(h, integerBits, fractionBits, min, max)` | `SerializeFixed64` | raw value an int64; bounds whole units |
| `s.serializeFixed128(h, integerBits, fractionBits, min, max)` | `SerializeFixed128` | raw value `[lo, hi]`; bounds int64 whole units |
| `s.serializeUint8/16/32/64(h)` | `SerializeUint8/16/32/64` | |
| `s.serializeBool(h)` | `SerializeBool` | a bool |
| `s.serializeFloat(h)` | `SerializeFloat32` | a double holding a float32, (e) |
| `s.serializeDouble(h)` | `SerializeFloat64` | a double |
| `s.serializeCompressedFloat(h, min, max, resolution)` | `SerializeCompressedFloat32` | float32 arithmetic, (e) |
| `s.serializeCompressedFloatPrecomputed(h, maxIntegerValue, bits, delta, min)` | `SerializeCompressedFloat32Precomputed` | the constants `compressedFloatParams` returns |
| `s.serializeBytes(data)` | `SerializeBytes` | a blob, length known to both sides |
| `s.serializeString(h, bufferSize)` | `SerializeString` | a Squirrel string of well-formed UTF-8 with no zero byte |
| `s.serializeAlign()` | `SerializeAlign` | |
| `s.serializeObject(object)` | `SerializeObject` | an object with `serialize(stream)` returning true |
| `s.serializeEnd()` | `SerializeEnd` | the end of the top-level object: on read, trailing_data then nonzero_padding; on write and measure nothing |
| `s.serializeIntRelative(previous, h)` | `SerializeIntRelative` | int32 in [0, 2147483647] |
| `s.alignBits()`, `s.bitsProcessed()`, `s.bytesProcessed()` | `AlignBits`, `BitsProcessed`, `BytesProcessed` | |
| `s.error()`, `s.ok()` | `Err` (JS `error`, `ok`) | |
| `s.setContext(c)`, `s.context()` | `SetContext`, `Context` | |
| `s.reset(...)` | `Reset` | clears the latch, keeps the context |
| `ws.flush()`, `ws.data()` | `Flush`, `Data` | `data()` returns a blob of `bytesProcessed()` bytes |

**The deviations, each with its reason.**

- `Continue` and `Until` keep Go's capital: `continue` is a Squirrel keyword,
  so `serialize.continue` does not parse.
- `isWriting()`, `isReading()`, `error()` and `ok()` are methods, where
  serialize.js has getters: Squirrel has no read-only properties, and a field
  would be writable by the caller.
- `serializeFixed64` and `serializeFixed128` keep Go's two names, where
  serialize.js has one `serializeFixed`: the two hold different values (an
  integer and `[lo, hi]`) and Go's rules differ (a Q format of at most 64 bits
  against exactly 128); JS's single name enforces a set of storage widths Go
  does not have.
- The Int128 and Uint128 types are `[lo, hi]` arrays (c), and only their
  constructors are exported: Go exports arithmetic methods because Go has no
  128-bit type for a caller to compute with; the wire needs only the codec's
  internal two-lane operations, which stay private to `serialize_int128.nut`.
- `fround` is exported though Go has no such function: Go's `float32()` is a
  language conversion, Squirrel has no float32 type, and schema's Squirrel leg
  shares this one narrowing (e).
- `serializeObject`: serialize.go latches the error the object returns. A
  Squirrel serializer returns a boolean, so an object that returns anything
  but `true` fails the call, and when it latched nothing itself the stream
  latches `ValueOutOfRange`: the object refused its own value.

## (b) BIT ORDER AND ENDIANNESS

Exactly C++ and Go. STANDARD.md, General Conventions, quoted:

> All multi-byte quantities are **little-endian**.
>
> The stream is accumulated in a **64-bit scratch word**. Bits are packed
> **least-significant-bit first**: the first value written occupies the lowest
> bits of the first word. When the scratch fills, the 64-bit word is copied to
> the buffer in host byte order on little-endian machines, and byte-swapped on
> big-endian machines. The result is the same bytes on the wire everywhere.
>
> A value of `n` bits, written when the scratch already holds `s` bits, occupies
> bits `[s, s+n)` of the current word. A value that would cross the 64-bit
> boundary is split: the low `64-s` bits complete the current word, and the
> remainder begins the next.
>
> **Flush.** After the final value, any partially filled scratch word is written
> out. The stream therefore always occupies a whole number of 8-byte words in the
> writer's buffer, but the meaningful length is the number of bytes actually
> required, rounded up to a byte.

So, for this library:

- the scratch is one 64-bit SQInteger, filled LSB first; a value crossing the
  word boundary is split, its low part completing the current word;
- each full word is stored as 8 little-endian bytes composed by hand (d), on
  every host; never `writen('l')`, which is the host's order;
- `bits > 32` is written as the low 32 bits first as a 32-bit group, then the
  `bits - 32` high bits (STANDARD.md bits); a uint128 is its low 64-bit half
  first, each half as `bits(64)` (STANDARD.md uint128);
- `flush()` writes the partial word; `data()` is the meaningful length,
  `(bits + 7) / 8` bytes;
- trailing bits are zero on write (the scratch starts at zero and only `|=`
  fills it) and ignored on read: a reader never inspects the bits past its
  last value.

## (c) THE NUMBER MODEL

The interpreter is built `sq64` with `-DSQUSEDOUBLE`; both switches are
load-bearing and both were measured on the pin: `sq64` makes `SQInteger` 64
bits (`_intsize_` 8; without it no int64, uint64 or 64-bit mask fits), and
`-DSQUSEDOUBLE` makes `SQFloat` a double (`_floatsize_` 8; without it
`16777217.0 == 16777216.0` is true). The entry refuses, by name, any VM where
`_intsize_` or `_floatsize_` is not 8. A host that embeds Squirrel must build
it the same way.

- **int64 is the integer.** Every signed width up to 64 is its value.
- **uint64 is the same bits.** A uint64 above 2^63 - 1 is the negative integer
  with the same 64 bits. Equality, `&`, `|`, `^`, `<<` and storing are the same
  on both readings. Three operations are not, and the code spells each: an
  unsigned COMPARISON is `(a ^ MIN) < (b ^ MIN)` with
  `MIN = 0x8000000000000000`; an unsigned right shift is `>>>`; an unsigned
  division, or a range offset `value - min` wider than 63 bits, is done in two
  halves (or, for an offset, as the wrapping subtraction of the bits, which is
  exact mod 2^64 and is what Go's `uint64(max) - uint64(min)` is).
- **Overflow is the C compiler's, so the library never overflows.** SQInteger
  arithmetic is C `long long`, where signed overflow is undefined: values are
  composed from bytes with shifts and masks only; every shift count stays in
  [0, 63] (a shift by 64 is undefined too); a 64-bit difference that can
  overflow is computed as the two 32-bit lanes with an explicit borrow.
- **Literals.** −2^63 and every uint64 above 2^63 − 1 are written as sixteen
  hex digits: the lexer cannot read −2^63's magnitude in decimal.
- **128 bits is two halves**: an int128, a uint128 and a 128-bit fixed point
  raw value are the array `[lo, hi]`, each half the bits of that half; the
  wire writes the low half first.
- **Floats** are doubles; a float32 is held in a double (e).

## (d) BYTES

The standard `blob` is the buffer: a growable byte array, indexable (`b[i]`
reads and writes one byte, 0..255), with `len`, `readblob`, `writeblob`,
`seek` and `tell`.

- **`readn` and `writen` are the HOST's byte order** (they `memcpy` the C
  value), so the library composes every multi-byte value from bytes by hand:
  `b[i] | b[i + 1] << 8 | ...` on read, `b[i] = (v >>> 8 * k) & 0xff` on write.
  A family card may measure `readn` behind a one-time check of the host's
  order as the faster path, with the composed form as its control; the
  composed form is the default.
- **`'f'` is a C conversion**, never used for a value that can be a NaN: a
  float32 is read as its 32 bits and widened by bit surgery (e).
- **A blob does not read past its end**: `readn` past the end throws. The
  reader never relies on that: every read checks the remaining length first
  and refuses with `PastEnd` (STANDARD.md Reader Obligations), because a
  thrown error is a crash, not a refusal.
- **Strings are not buffers.** A Squirrel string holds bytes but is immutable
  and interned: `serializeBytes` takes a blob; `serializeString` holds a
  Squirrel string and converts at the edge.
- A blob reports `typeof` `"blob"` (its `_typeof`) and is an instance of
  `::blob`; the streams check both.

## (e) FLOAT32

- **Bit patterns, never conversions.** `castf2i(f)` and `casti2f(i)` (the blob
  library's globals) reinterpret a double's 64 bits as an integer and back
  with no conversion. The float32 ↔ float64 widening and narrowing is integer
  surgery on those bits, in both directions, so every finite pattern, negative
  zero and the subnormals included, travels bit for bit (STANDARD.md, Finite
  values only, every one bit exact). The blob's `'f'` view is never used for
  this.
- **Finite values only** (format 2.0). A float or double whose exponent field
  is all ones (NaN with any payload, either sign, and both infinities) is not
  a value the format carries. A read tests the RAW BITS and refuses with
  `NonFiniteFloat` before the holder is written; a write or a measure handed
  one latches `NonFiniteFloat` and writes nothing, as serialize.go v2's
  WriteStream and MeasureStream return `ErrNonFiniteFloat`. The float write
  checks after the narrowing, so a finite double above float32's range, which
  narrows to an infinity, is refused too. `fround` of a NaN is the quiet
  float32 NaN of its sign: no payload is carried, because no NaN travels.
- **A float32 write rounds exactly as Go's `float32()` does** (coordinator
  ruling, 2026-10-17, shared with the Lua design and schema's leg). A double
  that is not exactly a float32 is NOT refused: it is narrowed by IEEE-754
  round-to-nearest, ties-to-even, so the bytes are the reference's, byte for
  byte. The narrowing is integer arithmetic on the bits from `castf2i`: the 29
  dropped mantissa bits decide the round (above half up, below down, exactly
  half to the even mantissa); a carry out of the mantissa bumps the exponent;
  a result below the normal range rounds into the subnormals the same way; one
  at or past `MaxFloat32 + ½ ulp` becomes the signed infinity; negative zero
  stays negative zero. That function is `fround(x)` (exported), in
  `serialize_float.nut`; its card holds it to Go's `float32()` over the edges
  (ties both ways, the subnormal boundary, overflow, negative zero) and over a
  seeded sweep.
- **A float32 read** widens the 32 bits exactly by bit surgery into the
  double that holds it.
- **compressed_float's arithmetic is float32**, pinned so by STANDARD.md
  (compressed_float): every float32 operation of serialize.go's
  `CompressedFloatParams` and `compressedFloat32Precomputed` is emulated in
  the double followed by `fround`, after EVERY operation (a double result of
  one float32 add, subtract, multiply or divide, rounded once, is the float32
  result; the operands are already float32 values). Inputs are `fround`ed on
  entry, as Go's `float32` parameters are. The writer's `(value - min) / delta`
  is two operations: the difference rounds before the quotient (the fuzz
  differential against serialize.go v2.0.0 found the format 1.1 port rounding
  only the quotient; TestSerializeCompressedFloat pins the witness).
- **The decode must be finite** (format 2.0, STANDARD.md compressed_float).
  A read whose decode rounds to an infinity (over `[3 * 2^103, FLT_MAX]` at
  resolution `2^104` the top integer does) refuses with `NonFiniteFloat`, the
  holder untouched, whatever the declaration. A write or a measure on a
  declaration whose top integer decodes to a non-finite value (`min + delta`,
  rounded once) raises serialize.go v2's panic text, `serialize: compressed
  float declaration decodes its top integer to a value that is not finite`,
  whatever the value.
- **A non-finite compressed_float input RAISES on write** (coordinator
  ruling, uniform across the Luau, Lua and Squirrel ports; STANDARD.md,
  compressed_float, "Non-finite inputs are non-conforming": "Conforming
  writers assert in checked builds", Glenn verbatim "should assert out on
  write too"). The value a `serializeCompressedFloat` or
  `serializeCompressedFloatPrecomputed` write is given is `fround`ed first;
  if the result is NaN, `+inf` or `-inf` the arm raises
  `serialize: compressed float value is not finite` before any bit moves, in
  every stream state, and nothing is latched or written. This is a deliberate
  deviation from serialize.go, which clamps such a value (a NaN normalizes
  into the range and is written as some integer): this writer is the checked
  build, (g), so the emulation of `compressedFloat32Precomputed` above covers
  finite inputs only and never copies the clamp for a non-finite one. The
  measure stream raises the same way (it raises on misuse like the writer).
  The read path never raises: the poison is in the input value, never on the
  wire, so a read refuses (above) and never raises.

## (f) LOADING IS CLOSED

Coordinator ruling, 2026-10-17 (shared with the Lua design and schema's leg):
loading resolves only the library's own directory. Nothing on any search path
may be found, and no native module may load.

Squirrel has no `import`, no `require`, no module search path and no native
module loader: a script reaches another file only through `dofile` and
`loadfile`, which take a path, and native code loads only when the HOST
registers it in C. So the one resolver is the loader in `serialize.nut`:

- it resolves a name to `<dir>/<name>.nut`, where `dir` is the entry's own
  directory (from `getstackinfos(1).src`), never the working directory and
  never a list of places;
- it refuses, by name, any name that is not a basename of letters, digits and
  underscores, so no `..`, no `/`, no absolute path reaches `loadfile`;
- a module is a script that receives its exports table as `vargv[0]` and the
  loader's `require` as `vargv[1]` (`local _M = vargv[0]; local require = vargv[1];`) and fills the table; the table is cached before the script runs,
  so a cycle meets the table it is still filling;
- `require(name, who)` raises `serialize: <who> not implemented (<path> is absent)` for an absent file: the lazy dispatch's error (h);
- every module reaches other files only through that `require`; none calls
  `dofile`, `loadfile` or `system` itself.

A host that embeds the VM keeps the same closure by registering only the
`blob`, `math` and `string` libraries plus `dofile`/`loadfile`, and NOT the
`system` library. TestSmoke plants a shadowing `serialize_stream.nut` in the
working directory and one level above `src/`, proves each would raise if run,
loads the entry, and requires that neither ran; and it requires that a
traversal name is refused by name.

## (g) WRITER AND READER

**The writer is STRICT**: exactly serialize.go v2.0.0's bytes. It latches
`ValueOutOfRange`, `NonFiniteFloat` or `PastEnd` exactly where serialize.go's
WriteStream returns `ErrValueOutOfRange`, `ErrNonFiniteFloat` or `ErrPastEnd`
(a ranged int, int64 or int128 value outside [min,max]; a fixed raw value
outside its raw bounds; a string that does not fit its buffer; a float or
double that is not finite; an int_relative current not greater than previous;
a write past the buffer), and it RAISES, naming the rule with serialize.go's
panic text, where serialize.go panics on API misuse
(bits outside [1,32] or [1,64]; min > max; a Q format or bounds the format
cannot hold; a buffer size outside [1, 2^31); compressed float parameters with
min >= max or resolution <= 0; precomputed constants that are not what
`compressedFloatParams` derives; a compressed float declaration whose top
integer decodes to a non-finite value, (e); a compressed float value that is
NaN, `+inf` or `-inf` after `fround`, which serialize.go clamps instead, (e); a
previous outside the int_relative domain; bytes on an unaligned stream; a
buffer that is not a multiple of 8 bytes), and where STANDARD.md says the
writer is handed only conforming input: a string that is not well-formed UTF-8
raises `serialize: a string must be well-formed UTF-8`, and one with a zero
byte raises `serialize: a string must not contain a zero byte`, on the write
and the measure stream.
What serialize.go silently masks (the high bits of a `serializeBits` value
above its width) this port masks too; serialize.go's clamp of a non-finite
compressed float is NOT copied: that is a raise above, uniform across the
Luau, Lua and Squirrel ports. A raise is API misuse and happens in
every stream state; only data latches.

**Reads forgive nothing** (format 2.0: every value has exactly one
encoding). A packet reader reads its top-level object and then `serializeEnd`,
which refuses a whole byte or more left as `TrailingData` (checked first) and
then a set bit among the final byte's unused bits as `NonzeroPadding`, and
consumes those bits: an accepted end leaves the stream at exactly `8 * bytes`
bits. A string's zero byte is refused as `EmbeddedNul` before its encoding is
validated (`InvalidUtf8`); the int_relative absolute tier refuses a current
outside the domain or not above previous as `ValueOutOfRange`, and then one no
more than 69914 above previous as `NonCanonical`, the difference formed in 64
bits so it cannot wrap.

**Security trumps.** Every refusal STANDARD.md (Reader Obligations, and each
operation's own rules) and serialize.go state is made, every time:

- a read that would consume more bits than remain fails with `PastEnd`
  BEFORE it reads (`bit_index + n > 8 * bytes`), so no read goes past the
  data's end and no partial value is produced;
- a refused read leaves its holder or destination untouched, and the stream
  is terminal after one refusal, keeping the first refusal's reason;
- a length-prefixed read (string) checks the claimed length against the bytes
  that remain BEFORE it allocates the payload;
- hostile bytes never raise: a raise is only ever API misuse by the caller,
  never data.

**The measure stream** is a conservative bound (STANDARD.md The Measure
Stream): exact width for every operation but `align`, `bytes` and `string`,
which charge the worst case of 7 alignment bits; `alignBits()` is 7; the end
costs nothing. Like serialize.go's, it latches what the writer latches on a
value (out of range, not finite) and raises on misuse like the writer.

**The skeleton's primitives** (in `serialize_stream.nut`, IMPLEMENTED) are
what every arm uses; an arm never touches the bit packer itself:

| primitive | WriteStream | ReadStream | MeasureStream |
|---|---|---|---|
| `s._fail(kind)` | latch kind if healthy; returns false | same | same |
| `s._room(n)` | false if latched; latches `PastEnd` if `bits + n > 8 * buffer.len()` | false if latched; latches `PastEnd` if `bits + n > 8 * data.len()` | false if latched, else true |
| `s._put(value, n)` / `s._take(n)` | writes one group, n in [1,32] | returns one group, n in [1,32] | `_put` counts n |
| `s._putBytes(data, offset, n)` / `s._takeBytes(dest, offset, n)` | n bytes, byte aligned | n bytes into dest, byte aligned | `_putBytes` counts 8n |
| `s.alignBits()` | `(8 - bits % 8) % 8` | same | 7 |

**The arm's shape**, in every family: (1) misuse checks, raising with
serialize.go's panic text; (2) `if (!s._room(n)) return false;` for the whole
width of the value, before any bit moves (a 64-bit value checks 64, then puts
two groups); (3) the moves; (4) on read, every refusal latched with
`s._fail(SerializeError.<reason>)`, and only after all of
them the holder assigned; (5) `return true`. A read refused after its bits
were taken keeps those bits counted, as serialize.go's does; the stream is
terminal either way.

## (h) THE FILE LAYOUT

`src/serialize.nut` is the entry and the loader; `src/serialize_stream.nut`
is the three streams. Each family is one file, created by one card, and no
two cards edit one file. The stream dispatches every serialize method to
`<module>.write`, `<module>.read` or `<module>.measure` `[method]`, requiring
the module LAZILY on the first call that needs it; while the file is absent
the method raises `serialize: <method> not implemented`, and a file without
that arm raises `serialize: <method> not implemented (<module>.nut has no <kind> arm)`. An arm is `function(stream, ...)` with the stream method's own
arguments after the stream. The API table's family functions are lazy the
same way.

| file | card | exports (beside the arms) | arms (`write`, `read`, `measure`) |
|---|---|---|---|
| `src/serialize.nut` | serialize-squirrel-design | the API table (a) | |
| `src/serialize_stream.nut` | serialize-squirrel-design | `SerializeError`, `Stream`, `WriteStream`, `ReadStream`, `MeasureStream`, `FAMILY`; `serializeEnd` is a stream method, not an arm | |
| `src/serialize_bitpacker.nut` | serialize-squirrel-bitpacker | `BitWriter(buffer)`: `writeBits(value, bits)` bits in [1,32], `writeAlign()`, `writeBytes(data, offset, n)`, `flushBits()`, `alignBits()`, `bitsWritten()`, `bitsAvailable()`, `bytesWritten()`, `data()`; `BitReader(data)`: `wouldReadPastEnd(bits)`, `readBits(bits)` bits in [1,32], `readAlign()` (true when the padding is zero), `readBytes(dest, offset, n)`, `alignBits()`, `bitsRead()`, `bitsRemaining()` | none |
| `src/serialize_bits.nut` | serialize-squirrel-bits | `bitsRequired(min, max)`, `bitsRequired64(min, max)`, `bitsRequired128(min, max)`, `signedToUnsigned(n)`, `unsignedToSigned(n)` | `serializeBits(s, h, bits)`, `serializeBits64(s, h, bits)`, `serializeBool(s, h)`, `serializeUint8(s, h)`, `serializeUint16(s, h)`, `serializeUint32(s, h)`, `serializeUint64(s, h)`, `serializeAlign(s)` |
| `src/serialize_int.nut` | serialize-squirrel-int | none | `serializeInt(s, h, min, max)`, `serializeInt64(s, h, min, max)` |
| `src/serialize_int128.nut` | serialize-squirrel-int | `int128From64(x)`, `uint128From64(x)`, and the two-lane helpers `serialize_fixed.nut` uses (`sub`, `cmp`, `lsh`, `rsh`, each on `[lo, hi]`) | `serializeInt128(s, h, min, max)`, `serializeUint128(s, h)` |
| `src/serialize_fixed.nut` | serialize-squirrel-fixed | none | `serializeFixed64(s, h, integerBits, fractionBits, min, max)`, `serializeFixed128(s, h, integerBits, fractionBits, min, max)` |
| `src/serialize_int_relative.nut` | serialize-squirrel-int-relative | none | `serializeIntRelative(s, previous, h)` |
| `src/serialize_float.nut` | serialize-squirrel-float | `fround(x)`, `float32Bits(x)` (the 32 bits of fround(x)), `float32FromBits(i)` (the double holding them), `floatBitsAreFinite(i)` | `serializeFloat(s, h)`, `serializeDouble(s, h)` |
| `src/serialize_compressed_float.nut` | serialize-squirrel-compressed-float | `compressedFloatParams(min, max, resolution)` returning `{ maxIntegerValue, bits, delta }` | `serializeCompressedFloat(s, h, min, max, resolution)`, `serializeCompressedFloatPrecomputed(s, h, maxIntegerValue, bits, delta, min)` |
| `src/serialize_bytes.nut` | serialize-squirrel-strings | none | `serializeBytes(s, data)`, `serializeString(s, h, bufferSize)` |

A family requires another only through `require` (the int_relative arms
reach `serialize_int`'s, compressed_float reaches `serialize_float`'s
`fround`, fixed reaches `serialize_int128`'s helpers). A card's own make
targets go in its own `make/<card>.mk` (the Makefile's `-include make/*.mk`),
and its tests in its own `test/<card>/` directory.

## (i) THE RUNNER

- `make dist-squirrel` fetches the pin
  (`https://github.com/albertodemichelis/squirrel/archive/refs/tags/v3.2.tar.gz`),
  refuses by name any sha256 but
  `02805414cfadd5bbb921891d3599b83375a40650abd6404a8ab407dc5e86a996`, and builds
  `make -C dist/squirrel-3.2 sq64 DEFS=-DSQUSEDOUBLE`. `dist/` is gitignored.
  It is setup, run once, never from a test. `SQ` is the pin, exported to every
  process make starts.
- `make toolchain-squirrel` refuses by name when `SQ` does not resolve; `make test` runs it first.
- `make test` runs every `test/*/*_test.nut`; `make test T=<name>` runs the
  files of `test/<name>/`. A missing or empty `test/<name>/` fails, naming it,
  never a skip.
- A test file declares root functions `function Test<Name>()` (the runner
  finds them by that line). A test passes by returning and fails by throwing.
  For each, the runner prints `RUN Test<Name>`, runs it in its own `sq`
  process from the scratch directory `build/test/<dir>/Test<Name>/` (the
  working directory a test may write in), through the generated driver
  `build/sqtest.nut`, which sets `::SERIALIZE_ROOT` to the repository root,
  runs the file and calls the test; then it prints `--- PASS Test<Name>` or
  `--- FAIL Test<Name>`, and exits nonzero on any failure.
- **`sq` exits 0 on a runtime error** (measured on the pin: an uncaught throw
  prints `AN ERROR HAS OCCURRED` and the call stack to stderr and exits 0;
  only a compile error exits nonzero). So a run passes only when `sq` exits 0
  AND writes nothing to stderr AND the driver printed its pass sentinel.
- **A throw across a native call is printed even when caught** (measured on
  the pin on `dofile` and `.call`; `.acall` is treated the same): a throw
  that crosses one writes the error and call stack to stderr although a `try`
  above catches it, and so fails the run by the rule above. So the library calls modules
  and arms directly (the loader binds a module's closure and calls it; lazy
  API wrappers have the function's own arity), and a test that expects a raise
  calls the raising function directly inside its `try`.
- A test reads `conformance/*.txt` itself, through `file(root + "/conformance/<name>.txt", "rb")` and `readblob`. Tests use no real time,
  no sockets, no network and no outside services; a test clock starts at
  1000.0.
- **The conformance runner** (`test/conformance/conformance_test.nut`)
  discovers `conformance/`, runs every vector, and requires each refused
  vector's stated reason as the stream's first refusal (`error()`); a missing
  or unknown reason is a malformed vector, red. It runs `writer_input` records
  on the writer, requires vector names unique across the corpus, and reads
  `end` as an operation and a step.
- **The negative controls** run in the same test, as STANDARD.md requires
  ("A gate nobody has seen go red is a claim, not a measurement"): the vendored
  `conformance-controls/unknown-operation.txt` and a file spelling the retired
  `wstring` must be rejected; and for each of the reference's fifteen refusal
  rules, a copy of `src/` under `build/controls/<rule>/` with that ONE rule
  deleted (needle and patch, the reference CMakeLists.txt's
  SERIALIZE_CONTROL_* in this port's spelling; a needle that does not occur
  exactly once fails the control), loaded through its own entry, must fail
  exactly the vectors `conformance-controls/<rule>.expected` names and no
  others. Where this port spells one reference rule at several sites (the
  padding of align, bytes and string; the ranged int of int, the int_relative
  payloads and the string length), the control deletes it at every site.
