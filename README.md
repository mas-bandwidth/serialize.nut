# serialize.nut

A simple bitpacking serializer for Squirrel, wire compatible with the C++ [serialize](https://github.com/mas-bandwidth/serialize) library and [serialize.go](https://github.com/mas-bandwidth/serialize.go): the same values produce the same bytes.

The wire format is serialize's STANDARD.md, **format version 2.0** (standard 2.1, vendored from serialize v2.1.0): the wire carries only integers and bytes, and every value has exactly one encoding. Floats and doubles are finite only, strings are well-formed UTF-8 with no zero byte, and every refusal names its reason (`stream.error()` is one of `past_end`, `value_out_of_range`, `nonzero_padding`, `trailing_data`, `non_finite_float`, `invalid_utf8`, `embedded_nul`, `non_canonical`, `rejected`). A caller refuses a value whose bytes were well formed with `stream.reject()`, or by returning `false` from a nested object's `serialize`; both latch `rejected`, and the first reason wins. A packet reader reads its top-level object and then calls `serializeEnd()`, which refuses trailing bytes and set padding:

```squirrel
local serialize = dofile(dir + "/src/serialize.nut", true);
local rs = serialize.ReadStream(packet);
if (!rs.serializeObject(message) || !rs.serializeEnd()) print("refused: " + rs.error() + "\n");
```

The pinned interpreter is Squirrel 3.2 built sq64 with SQUSEDOUBLE: `make dist-squirrel` builds it and `make test` runs the tests, the conformance corpus and its negative controls; `make fuzz` runs the differential against serialize.go v2.0.0 and `make fuzz-negative-control` proves it goes red; the nightly-fuzz workflow runs the same differential for an hour from a random, logged seed (`make fuzz FUZZ_ARGS='-seed 0x...'` replays a round). DESIGN.md is the design.

BSD 3-Clause license.
