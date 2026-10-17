# serialize.nut

A simple bitpacking serializer for Squirrel, wire compatible with the C++ [serialize](https://github.com/mas-bandwidth/serialize) library and [serialize.go](https://github.com/mas-bandwidth/serialize.go): the same values produce the same bytes.

Status: in progress: the design (DESIGN.md), the entry and loader (src/serialize.nut) and the streams (src/serialize_stream.nut) are in; each value family lands as its own file. `make dist-squirrel` builds the pinned interpreter and `make test` runs the tests. The wire format is serialize's STANDARD.md, format version 1.1. The pinned interpreter is Squirrel 3.2 (sq64, SQUSEDOUBLE).

BSD 3-Clause license.
