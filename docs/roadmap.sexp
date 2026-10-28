; The serialize.nut roadmap: planned work, as data, never evaluated.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment) and
; serialize.js's docs/roadmap.sexp. Created 2026-10-27 at the 2.1.0 wrap-up (Glenn, 2026-10-27:
; "I want all this on main in a place where we can stop soon"), holding the 2.1 work that release
; deferred; the audit findings and most of the uniform rules landed after it, the same day.
(roadmap "v2.2"
 :title "serialize.nut roadmap"
 :text "Planned work for serialize.nut. 2.1.0 shipped the `rejected` reason (IMPLEMENTING.md U2), the v2.1.0 corpus, the 2026-10-27 audit findings (the 64-bit lanes, the UBSan CI leg, the int128 degenerate copy) and U1, U3 to U5, U7, U8 and U10 to U16; what is left of the uniform rules is below."

 :groups
 (
  (group "uniform-rules" :title "IMPLEMENTING.md U1 to U16"
   :text "Each rule the port breaks gets a unit test that is red first, then the fix (IMPLEMENTING.md, Uniform behaviour). Rules already kept get a note.")
 )

 :items
 (
  (item "u6-u9-one-write-misuse-mechanism" :group "uniform-rules" :area "serialize.nut"
   :title "U6 and U9: one write-misuse mechanism, and a measure that latches nothing"
   :text "The port has two write-misuse mechanisms: a raise for a bad declaration and for a non-finite compressed float, and a latched ValueOutOfRange or NonFiniteFloat for a value out of range, a non-finite float or an over-wide bits value (DESIGN.md (g), serialize.go's split). U9 asks for one, applied to every operation; U6 asks a measure stream never to latch a read refusal, and today a measure latches value_out_of_range and non_finite_float. Choosing the one mechanism changes the public write contract and every family's write and measure arm, the fuzz differential against serialize.go and the smoke, end and family tests, so it is a design ruling first, then a sweep. Kept already: reject and fail on write and measure answer false, latch nothing and never raise."
   :done-when "DESIGN.md (g) names the one write-misuse mechanism; every write and measure arm uses it for every misuse, compressed_float included; a measure stream's error() stays null through any misuse; test/uniform/ has TestU6 and TestU9, red before the change and green after; make test, make test-ubsan and make fuzz are green."
   :date "2026-10-27"
   :origin "IMPLEMENTING.md U6, U9 (serialize v2.1.0); left at the 2.1.0 rules landing")
  (item "u15-extras-ruling" :group "uniform-rules" :area "serialize.nut"
   :title "U15: a ruling on the port's extra exports"
   :text "U15 allows Bits64, Continue/Until and batch APIs and nothing else without a ruling. The port also exports serialize.go's helpers: BitWriter, BitReader, bitsRequired/64/128, signedToUnsigned, unsignedToSigned, int128From64, uint128From64 and fround (compressedFloatParams is the reference's compressed_float_params). The missing reference operation, serialize_copy_string, landed as copyString in 2.1.0."
   :done-when "IMPLEMENTING.md or a recorded ruling lists each of these exports as allowed, or the port drops the ones it does not allow; DESIGN.md (a) says which."
   :date "2026-10-27"
   :origin "IMPLEMENTING.md U15 (serialize v2.1.0)")
 ))
