; The serialize.nut roadmap: planned work, as data, never evaluated.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment) and
; serialize.js's docs/roadmap.sexp. Created 2026-10-27 at the 2.1.0 wrap-up (Glenn, 2026-10-27:
; "I want all this on main in a place where we can stop soon"), holding the 2.1 work that release
; deferred. The audit reproducers named below live outside this repository, under
; /Volumes/nova/ai/rowan/working/serialize-love/audit2/serialize.nut/audit/.
(roadmap "v2.2"
 :title "serialize.nut roadmap"
 :text "Planned work for serialize.nut. 2.1.0 shipped the `rejected` reason (IMPLEMENTING.md U2) and the v2.1.0 corpus; the uniform rules and the 2026-10-27 audit findings below were deferred to keep main green at the wrap-up."

 :groups
 (
  (group "uniform-rules" :title "IMPLEMENTING.md U1 to U16"
   :text "Each rule the port breaks gets a unit test that is red first, then the fix (IMPLEMENTING.md, Uniform behaviour). Rules already kept get a note.")
  (group "audit-2026-10-27" :title "Audit findings of 2026-10-27"
   :text "The port's entries under the nut heading of the audit ledger. Run each reproducer first and confirm it fails before fixing.")
 )

 :items
 (
  (item "u5-int-bounds-int32" :group "uniform-rules" :area "serialize_int"
   :title "U5: serializeInt bounds outside int32 are caller error, caught on the caller's value before narrowing"
   :text "A min or max outside int32 must never become a silent zero-bit or narrowed field. Write and measure: the write-misuse mechanism (a raise). Read: refuse as value_out_of_range (U7, U16), never raise. Unit test red first in test/int/."
   :done-when "test/int/ has a test that serializeInt with min or max outside [-2^31, 2^31 - 1] raises on write and measure and refuses as value_out_of_range on read; it was red before the fix and is green after; make test is green."
   :date "2026-10-27"
   :origin "IMPLEMENTING.md U5 (serialize v2.1.0); assigned with the 2.1 port brief")
  (item "u-rules-audit" :group "uniform-rules" :area "serialize.nut"
   :title "U1, U3, U4, U6 to U16: check each rule against the port, fix the ones it breaks"
   :text "Not yet checked rule by rule. Known shapes to look at: U14 asks for a public fail(reason) that maps no reason or an unknown one to rejected; U9 asks reject and fail on write or measure to answer false (reject already does); U7 asks caller misuse on read (negative byte count, string buffer below 1) to refuse as value_out_of_range rather than raise."
   :done-when "Each of U1, U3, U4, U6 to U16 is recorded as kept (with the test that shows it) or broken and fixed (with a unit test red before the fix, green after); make test is green."
   :date "2026-10-27"
   :origin "IMPLEMENTING.md U1-U16 (serialize v2.1.0); deferred at the 2.1.0 wrap-up")
  (item "audit-m-int-overflow" :group "audit-2026-10-27" :area "serialize_int, serialize_int128, serialize_fixed, serialize_bits"
   :title "M: signed 64-bit overflow (C++ UB in the VM) in int64, int128, fixed and bits math; wire-driven for int128 over [1, 2^64]"
   :text "DESIGN.md promises the arithmetic never overflows. Route the offending sums, differences and shifts through the add64/sub64/shl64 lanes. Reproducers: audit/repro_int128_overflow.nut, audit/repro_int64_overflow.nut, run under the UBSan interpreter built by audit/build-ubsan.sh."
   :done-when "repro_int128_overflow.nut and repro_int64_overflow.nut run clean under the UBSan interpreter (they report overflow before the fix); a unit test pins the int128 [1, 2^64] read; make test is green."
   :date "2026-10-27"
   :origin "audit ledger, nut M; reproducers /Volumes/nova/ai/rowan/working/serialize-love/audit2/serialize.nut/audit/repro_int128_overflow.nut and repro_int64_overflow.nut")
  (item "audit-l-ubsan-ci" :group "audit-2026-10-27" :area "ci"
   :title "L: CI has no UBSan interpreter leg"
   :text "Add a CI leg that builds the pinned interpreter with -fsanitize=undefined (audit/build-ubsan.sh is the starting point) and runs make test under it, with suppressions for the VM's own reports."
   :done-when "ci.yml runs make test on a UBSan build of the pinned interpreter; the leg goes red on repro_int128_overflow.nut before the overflow fix; check-ci holds the leg."
   :date "2026-10-27"
   :origin "audit ledger, nut L; /Volumes/nova/ai/rowan/working/serialize-love/audit2/serialize.nut/audit/build-ubsan.sh")
  (item "audit-l-int128-degenerate-alias" :group "audit-2026-10-27" :area "serialize_int128"
   :title "L: a degenerate int128 read (min == max) hands back the caller's min array itself"
   :text "The zero-bit read assigns the caller's min array to the holder, so a later write through the holder changes the caller's bound. Copy the lanes. Reproducer: audit/repro_int128_degenerate_alias.nut."
   :done-when "a unit test in test/int/ mutates the holder after a degenerate int128 read and sees min unchanged; red before the fix, green after; make test is green."
   :date "2026-10-27"
   :origin "audit ledger, nut L; /Volumes/nova/ai/rowan/working/serialize-love/audit2/serialize.nut/audit/repro_int128_degenerate_alias.nut")
 ))
