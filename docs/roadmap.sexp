; The serialize.nut roadmap: planned work, as data, never evaluated.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment) and
; serialize.js's docs/roadmap.sexp. Created 2026-10-27 at the 2.1.0 wrap-up (Glenn, 2026-10-27:
; "I want all this on main in a place where we can stop soon"), holding the 2.1 work that release
; deferred; the audit findings and most of the uniform rules landed after it, the same day, and
; the last two items (u6-u9-one-write-misuse-mechanism, u15-extras-ruling) landed in 2.1.1.
(roadmap "v2.2"
 :title "serialize.nut roadmap"
 :text "Planned work for serialize.nut. 2.1.0 shipped the `rejected` reason (IMPLEMENTING.md U2), the v2.1.0 corpus, the 2026-10-27 audit findings (the 64-bit lanes, the UBSan CI leg, the int128 degenerate copy) and U1, U3 to U5, U7, U8 and U10 to U16. 2.1.1 shipped the serialize v2.1.1 rulings: U9's one write-misuse mechanism (the trap; TestU9WriteMisuseTraps), U6's measure that makes every write check and latches nothing (TestU6MeasureTraps), copyString's back-off to a whole character (TestU15CopyStringBackOff) and U15's export ruling (TestU15Exports; DESIGN.md (a)). No uniform-rule work is open."

 :groups
 (
  (group "uniform-rules" :title "IMPLEMENTING.md U1 to U16"
   :text "Each rule the port breaks gets a unit test that is red first, then the fix (IMPLEMENTING.md, Uniform behaviour). Rules already kept get a note.")
 )

 :items
 (
 ))
