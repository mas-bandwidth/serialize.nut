// TestDifferentialAgainstSerializeGo: serialize-squirrel-fuzz-differential.
//
// A fuzz differential of the Squirrel port against its reference,
// github.com/mas-bandwidth/serialize.go v1.15.1 (DESIGN.md, Pins). From a FIXED
// seed (math/rand/v2 PCG with constant seeds; no clock) it generates 2000
// random programs, each a sequence of 1 to 24 operations drawn from every
// operation serialize.go has, with values in range, and for each program:
//
//  1. serialize.go writes it, and the Squirrel port (fuzz/driver.nut under the
//     pinned interpreter, DESIGN.md (i)) writes it; the bytes must be equal
//     (DESIGN.md (g), the writer is STRICT).
//  2. Each side reads the other's bytes; the decoded values must equal the
//     program's (floats by bit pattern; a compressed float by the value
//     serialize.go itself decodes from its own bytes, since quantization is
//     lossy), and both must consume the bits the writer wrote.
//  3. For 1 in 4 programs the bytes are mutated (bit flips, truncation,
//     extension) and both readers must agree on accept or refuse, on the index
//     of the step that refused, on the error kind, and on every value decoded
//     before it (STANDARD.md, Reader Obligations; DESIGN.md (g), security
//     trumps).
//  4. For 1 in 8 programs whose bytes exceed one 8-byte word, both writers
//     write into a buffer one word too short and must refuse at the same step
//     with the same kind (DESIGN.md (g): a full buffer latches Overflow
//     exactly where serialize.go's WriteStream returns ErrOverflow).
//
// The driver takes programs as text, one interpreter process per batch of 100
// programs, the batch in a file in a t.TempDir() (DESIGN.md (i), the runner),
// and prints results as lowercase hex lines.
//
// THE NEGATIVE CONTROL. The test-only flag -sabotage-widen-int makes the Go
// side write every non-degenerate int range one bit wider; with it the test
// must go red (make fuzz-negative-control runs it and requires the red). The
// same sabotaged writer also runs inside every normal run, over the same
// programs, through the same comparison, and the run fails unless that
// comparison goes red on it.
package fuzz

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	serialize "github.com/mas-bandwidth/serialize.go"
)

var sabotageWidenInt = flag.Bool("sabotage-widen-int", false,
	"test only: the Go writer writes every non-degenerate int range one bit wider, so the differential must go red")

const (
	programCount = 2000
	batchSize    = 100
	maxOps       = 24
	writeCap     = 8192 // bytes; a multiple of 8 (STANDARD.md General Conventions)
	seed1        = 0x5e7a11a15e7a11a1
	seed2        = 0x00d1ff0000d1ff00
)

// ---------------------------------------------------------------------------
// the program model

type step struct {
	kind  string
	width int // bits / bits64 width; object span; string / wstring buffer size
	ib    int // fixed integer bits
	fb    int // fixed fraction bits
	min   serialize.Int128
	max   serialize.Int128
	prev  int32
	fmin  float32
	fmax  float32
	fres  float32
	u     serialize.Uint128 // numeric value bits (signed kinds sign extended)
	b     bool
	data  []byte // bytes, string (UTF-8), wstring (UTF-8)
}

var minInt128 = serialize.Int128{Lo: 0, Hi: 1 << 63}
var maxInt128 = serialize.Int128{Lo: math.MaxUint64, Hi: math.MaxInt64}

func hex128(lo, hi uint64) string { return fmt.Sprintf("%016x%016x", hi, lo) }
func hexI(x serialize.Int128) string { return hex128(x.Lo, x.Hi) }
func hexU(x serialize.Uint128) string { return hex128(x.Lo, x.Hi) }
func hexS(x int64) string        { return hexI(serialize.Int128From64(x)) }
func hexBytes(b []byte) string    { return "x" + fmt.Sprintf("%x", b) }

// text renders a step as the driver's program spelling (fuzz/driver.nut, THE
// PROGRAM TEXT).
func (s *step) text() string {
	switch s.kind {
	case "bits", "bits64":
		return fmt.Sprintf("%s %d %s", s.kind, s.width, hexU(s.u))
	case "uint8", "uint16", "uint32", "uint64", "uint128", "float", "double":
		return s.kind + " " + hexU(s.u)
	case "bool":
		if s.b {
			return "bool 1"
		}
		return "bool 0"
	case "int", "int64", "int128":
		return fmt.Sprintf("%s %s %s %s", s.kind, hexI(s.min), hexI(s.max), hexU(s.u))
	case "fixed64", "fixed128":
		return fmt.Sprintf("%s %d %d %s %s %s", s.kind, s.ib, s.fb, hexI(s.min), hexI(s.max), hexU(s.u))
	case "int_relative":
		return fmt.Sprintf("int_relative %s %s", hexS(int64(s.prev)), hexU(s.u))
	case "cfloat", "cfloatpre":
		return fmt.Sprintf("%s %s %s %s %s", s.kind,
			hexU(serialize.Uint128{Lo: uint64(math.Float32bits(s.fmin))}),
			hexU(serialize.Uint128{Lo: uint64(math.Float32bits(s.fmax))}),
			hexU(serialize.Uint128{Lo: uint64(math.Float32bits(s.fres))}), hexU(s.u))
	case "bytes":
		return "bytes " + hexBytes(s.data)
	case "string", "wstring":
		return fmt.Sprintf("%s %d %s", s.kind, s.width, hexBytes(s.data))
	case "align":
		return "align"
	case "object":
		return fmt.Sprintf("object %d", s.width)
	}
	panic("no text for step kind " + s.kind)
}

func programText(steps []step) string {
	parts := make([]string, len(steps))
	for i := range steps {
		parts[i] = steps[i].text()
	}
	return strings.Join(parts, " ")
}

// programValue is the rendered value the program states for step i, the token
// a reader must decode ("-" for a step with no value of its own).
func programValue(s *step) string {
	switch s.kind {
	case "bool":
		if s.b {
			return "1"
		}
		return "0"
	case "bytes", "string", "wstring":
		return hexBytes(s.data)
	case "align", "object":
		return "-"
	}
	return hexU(s.u)
}

// ---------------------------------------------------------------------------
// the generator (fixed seed, values in range)

type gen struct{ r *rand.Rand }

func (g *gen) u64LE(n uint64) uint64 {
	if n == math.MaxUint64 {
		return g.r.Uint64()
	}
	return g.r.Uint64N(n + 1)
}

func (g *gen) u128LE(n serialize.Uint128) serialize.Uint128 {
	if n.Hi == 0 {
		return serialize.Uint128{Lo: g.u64LE(n.Lo)}
	}
	for {
		hi := g.u64LE(n.Hi)
		lo := g.r.Uint64()
		if hi < n.Hi || lo <= n.Lo {
			return serialize.Uint128{Lo: lo, Hi: hi}
		}
	}
}

// range64 draws [min,max] inside [lo,hi]: the full range, a degenerate one, a
// power-of-two width (exactly 2^k and 2^k - 1, the bits_required edges), an
// edge-hugging one, or a random pair (STANDARD.md int (ranged)).
func (g *gen) range64(lo, hi int64) (int64, int64) {
	span := uint64(hi) - uint64(lo)
	at := func(off uint64) int64 { return int64(uint64(lo) + off) }
	switch g.r.IntN(6) {
	case 0:
		return lo, hi
	case 1:
		v := at(g.u64LE(span))
		return v, v
	case 2:
		w := uint64(1) << g.r.IntN(64)
		if g.r.IntN(2) == 0 {
			w--
		}
		if w > span {
			w = span
		}
		start := g.u64LE(span - w)
		return at(start), at(start + w)
	case 3:
		w := g.u64LE(min(span, 300))
		if g.r.IntN(2) == 0 {
			return lo, at(w)
		}
		return at(span - w), hi
	default:
		a, b := at(g.u64LE(span)), at(g.u64LE(span))
		if a > b {
			a, b = b, a
		}
		return a, b
	}
}

// pick64 draws a value in [min,max], favouring the edges.
func (g *gen) pick64(lo, hi int64) int64 {
	span := uint64(hi) - uint64(lo)
	switch g.r.IntN(6) {
	case 0:
		return lo
	case 1:
		return hi
	case 2:
		if span > 0 {
			return int64(uint64(lo) + 1)
		}
		return lo
	case 3:
		if span > 0 {
			return int64(uint64(hi) - 1)
		}
		return hi
	}
	return int64(uint64(lo) + g.u64LE(span))
}

func (g *gen) range128() (serialize.Int128, serialize.Int128) {
	switch g.r.IntN(5) {
	case 0:
		return minInt128, maxInt128
	case 1:
		v := serialize.Int128{Lo: g.r.Uint64(), Hi: g.r.Uint64()}
		return v, v
	case 2:
		a, b := g.range64(math.MinInt64, math.MaxInt64)
		return serialize.Int128From64(a), serialize.Int128From64(b)
	case 3:
		k := g.r.IntN(128)
		w := serialize.Uint128From64(1).Lsh(uint(k))
		if g.r.IntN(2) == 0 {
			w = w.Sub(serialize.Uint128From64(1))
		}
		full := serialize.Uint128{Lo: math.MaxUint64, Hi: math.MaxUint64}
		start := g.u128LE(full.Sub(w))
		base := minInt128.Uint128()
		return start.Add(base).Int128(), start.Add(w).Add(base).Int128()
	default:
		a := serialize.Int128{Lo: g.r.Uint64(), Hi: g.r.Uint64()}
		b := serialize.Int128{Lo: g.r.Uint64(), Hi: g.r.Uint64()}
		if a.Cmp(b) > 0 {
			a, b = b, a
		}
		return a, b
	}
}

func (g *gen) pick128(lo, hi serialize.Int128) serialize.Int128 {
	switch g.r.IntN(4) {
	case 0:
		return lo
	case 1:
		return hi
	}
	span := hi.Uint128().Sub(lo.Uint128())
	return lo.Uint128().Add(g.u128LE(span)).Int128()
}

// fixedCapacity is serialize.go's fixedPointCapacity (stream.go), restated: the
// whole unit bounds a Q format holds (STANDARD.md fixed).
func fixedCapacity(integerBits int, signed bool) (int64, int64) {
	if signed {
		if integerBits >= 65 {
			return math.MinInt64, math.MaxInt64
		}
		lo := int64(-(uint64(1) << (integerBits - 1)))
		if integerBits >= 64 {
			return lo, math.MaxInt64
		}
		return lo, int64(uint64(1)<<(integerBits-1) - 1)
	}
	if integerBits >= 63 {
		return 0, math.MaxInt64
	}
	return 0, int64(uint64(1)<<integerBits - 1)
}

func (g *gen) float32Bits() uint32 {
	sign := uint32(g.r.IntN(2)) << 31
	switch g.r.IntN(8) {
	case 0: // a NaN, signalling or quiet, with a payload
		return sign | 0x7f800000 | (1 + g.r.Uint32N(0x7fffff))
	case 1: // a signalling NaN with the smallest payload
		return sign | 0x7f800001
	case 2:
		return sign | 0x7f800000 // infinity
	case 3:
		return sign // zero
	case 4: // a subnormal
		return sign | (1 + g.r.Uint32N(0x7fffff))
	}
	return g.r.Uint32()
}

func (g *gen) float64Bits() uint64 {
	sign := uint64(g.r.IntN(2)) << 63
	switch g.r.IntN(8) {
	case 0:
		return sign | 0x7ff0000000000000 | (1 + g.r.Uint64N(0xfffffffffffff))
	case 1:
		return sign | 0x7ff0000000000001
	case 2:
		return sign | 0x7ff0000000000000
	case 3:
		return sign
	case 4:
		return sign | (1 + g.r.Uint64N(0xfffffffffffff))
	}
	return g.r.Uint64()
}

func (g *gen) runeOf() rune {
	switch g.r.IntN(4) {
	case 0:
		return rune(0x80 + g.r.IntN(0x800-0x80))
	case 1:
		for {
			r := rune(0x800 + g.r.IntN(0x10000-0x800))
			if r < 0xd800 || r > 0xdfff {
				return r
			}
		}
	case 2:
		return rune(0x10000 + g.r.IntN(0x110000-0x10000))
	}
	return rune(1 + g.r.IntN(0x7f)) // ASCII, never NUL (STANDARD.md string)
}

func (g *gen) compressed(s *step) {
	s.fmin = float32(math.Round((g.r.Float64()*2000-1000)*8) / 8)
	widths := []float32{0.5, 1, 10, 100, 1000, 3.25, 0.001}
	width := widths[g.r.IntN(len(widths))]
	s.fmax = s.fmin + width
	if !(s.fmin < s.fmax) {
		s.fmax = s.fmin + 1
	}
	delta := s.fmax - s.fmin
	switch g.r.IntN(4) {
	case 0: // the integer clamp's edge: a quantized range in [2^23, 2^24)
		s.fres = delta / float32((1<<23)+g.r.IntN(1<<23))
	case 1:
		s.fres = delta * 2 // one step
	default:
		res := []float32{0.001, 0.01, 0.1, 0.5, 1, 0.37, 0.0001}
		s.fres = res[g.r.IntN(len(res))]
	}
	if !(s.fres > 0) {
		s.fres = 0.5
	}
	var v float32
	switch g.r.IntN(5) {
	case 0:
		v = s.fmin
	case 1:
		v = s.fmax
	case 2: // a half-quantum boundary
		v = s.fmin + (float32(g.r.IntN(64))+0.5)*s.fres
	default:
		v = s.fmin + float32(g.r.Float64())*delta
	}
	if !(v >= s.fmin) {
		v = s.fmin
	}
	if !(v <= s.fmax) {
		v = s.fmax
	}
	s.u = serialize.Uint128{Lo: uint64(math.Float32bits(v))}
}

var leafKinds = []string{
	"bits", "bits64", "bool", "uint8", "uint16", "uint32", "uint64", "uint128",
	"int", "int64", "int128", "fixed64", "fixed128", "int_relative",
	"float", "double", "cfloat", "cfloatpre", "bytes", "string", "wstring", "align",
}

func (g *gen) leaf(kind string) step {
	s := step{kind: kind}
	switch kind {
	case "bits":
		s.width = 1 + g.r.IntN(32)
		s.u = serialize.Uint128{Lo: g.r.Uint64() & (math.MaxUint64 >> (64 - s.width))}
	case "bits64":
		s.width = 1 + g.r.IntN(64)
		s.u = serialize.Uint128{Lo: g.r.Uint64() & (math.MaxUint64 >> (64 - s.width))}
	case "bool":
		s.b = g.r.IntN(2) == 0
	case "uint8":
		s.u = serialize.Uint128{Lo: uint64(g.r.Uint32N(1 << 8))}
	case "uint16":
		s.u = serialize.Uint128{Lo: uint64(g.r.Uint32N(1 << 16))}
	case "uint32":
		s.u = serialize.Uint128{Lo: uint64(g.r.Uint32())}
	case "uint64":
		s.u = serialize.Uint128{Lo: g.r.Uint64()}
	case "uint128":
		s.u = serialize.Uint128{Lo: g.r.Uint64(), Hi: g.r.Uint64()}
	case "int":
		a, b := g.range64(math.MinInt32, math.MaxInt32)
		s.min, s.max = serialize.Int128From64(a), serialize.Int128From64(b)
		s.u = serialize.Int128From64(g.pick64(a, b)).Uint128()
	case "int64":
		a, b := g.range64(math.MinInt64, math.MaxInt64)
		s.min, s.max = serialize.Int128From64(a), serialize.Int128From64(b)
		s.u = serialize.Int128From64(g.pick64(a, b)).Uint128()
	case "int128":
		s.min, s.max = g.range128()
		s.u = g.pick128(s.min, s.max).Uint128()
	case "fixed64":
		s.ib = 1 + g.r.IntN(64)
		s.fb = g.r.IntN(64 - s.ib + 1)
		lo, hi := fixedCapacity(s.ib, g.r.IntN(2) == 0)
		a, b := g.range64(lo, hi)
		s.min, s.max = serialize.Int128From64(a), serialize.Int128From64(b)
		rawMin := uint64(a) << s.fb
		rawRange := (uint64(b) << s.fb) - rawMin
		s.u = serialize.Int128From64(int64(rawMin + g.u64LE(rawRange))).Uint128()
	case "fixed128":
		s.ib = 1 + g.r.IntN(128)
		s.fb = 128 - s.ib
		lo, hi := fixedCapacity(s.ib, g.r.IntN(2) == 0)
		a, b := g.range64(lo, hi)
		s.min, s.max = serialize.Int128From64(a), serialize.Int128From64(b)
		rawMin := serialize.Int128From64(a).Uint128().Lsh(uint(s.fb))
		rawRange := serialize.Int128From64(b).Uint128().Lsh(uint(s.fb)).Sub(rawMin)
		s.u = rawMin.Add(g.u128LE(rawRange))
	case "int_relative":
		s.prev = int32(g.pick64(0, math.MaxInt32-1))
		buckets := [][2]int64{{1, 1}, {2, 6}, {7, 23}, {24, 280}, {281, 4377}, {4378, 69914}, {69915, math.MaxInt32}}
		bk := buckets[g.r.IntN(len(buckets))]
		d := g.pick64(bk[0], bk[1])
		if int64(s.prev)+d > math.MaxInt32 {
			d = math.MaxInt32 - int64(s.prev)
		}
		s.u = serialize.Int128From64(int64(s.prev) + d).Uint128()
	case "float":
		s.u = serialize.Uint128{Lo: uint64(g.float32Bits())}
	case "double":
		s.u = serialize.Uint128{Lo: g.float64Bits()}
	case "cfloat", "cfloatpre":
		g.compressed(&s)
	case "bytes":
		s.data = make([]byte, g.r.IntN(41))
		for i := range s.data {
			s.data[i] = byte(g.r.Uint32())
		}
	case "string":
		s.width = 1 + g.r.IntN(64)
		target := g.r.IntN(s.width) // fewer than bufferSize bytes
		var out []byte
		for {
			r := g.runeOf()
			if len(out)+utf8.RuneLen(r) > target {
				break
			}
			out = utf8.AppendRune(out, r)
		}
		s.data = out
	case "wstring":
		s.width = 1 + g.r.IntN(32)
		target := g.r.IntN(s.width) // fewer than bufferSize code units
		var out []byte
		units := 0
		for {
			r := g.runeOf()
			n := utf16.RuneLen(r)
			if units+n > target {
				break
			}
			units += n
			out = utf8.AppendRune(out, r)
		}
		s.data = out
	case "align":
	default:
		panic("no generator for " + kind)
	}
	return s
}

// program appends up to budget flat steps; an object spans the steps it
// contains (STANDARD.md object: no bytes of its own), nested at most twice.
func (g *gen) program(budget, depth int) []step {
	var out []step
	for len(out) < budget {
		if depth < 2 && budget-len(out) >= 2 && g.r.IntN(12) == 0 {
			inner := g.program(1+g.r.IntN(min(3, budget-len(out)-1)), depth+1)
			out = append(out, step{kind: "object", width: len(inner)})
			out = append(out, inner...)
			continue
		}
		out = append(out, g.leaf(leafKinds[g.r.IntN(len(leafKinds))]))
	}
	return out
}

// ---------------------------------------------------------------------------
// the Go side: one step runner for write and read (serialize.go's Stream)

type precomputed interface {
	SerializeCompressedFloat32Precomputed(value *float32, maxIntegerValue uint32, bits int, delta, min float32) error
}

type runner struct {
	steps    []step
	vals     []string
	endBits  []int64
	failIdx  int
	sabotage bool
}

type object struct {
	r        *runner
	from, to int
}

func (o *object) Serialize(s serialize.Stream) error {
	_, err := o.r.run(s, o.from, o.to)
	return err
}

func (r *runner) run(s serialize.Stream, from, to int) (int, error) {
	i := from
	for i < to {
		st := &r.steps[i]
		if st.kind == "object" {
			r.vals[i] = "-"
			if err := s.SerializeObject(&object{r: r, from: i + 1, to: i + 1 + st.width}); err != nil {
				if r.failIdx < 0 {
					r.failIdx = i
				}
				return i, err
			}
			r.endBits[i] = s.BitsProcessed()
			i += 1 + st.width
			continue
		}
		if err := r.one(s, i); err != nil {
			if r.failIdx < 0 {
				r.failIdx = i
			}
			return i, err
		}
		r.endBits[i] = s.BitsProcessed()
		i++
	}
	return to, nil
}

func (r *runner) one(s serialize.Stream, i int) error {
	st := &r.steps[i]
	set := func(v string) { r.vals[i] = v }
	switch st.kind {
	case "bits":
		v := uint32(st.u.Lo)
		if err := s.SerializeBits(&v, st.width); err != nil {
			return err
		}
		set(hex128(uint64(v), 0))
	case "bits64":
		v := st.u.Lo
		if err := s.SerializeBits64(&v, st.width); err != nil {
			return err
		}
		set(hex128(v, 0))
	case "bool":
		v := st.b
		if err := s.SerializeBool(&v); err != nil {
			return err
		}
		if v {
			set("1")
		} else {
			set("0")
		}
	case "uint8":
		v := uint8(st.u.Lo)
		if err := s.SerializeUint8(&v); err != nil {
			return err
		}
		set(hex128(uint64(v), 0))
	case "uint16":
		v := uint16(st.u.Lo)
		if err := s.SerializeUint16(&v); err != nil {
			return err
		}
		set(hex128(uint64(v), 0))
	case "uint32":
		v := uint32(st.u.Lo)
		if err := s.SerializeUint32(&v); err != nil {
			return err
		}
		set(hex128(uint64(v), 0))
	case "uint64":
		v := st.u.Lo
		if err := s.SerializeUint64(&v); err != nil {
			return err
		}
		set(hex128(v, 0))
	case "uint128":
		v := st.u
		if err := s.SerializeUint128(&v); err != nil {
			return err
		}
		set(hexU(v))
	case "int":
		v, lo, hi := int32(st.u.Lo), int32(st.min.Lo), int32(st.max.Lo)
		if r.sabotage && s.IsWriting() {
			// THE NEGATIVE CONTROL: this one int range one bit wider
			if bits := serialize.BitsRequired(uint32(lo), uint32(hi)); bits >= 1 && bits < 32 {
				off := uint32(v) - uint32(lo)
				return s.SerializeBits(&off, bits+1)
			}
		}
		if err := s.SerializeInt(&v, lo, hi); err != nil {
			return err
		}
		set(hexS(int64(v)))
	case "int64":
		v := int64(st.u.Lo)
		if err := s.SerializeInt64(&v, int64(st.min.Lo), int64(st.max.Lo)); err != nil {
			return err
		}
		set(hexS(v))
	case "int128":
		v := st.u.Int128()
		if err := s.SerializeInt128(&v, st.min, st.max); err != nil {
			return err
		}
		set(hexI(v))
	case "fixed64":
		v := int64(st.u.Lo)
		if err := s.SerializeFixed64(&v, st.ib, st.fb, int64(st.min.Lo), int64(st.max.Lo)); err != nil {
			return err
		}
		set(hexS(v))
	case "fixed128":
		v := st.u.Int128()
		if err := s.SerializeFixed128(&v, st.ib, st.fb, int64(st.min.Lo), int64(st.max.Lo)); err != nil {
			return err
		}
		set(hexI(v))
	case "int_relative":
		v := int32(st.u.Lo)
		if err := s.SerializeIntRelative(st.prev, &v); err != nil {
			return err
		}
		set(hexS(int64(v)))
	case "float":
		v := math.Float32frombits(uint32(st.u.Lo))
		if err := s.SerializeFloat32(&v); err != nil {
			return err
		}
		set(hex128(uint64(math.Float32bits(v)), 0))
	case "double":
		v := math.Float64frombits(st.u.Lo)
		if err := s.SerializeFloat64(&v); err != nil {
			return err
		}
		set(hex128(math.Float64bits(v), 0))
	case "cfloat":
		v := math.Float32frombits(uint32(st.u.Lo))
		if err := s.SerializeCompressedFloat32(&v, st.fmin, st.fmax, st.fres); err != nil {
			return err
		}
		set(hex128(uint64(math.Float32bits(v)), 0))
	case "cfloatpre":
		v := math.Float32frombits(uint32(st.u.Lo))
		m, bits, delta := serialize.CompressedFloatParams(st.fmin, st.fmax, st.fres)
		if err := s.(precomputed).SerializeCompressedFloat32Precomputed(&v, m, bits, delta, st.fmin); err != nil {
			return err
		}
		set(hex128(uint64(math.Float32bits(v)), 0))
	case "bytes":
		data := make([]byte, len(st.data))
		if s.IsWriting() {
			copy(data, st.data)
		}
		if err := s.SerializeBytes(data); err != nil {
			return err
		}
		set(hexBytes(data))
	case "string":
		v := ""
		if s.IsWriting() {
			v = string(st.data)
		}
		if err := s.SerializeString(&v, st.width); err != nil {
			return err
		}
		set(hexBytes([]byte(v)))
	case "wstring":
		v := ""
		if s.IsWriting() {
			v = string(st.data)
		}
		if err := s.SerializeWideString(&v, st.width); err != nil {
			return err
		}
		set(hexBytes([]byte(v)))
	case "align":
		if err := s.SerializeAlign(); err != nil {
			return err
		}
		set("-")
	default:
		panic("no runner for " + st.kind)
	}
	return nil
}

func errKind(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, serialize.ErrOverflow):
		return "overflow"
	case errors.Is(err, serialize.ErrValueOutOfRange):
		return "value_out_of_range"
	case errors.Is(err, serialize.ErrAlign):
		return "align"
	}
	return "other:" + err.Error()
}

// result is one side's outcome of a write or a read, in the driver's terms.
type result struct {
	ok      bool
	idx     int    // the refusing step, when !ok
	kind    string // the latched error kind, when !ok
	bytes   []byte // a write's flushed data
	bits    int64  // a read's bits consumed, when ok
	vals    []string
	endBits []int64
}

func goWrite(steps []step, capacity int, sabotage bool) result {
	r := &runner{steps: steps, vals: make([]string, len(steps)), endBits: make([]int64, len(steps)), failIdx: -1, sabotage: sabotage}
	ws := serialize.NewWriteStream(make([]byte, capacity))
	if _, err := r.run(ws, 0, len(steps)); err != nil {
		return result{idx: r.failIdx, kind: errKind(err)}
	}
	ws.Flush()
	return result{ok: true, bytes: append([]byte(nil), ws.Data()...), bits: ws.BitsProcessed(), endBits: r.endBits}
}

func goRead(steps []step, data []byte) result {
	r := &runner{steps: steps, vals: make([]string, len(steps)), endBits: make([]int64, len(steps)), failIdx: -1}
	rs := serialize.NewReadStream(data)
	if _, err := r.run(rs, 0, len(steps)); err != nil {
		return result{idx: r.failIdx, kind: errKind(err), vals: r.vals[:r.failIdx]}
	}
	return result{ok: true, bits: rs.BitsProcessed(), vals: r.vals}
}

// ---------------------------------------------------------------------------
// the Squirrel side: fuzz/driver.nut under the pinned interpreter

type request struct {
	id   string
	line string
}

func parseResult(fields []string, n int) (result, error) {
	// <id> <w|r> ok x<hex>                    a write
	// <id> <w|r> ok <bits> <v0> ... <vn-1>    a read
	// <id> <w|r> refused <idx> <kind> <v0> ... <vidx-1>
	if len(fields) < 3 {
		return result{}, fmt.Errorf("short result line %q", strings.Join(fields, " "))
	}
	op, status := fields[1], fields[2]
	if status == "ok" && op == "w" {
		if len(fields) != 4 || !strings.HasPrefix(fields[3], "x") {
			return result{}, fmt.Errorf("bad write result %q", strings.Join(fields, " "))
		}
		b, err := decodeX(fields[3])
		return result{ok: true, bytes: b}, err
	}
	if status == "ok" && op == "r" {
		if len(fields) != 4+n {
			return result{}, fmt.Errorf("read result has %d values, the program has %d steps: %q", len(fields)-4, n, strings.Join(fields, " "))
		}
		bits, err := strconv.ParseInt(fields[3], 10, 64)
		return result{ok: true, bits: bits, vals: fields[4:]}, err
	}
	if status == "refused" && len(fields) >= 5 {
		idx, err := strconv.Atoi(fields[3])
		if err != nil {
			return result{}, err
		}
		res := result{idx: idx, kind: fields[4]}
		if op == "r" {
			if len(fields) != 5+idx {
				return result{}, fmt.Errorf("refused read states %d values before step %d: %q", len(fields)-5, idx, strings.Join(fields, " "))
			}
			res.vals = fields[5:]
		}
		return res, nil
	}
	return result{}, fmt.Errorf("bad result line %q", strings.Join(fields, " "))
}

func decodeX(tok string) ([]byte, error) {
	return hex.DecodeString(tok[1:])
}

func runDriver(t *testing.T, sq, root, driver string, batch int, reqs []request) map[string][]string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, fmt.Sprintf("batch-%02d.txt", batch))
	var body bytes.Buffer
	for _, q := range reqs {
		body.WriteString(q.line)
		body.WriteByte('\n')
	}
	if err := os.WriteFile(path, body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sq, driver, root, path)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	// sq exits 0 on an uncaught throw (DESIGN.md (i)): a run passes only on exit
	// 0, an empty stderr and the driver's own completion line
	if err != nil || stderr.Len() != 0 {
		t.Fatalf("batch %d: the driver failed (%v); stderr:\n%s", batch, err, stderr.String())
	}
	out := map[string][]string{}
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	done := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if f[0] == "done" {
			if len(f) != 2 || f[1] != strconv.Itoa(len(reqs)) {
				t.Fatalf("batch %d: driver completion line %q, want done %d", batch, sc.Text(), len(reqs))
			}
			done = true
			continue
		}
		out[f[0]] = f
	}
	if !done {
		t.Fatalf("batch %d: the driver never printed its completion line; stdout:\n%s", batch, stdout.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// comparison

type program struct {
	n        int
	steps    []step
	text     string
	goW      result // serialize.go's write
	canon    []string
	mutant   []byte
	mutation string
	shortCap int
}

func (p *program) header() string {
	return fmt.Sprintf("program %d (%d steps): %s", p.n, len(p.steps), p.text)
}

// firstDifferingStep maps the first differing bit of two byte strings onto the
// step of the writer whose bits hold it.
func firstDifferingStep(a, b []byte, endBits []int64) string {
	bit := int64(-1)
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y byte
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y || i >= len(a) || i >= len(b) {
			d := x ^ y
			k := int64(0)
			for d != 0 && d&1 == 0 {
				d >>= 1
				k++
			}
			bit = int64(i)*8 + k
			break
		}
	}
	for i, e := range endBits {
		if e > bit {
			return fmt.Sprintf("step %d (bit %d)", i, bit)
		}
	}
	return fmt.Sprintf("past the last step (bit %d)", bit)
}

func compareWrite(p *program, goW, sqW result) string {
	if !goW.ok || !sqW.ok {
		return fmt.Sprintf("%s\n  a write refused: go ok=%v %d %s, squirrel ok=%v %d %s", p.header(), goW.ok, goW.idx, goW.kind, sqW.ok, sqW.idx, sqW.kind)
	}
	if !bytes.Equal(goW.bytes, sqW.bytes) {
		return fmt.Sprintf("%s\n  go bytes:       %x\n  squirrel bytes: %x\n  first differing step: %s",
			p.header(), goW.bytes, sqW.bytes, firstDifferingStep(goW.bytes, sqW.bytes, goW.endBits))
	}
	return ""
}

func compareValues(p *program, who string, got, want []string) string {
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			g := "(none)"
			if i < len(got) {
				g = got[i]
			}
			return fmt.Sprintf("%s\n  %s: first differing step %d (%s): decoded %s, want %s", p.header(), who, i, p.steps[i].kind, g, want[i])
		}
	}
	return ""
}

func compareReads(p *program, what string, data []byte, a, b result) string {
	head := fmt.Sprintf("%s\n  %s bytes: %x\n", p.header(), what, data)
	if a.ok != b.ok {
		return head + fmt.Sprintf("  go ok=%v (refused step %d %s), squirrel ok=%v (refused step %d %s)", a.ok, a.idx, a.kind, b.ok, b.idx, b.kind)
	}
	if !a.ok {
		if a.idx != b.idx || a.kind != b.kind {
			return head + fmt.Sprintf("  go refused step %d (%s) with %s, squirrel refused step %d (%s) with %s",
				a.idx, p.steps[a.idx].kind, a.kind, b.idx, p.steps[min(b.idx, len(p.steps)-1)].kind, b.kind)
		}
	} else if a.bits != b.bits {
		return head + fmt.Sprintf("  go consumed %d bits, squirrel %d", a.bits, b.bits)
	}
	if d := compareValues(p, what+": go vs squirrel", b.vals, a.vals); d != "" {
		return d
	}
	return ""
}

func TestDifferentialAgainstSerializeGo(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	sq := os.Getenv("SQ")
	if sq == "" {
		sq = filepath.Join(root, "dist", "squirrel-3.2", "bin", "sq")
	}
	if fi, err := os.Stat(sq); err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		// refused by name, never a skip (DESIGN.md (i), THE TOOLCHAIN GATE)
		t.Fatalf("the pinned interpreter SQ=%s does not resolve; run make dist-squirrel", sq)
	}
	driver := filepath.Join(root, "fuzz", "driver.nut")

	g := &gen{r: rand.New(rand.NewPCG(seed1, seed2))}
	progs := make([]*program, programCount)
	ops := 0
	for n := range progs {
		steps := g.program(1+g.r.IntN(maxOps), 0)
		ops += len(steps)
		p := &program{n: n, steps: steps, text: programText(steps)}
		p.goW = goWrite(steps, writeCap, *sabotageWidenInt)
		if !p.goW.ok {
			t.Fatalf("%s\n  serialize.go refused its own in-range program at step %d (%s): a generator bug", p.header(), p.goW.idx, p.goW.kind)
		}
		self := goRead(steps, p.goW.bytes)
		if !self.ok || self.bits != p.goW.bits {
			if !*sabotageWidenInt {
				t.Fatalf("%s\n  serialize.go does not read back its own bytes %x (ok=%v step %d %s)", p.header(), p.goW.bytes, self.ok, self.idx, self.kind)
			}
		}
		p.canon = make([]string, len(steps))
		for i := range steps {
			p.canon[i] = programValue(&steps[i])
			if steps[i].kind == "cfloat" || steps[i].kind == "cfloatpre" {
				// quantization is lossy: the value a reader must decode is the
				// one serialize.go decodes from its own bytes (STANDARD.md compressed_float)
				if self.ok {
					p.canon[i] = self.vals[i]
				}
			} else if !*sabotageWidenInt && self.vals[i] != p.canon[i] {
				t.Fatalf("%s\n  serialize.go decodes step %d as %s from its own bytes, the program states %s", p.header(), i, self.vals[i], p.canon[i])
			}
		}
		if g.r.IntN(4) == 0 {
			p.mutant, p.mutation = mutate(g, p.goW.bytes)
		}
		if len(p.goW.bytes) > 8 && g.r.IntN(8) == 0 {
			p.shortCap = (len(p.goW.bytes) - 1) / 8 * 8
		}
		progs[n] = p
	}

	// every operation serialize.go has is drawn: a kind the generator never
	// reaches would be a hole in the differential, so it fails by name
	seen := map[string]int{}
	for _, p := range progs {
		for i := range p.steps {
			seen[p.steps[i].kind]++
		}
	}
	var counts []string
	for _, k := range append(append([]string{}, leafKinds...), "object") {
		if seen[k] == 0 {
			t.Errorf("the generator drew no %s step in %d programs", k, programCount)
		}
		counts = append(counts, fmt.Sprintf("%s=%d", k, seen[k]))
	}
	t.Logf("operations drawn: %s", strings.Join(counts, " "))

	var disagreements []string
	mutants, mutantRefusals, shortWrites := 0, 0, 0
	sqBytes := make([][]byte, programCount)
	for b := 0; b*batchSize < programCount; b++ {
		batch := progs[b*batchSize : min((b+1)*batchSize, programCount)]
		var reqs []request
		for _, p := range batch {
			id := strconv.Itoa(p.n)
			reqs = append(reqs,
				request{id + "w", fmt.Sprintf("w %sw %d %s", id, writeCap, p.text)},
				request{id + "r", fmt.Sprintf("r %sr %s %s", id, hexBytes(p.goW.bytes), p.text)})
			if p.mutant != nil {
				reqs = append(reqs, request{id + "m", fmt.Sprintf("r %sm %s %s", id, hexBytes(p.mutant), p.text)})
			}
			if p.shortCap > 0 {
				reqs = append(reqs, request{id + "s", fmt.Sprintf("w %ss %d %s", id, p.shortCap, p.text)})
			}
		}
		out := runDriver(t, sq, root, driver, b, reqs)
		get := func(id string, n int) (result, bool) {
			f, ok := out[id]
			if !ok {
				t.Fatalf("batch %d: the driver gave no result for request %s", b, id)
			}
			res, err := parseResult(f, n)
			if err != nil {
				t.Fatalf("batch %d: request %s: %v", b, id, err)
			}
			return res, true
		}
		for _, p := range batch {
			id := strconv.Itoa(p.n)
			n := len(p.steps)
			add := func(d string) {
				if d != "" {
					disagreements = append(disagreements, d)
				}
			}
			// (1) the bytes are equal
			sqW, _ := get(id+"w", n)
			add(compareWrite(p, p.goW, sqW))
			sqBytes[p.n] = sqW.bytes
			// (2) each side reads the other's bytes and decodes the program
			sqR, _ := get(id+"r", n)
			if !sqR.ok {
				add(fmt.Sprintf("%s\n  squirrel refused serialize.go's bytes %x at step %d with %s", p.header(), p.goW.bytes, sqR.idx, sqR.kind))
			} else {
				add(compareValues(p, "squirrel reading go's bytes", sqR.vals, p.canon))
				if sqR.bits != p.goW.bits {
					add(fmt.Sprintf("%s\n  squirrel consumed %d bits of go's bytes, go wrote %d", p.header(), sqR.bits, p.goW.bits))
				}
			}
			if sqW.ok {
				goR := goRead(p.steps, sqW.bytes)
				if !goR.ok {
					add(fmt.Sprintf("%s\n  go refused squirrel's bytes %x at step %d with %s", p.header(), sqW.bytes, goR.idx, goR.kind))
				} else {
					add(compareValues(p, "go reading squirrel's bytes", goR.vals, p.canon))
				}
			}
			// (3) both readers agree on a mutant
			if p.mutant != nil {
				mutants++
				sqM, _ := get(id+"m", n)
				goM := goRead(p.steps, p.mutant)
				if !goM.ok {
					mutantRefusals++
				}
				add(compareReads(p, "mutant ("+p.mutation+")", p.mutant, goM, sqM))
			}
			// (4) both writers refuse a short buffer at the same step
			if p.shortCap > 0 {
				shortWrites++
				sqS, _ := get(id+"s", n)
				goS := goWrite(p.steps, p.shortCap, *sabotageWidenInt)
				if goS.ok != sqS.ok || goS.idx != sqS.idx || goS.kind != sqS.kind {
					add(fmt.Sprintf("%s\n  a %d-byte buffer: go ok=%v refused step %d with %s, squirrel ok=%v refused step %d with %s",
						p.header(), p.shortCap, goS.ok, goS.idx, goS.kind, sqS.ok, sqS.idx, sqS.kind))
				}
			}
		}
	}

	t.Logf("%d programs, %d operations, %d mutants (%d of them refused by serialize.go), %d short-buffer writes, %d disagreements",
		programCount, ops, mutants, mutantRefusals, shortWrites, len(disagreements))
	for i, d := range disagreements {
		if i == 10 {
			t.Errorf("... and %d more disagreements", len(disagreements)-10)
			break
		}
		t.Errorf("disagreement:\n%s", d)
	}

	// THE NEGATIVE CONTROL, in every run: the same programs written by a Go
	// writer that widens each int range by one bit, through the same
	// comparison, must go red.
	if !*sabotageWidenInt {
		red, eligible := 0, 0
		first := ""
		for _, p := range progs {
			has := false
			for i := range p.steps {
				s := &p.steps[i]
				if s.kind == "int" {
					if bits := serialize.BitsRequired(uint32(int32(s.min.Lo)), uint32(int32(s.max.Lo))); bits >= 1 && bits < 32 {
						has = true
					}
				}
			}
			if !has {
				continue
			}
			eligible++
			sab := goWrite(p.steps, writeCap, true)
			if d := compareWrite(p, sab, result{ok: true, bytes: sqBytes[p.n]}); d != "" {
				red++
				if first == "" {
					first = d
				}
			}
		}
		if red == 0 {
			t.Errorf("negative control: the int range widened by one bit went green on all %d programs with a widenable int", eligible)
		} else {
			t.Logf("negative control: the int range widened by one bit went red on %d of %d programs with a widenable int; the first:\n%s", red, eligible, first)
		}
	}
	if len(disagreements) == 0 {
		t.Logf("%d programs agree", programCount)
	}
}

// mutate returns a copy of b with bit flips, a truncation or an extension.
func mutate(g *gen, b []byte) ([]byte, string) {
	m := append([]byte(nil), b...)
	choice := g.r.IntN(3)
	if len(m) == 0 {
		choice = 2
	}
	switch choice {
	case 0:
		n := 1 + g.r.IntN(3)
		for range n {
			bit := g.r.IntN(len(m) * 8)
			m[bit/8] ^= 1 << (bit % 8)
		}
		return m, fmt.Sprintf("%d bit flips", n)
	case 1:
		cut := 1 + g.r.IntN(len(m))
		return m[:len(m)-cut], fmt.Sprintf("truncated by %d bytes", cut)
	}
	n := 1 + g.r.IntN(8)
	for range n {
		m = append(m, byte(g.r.Uint32()))
	}
	return m, fmt.Sprintf("extended by %d bytes", n)
}
