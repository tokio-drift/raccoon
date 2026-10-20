package carve

// matchNode is one state of the Aho-Corasick automaton. next[c] is the index of
// the child reached on byte c (0 means "no edge"; the root is node 0, so an
// unset edge out of the root behaves as a self-loop, which is exactly the
// desired restart behaviour). fail is the fallback state, and out lists every
// pattern index that terminates at this state, including patterns that are
// suffixes of it (resolved through fail links at build time).
type matchNode struct {
	next [256]int32
	fail int32
	out  []int32
}

// Matcher is an Aho-Corasick automaton that finds every occurrence of a set of
// byte patterns in a buffer in a single pass, including overlapping
// occurrences. It is safe for concurrent Scan calls after construction.
type Matcher struct {
	nodes []matchNode
	lens  []int // lens[i] is the length of pattern i (0 for empty patterns)
}

// NewMatcher compiles patterns into a Matcher. Empty patterns are ignored and
// never match. Overlapping and duplicate patterns are supported: every pattern
// index is reported independently.
func NewMatcher(patterns [][]byte) *Matcher {
	m := &Matcher{
		nodes: []matchNode{{}},
		lens:  make([]int, len(patterns)),
	}
	for idx, p := range patterns {
		if len(p) == 0 {
			continue
		}
		m.lens[idx] = len(p)
		n := 0
		for _, c := range p {
			if m.nodes[n].next[c] == 0 {
				m.nodes[n].next[c] = int32(len(m.nodes))
				m.nodes = append(m.nodes, matchNode{})
			}
			n = int(m.nodes[n].next[c])
		}
		m.nodes[n].out = append(m.nodes[n].out, int32(idx))
	}
	m.buildFail()
	return m
}

// buildFail computes fail links breadth-first and propagates each state's
// terminal outputs along them, so Scan never has to walk fail links to report
// matches.
func (m *Matcher) buildFail() {
	queue := make([]int32, 0, len(m.nodes))
	for c := 0; c < 256; c++ {
		if ch := m.nodes[0].next[c]; ch != 0 {
			m.nodes[ch].fail = 0
			queue = append(queue, ch)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for c := 0; c < 256; c++ {
			ch := m.nodes[n].next[c]
			if ch == 0 {
				continue
			}
			f := m.nodes[n].fail
			for f != 0 && m.nodes[f].next[c] == 0 {
				f = m.nodes[f].fail
			}
			if got := m.nodes[f].next[c]; got != 0 && got != ch {
				m.nodes[ch].fail = got
			} else {
				m.nodes[ch].fail = 0
			}
			failOut := m.nodes[m.nodes[ch].fail].out
			if len(failOut) > 0 {
				m.nodes[ch].out = append(m.nodes[ch].out, failOut...)
			}
			queue = append(queue, ch)
		}
	}
}

// Scan walks buf in one pass and calls fn for every match: patternIdx is the
// index of the pattern in the slice passed to NewMatcher, and off is the
// absolute offset of the match start, i.e. base plus the index of the match's
// first byte in buf. Matches are reported in offset order; fn must not modify
// the matcher.
func (m *Matcher) Scan(buf []byte, base int64, fn func(patternIdx int, off int64)) {
	if fn == nil || len(m.nodes) == 0 {
		return
	}
	n := 0
	for i, c := range buf {
		for n != 0 && m.nodes[n].next[c] == 0 {
			n = int(m.nodes[n].fail)
		}
		if ch := m.nodes[n].next[c]; ch != 0 {
			n = int(ch)
		}
		for _, p := range m.nodes[n].out {
			fn(int(p), base+int64(i)-int64(m.lens[p])+1)
		}
	}
}
