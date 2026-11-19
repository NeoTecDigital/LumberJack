// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

// Ordered resident projection. A cursor pins a root by advancing the write
// generation. Unshared paths mutate in place; writes copy only pinned paths.
type branch struct {
	key         string
	summary     *item // present only in the ID projection
	left, right *branch
	gen         uint64
	height      int
}
type ordered struct {
	root *branch
	gen  uint64
}

func height(n *branch) int {
	if n == nil {
		return 0
	}
	return n.height
}
func (t *ordered) own(n *branch) *branch {
	if n == nil || n.gen == t.gen {
		return n
	}
	c := *n
	c.gen = t.gen
	return &c
}
func fix(n *branch) { n.height = 1 + max(height(n.left), height(n.right)) }
func (t *ordered) left(n *branch) *branch {
	r := t.own(n.right)
	n.right = r.left
	r.left = n
	fix(n)
	fix(r)
	return r
}
func (t *ordered) right(n *branch) *branch {
	l := t.own(n.left)
	n.left = l.right
	l.right = n
	fix(n)
	fix(l)
	return l
}
func (t *ordered) balance(n *branch) *branch {
	fix(n)
	b := height(n.left) - height(n.right)
	if b > 1 {
		if height(n.left.right) > height(n.left.left) {
			n.left = t.left(t.own(n.left))
		}
		return t.right(n)
	}
	if b < -1 {
		if height(n.right.left) > height(n.right.right) {
			n.right = t.right(t.own(n.right))
		}
		return t.left(n)
	}
	return n
}
func (t *ordered) update(n *branch, key string, v *item, remove bool) *branch {
	if n == nil {
		if remove {
			return nil
		}
		return &branch{key: key, summary: v, gen: t.gen, height: 1}
	}
	n = t.own(n)
	switch {
	case key < n.key:
		n.left = t.update(n.left, key, v, remove)
	case key > n.key:
		n.right = t.update(n.right, key, v, remove)
	case !remove:
		n.summary = v
		return n
	case n.left == nil:
		return n.right
	case n.right == nil:
		return n.left
	default:
		next := n.right
		for next.left != nil {
			next = next.left
		}
		n.key, n.summary = next.key, next.summary
		n.right = t.update(n.right, next.key, nil, true)
	}
	return t.balance(n)
}
func (t *ordered) set(key string, v *item) { t.root = t.update(t.root, key, v, false) }
func (t *ordered) drop(key string)         { t.root = t.update(t.root, key, nil, true) }
func lookup(n *branch, key string) *branch {
	for n != nil {
		switch {
		case key < n.key:
			n = n.left
		case key > n.key:
			n = n.right
		default:
			return n
		}
	}
	return nil
}

// seek visits only the lower-bound path and the returned interval, in order.
func seek(n *branch, lower string, visit func(*branch) bool) bool {
	if n == nil {
		return true
	}
	if n.key < lower {
		return seek(n.right, lower, visit)
	}
	return seek(n.left, lower, visit) && visit(n) && seek(n.right, lower, visit)
}
