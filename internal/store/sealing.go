// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/internal/keywrap"
	"github.com/NeoTecDigital/LumberJack/types"
)

const sealedBanner = "LUMBERJACK-RECORD-2\nsealed command journal\n"

type keyEnvelope struct {
	Store  string          `json:"store"`
	Host   bool            `json:"host_family"`
	Master keywrap.Wrapped `json:"wrapped_master"`
	Marker []byte          `json:"marker"`
}
type journalKey struct {
	key    []byte
	domain string
}

func domain(prefix, store string) string { return prefix + "record-v2/" + store + "/" }
func markerBytes(m marker, cfg *types.StorageConfig) ([]byte, *journalKey, error) {
	raw, err := json.Marshal(m)
	if err != nil || cfg == nil {
		return append([]byte(banner), raw...), nil, err
	}
	w, err := keywrap.For(*cfg)
	if err != nil {
		return nil, nil, err
	}
	prefix := (compat.Label{}).StatePrefix()
	host := false
	for _, l := range cfg.Labels {
		if l.Name == cfg.WriteLabel {
			prefix = l.StatePrefix
			host = true
		}
	}
	master, err := keywrap.Random()
	if err != nil {
		return nil, nil, err
	}
	k := &journalKey{master, domain(prefix, m.Store)}
	wrapped, err := w.Wrap(context.Background(), master, []byte(k.domain+"master"))
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := keywrap.Seal(master, raw, []byte(k.domain+"marker"))
	if err != nil {
		return nil, nil, err
	}
	envelope, err := json.Marshal(keyEnvelope{m.Store, host, wrapped, ciphertext})
	return append([]byte(sealedBanner), envelope...), k, err
}
func decodeMarker(data []byte, cfg *types.StorageConfig) (marker, *journalKey, error) {
	var m marker
	switch {
	case bytes.HasPrefix(data, []byte(banner)):
		if cfg != nil {
			return m, nil, types.ErrSealingLabel
		}
		err := Decode(data[len(banner):], &m)
		return m, nil, err
	case !bytes.HasPrefix(data, []byte(sealedBanner)):
		return m, nil, ErrConflict
	case cfg == nil:
		return m, nil, types.ErrSealingLabel
	}
	var e keyEnvelope
	if err := Decode(data[len(sealedBanner):], &e); err != nil || !semanticID(e.Store) {
		return m, nil, types.ErrSealingLabel
	}
	w, err := keywrap.For(*cfg)
	if err != nil {
		return m, nil, errors.Join(types.ErrSealingLabel, err)
	}
	prefixes := []string{(compat.Label{}).StatePrefix()}
	if e.Host {
		prefixes = nil
		for _, l := range cfg.Labels {
			prefixes = append(prefixes, l.StatePrefix)
		}
	}
	for _, p := range prefixes {
		k := journalKey{domain: domain(p, e.Store)}
		k.key, err = w.Unwrap(context.Background(), e.Master, []byte(k.domain+"master"))
		if err != nil || len(k.key) != 32 {
			continue
		}
		raw, err := keywrap.Open(k.key, e.Marker, []byte(k.domain+"marker"))
		if err != nil || Decode(raw, &m) != nil || m.Store != e.Store {
			return marker{}, nil, types.ErrSealingLabel
		}
		return m, &k, nil
	}
	return m, nil, types.ErrSealingLabel
}
func (k *journalKey) frame(seal bool, seq uint64, raw []byte) ([]byte, error) {
	if k == nil {
		return raw, nil
	}
	aad := []byte(k.domain + "frame/" + strconv.FormatUint(seq, 10))
	if seal {
		return keywrap.Seal(k.key, raw, aad)
	}
	plain, err := keywrap.Open(k.key, raw, aad)
	if err != nil {
		return nil, types.ErrSealingLabel
	}
	return plain, nil
}
