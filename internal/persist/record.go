// Written by Richard Christopher, Copyright 2026 Richard Christopher

// Package persist is the hot layer of tiered persistence: an append-only log of change records
// beside the state file, the rules for recovering it, and the hook a sync layer attaches to.
//
// A record is ONE commit: the nodes it changed and the ids it deleted, as JSON the caller encodes,
// under a sequence number the log assigns in commit order. The log knows nothing about nodes; it
// carries bytes, numbers them, makes them durable, and gives them back in order.
package persist

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// SegmentMagic opens every segment file. A build that does not know the log cannot mistake a
// segment for a state file: the state file's own banner is different and the loader checks it.
const SegmentMagic = "LUMBERJACK-LOG-1\n"

// headerSize is the fixed header in front of every record's body:
//
//	[0:4]   body length, uint32 little-endian
//	[4:12]  sequence,    uint64 little-endian
//	[12:16] crc32c of the body
//	[16:20] crc32c of bytes [0:16]
//
// The header carries its own checksum so a torn or damaged header is told apart from a short
// body: a header that verifies and a body that does not is damage inside the record, and a header
// that does not verify is either the torn end of a write or damage to the header itself. Recovery
// treats both by where they are and what follows them — see recover.go.
const headerSize = 20

// maxBodySize bounds one record. A command body is capped at 16 MiB by the API, and a fallback
// record of a large forest could legitimately be bigger, so the ceiling is generous; it exists so
// a damaged length field cannot ask for a multi-gigabyte allocation.
const maxBodySize = 1 << 30

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Record is one appended commit.
type Record struct {
	Seq  uint64
	Body []byte
}

// ErrBodyTooLarge is a record the format cannot carry.
var ErrBodyTooLarge = errors.New("log record body exceeds the format's limit")

// encodeRecord lays a record out as header followed by body.
func encodeRecord(buffer []byte, record Record) ([]byte, error) {
	if len(record.Body) > maxBodySize {
		return buffer, ErrBodyTooLarge
	}
	var header [headerSize]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(record.Body)))
	binary.LittleEndian.PutUint64(header[4:12], record.Seq)
	binary.LittleEndian.PutUint32(header[12:16], crc32.Checksum(record.Body, crcTable))
	binary.LittleEndian.PutUint32(header[16:20], crc32.Checksum(header[0:16], crcTable))
	buffer = append(buffer, header[:]...)
	return append(buffer, record.Body...), nil
}

// recordHeader is a decoded header.
type recordHeader struct {
	length  uint32
	seq     uint64
	bodyCRC uint32
}

// decodeHeader reads a header, reporting false when its checksum does not vouch for it.
func decodeHeader(data []byte) (recordHeader, bool) {
	if len(data) < headerSize {
		return recordHeader{}, false
	}
	if crc32.Checksum(data[0:16], crcTable) != binary.LittleEndian.Uint32(data[16:20]) {
		return recordHeader{}, false
	}
	return recordHeader{
		length:  binary.LittleEndian.Uint32(data[0:4]),
		seq:     binary.LittleEndian.Uint64(data[4:12]),
		bodyCRC: binary.LittleEndian.Uint32(data[12:16]),
	}, true
}

// parseRecord reads the record at the start of data: the record, the bytes it spans, and why it
// could not be read. intact is false for a short or damaged record.
func parseRecord(data []byte) (record Record, span int, intact bool, reason string) {
	header, ok := decodeHeader(data)
	if !ok {
		if len(data) < headerSize {
			return Record{}, 0, false, "short header"
		}
		return Record{}, 0, false, "header checksum"
	}
	if header.length > maxBodySize {
		return Record{}, 0, false, "header checksum"
	}
	span = headerSize + int(header.length)
	if len(data) < span {
		return Record{}, 0, false, "short body"
	}
	body := data[headerSize:span]
	if crc32.Checksum(body, crcTable) != header.bodyCRC {
		return Record{}, span, false, "body checksum"
	}
	return Record{Seq: header.seq, Body: body}, span, true, ""
}
