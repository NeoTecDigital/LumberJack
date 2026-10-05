// Written by Richard Christopher, Copyright 2026 Richard Christopher

package persist

import (
	"fmt"
	"os"
)

// Recovery reads every segment in order and decides, record by record, whether the file is what
// the writer left or something else.
//
// THE ONE THING THAT IS CUT is a torn tail: the last record of the last segment, left short or
// unverifiable by a crash in the middle of the write that was appending it. Nothing was ever
// acknowledged on it, so cutting it loses nothing that was promised.
//
// EVERYTHING ELSE REFUSES, naming the segment and the offset. A record that does not verify in an
// earlier segment, or in the last segment with an intact record after it, is damage: a torn write
// cannot be followed by a record that was written later and survived whole. An intact record whose
// sequence is not the one expected is a gap: something was removed, or a segment is missing, and
// replaying past it would silently build a forest that never existed.
//
// A gap is also refused BETWEEN the state file and the log: the first record the log holds must be
// at or below the sequence after the one the state file covers, or the log has lost the records
// that bridge them.

// Fault is why a log could not be opened: where, and what was found there.
type Fault struct {
	Segment string
	Offset  int64
	Reason  string
}

func (f *Fault) Error() string {
	return fmt.Sprintf("log segment %s at offset %d: %s", f.Segment, f.Offset, f.Reason)
}

// recoverSegments reads the log beside a state file. It answers the segments as they stand after
// any torn tail has been cut, the records past covered in order, and the next sequence to assign.
func recoverSegments(statePath string, covered uint64) ([]*segment, []Record, uint64, error) {
	segments, err := listSegments(statePath)
	if err != nil {
		return nil, nil, 0, err
	}
	var records []Record
	var expect uint64
	for i, s := range segments {
		last := i == len(segments)-1
		held, err := readSegment(s, expect, last)
		if err != nil {
			return nil, nil, 0, err
		}
		for _, record := range held {
			if expect == 0 {
				expect = record.Seq
			}
			if record.Seq > covered {
				records = append(records, record)
			}
			expect = record.Seq + 1
		}
	}
	if expect != 0 && len(records) > 0 && records[0].Seq > covered+1 {
		return nil, nil, 0, &Fault{Segment: segments[0].path, Offset: int64(len(SegmentMagic)),
			Reason: fmt.Sprintf("the state file holds the log through sequence %d and the log begins at %d", covered, records[0].Seq)}
	}
	next := covered + 1
	if expect > next {
		next = expect
	}
	return segments, records, next, nil
}

// readSegment reads one segment's records. expect is the sequence the first record must carry, or
// zero when nothing has fixed it yet; last says this is the final segment, where a torn tail may
// be cut.
func readSegment(s *segment, expect uint64, last bool) ([]Record, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if len(data) < len(SegmentMagic) || string(data[:len(SegmentMagic)]) != SegmentMagic {
		if last && len(data) < len(SegmentMagic) && isPrefix(data, SegmentMagic) {
			return nil, cutSegment(s, 0, "")
		}
		return nil, &Fault{Segment: s.path, Offset: 0, Reason: "not a log segment: the banner is missing"}
	}
	var records []Record
	offset := len(SegmentMagic)
	for offset < len(data) {
		record, span, intact, reason := parseRecord(data[offset:])
		if !intact {
			return recoverTail(s, data, offset, reason, last, expect, records)
		}
		if expect != 0 && record.Seq != expect {
			return nil, &Fault{Segment: s.path, Offset: int64(offset),
				Reason: fmt.Sprintf("sequence gap: expected %d, found %d", expect, record.Seq)}
		}
		record.Body = append([]byte(nil), record.Body...)
		records = append(records, record)
		expect = record.Seq + 1
		offset += span
	}
	s.size = int64(len(data))
	if len(records) > 0 {
		s.last = records[len(records)-1].Seq
	}
	return records, nil
}

// recoverTail decides what an unverifiable record at offset is. In the last segment with nothing
// intact after it, it is the torn tail and is cut; anywhere else it is damage.
func recoverTail(s *segment, data []byte, offset int, reason string, last bool, expect uint64, records []Record) ([]Record, error) {
	if !last || intactRecordAfter(data, offset, expect) {
		return nil, &Fault{Segment: s.path, Offset: int64(offset), Reason: reason}
	}
	if err := cutSegment(s, int64(offset), reason); err != nil {
		return nil, err
	}
	if len(records) > 0 {
		s.last = records[len(records)-1].Seq
	}
	return records, nil
}

// intactRecordAfter reports whether any intact record with a sequence at or past expect lies
// anywhere after offset. A torn write leaves nothing intact after it; damage leaves everything
// written later.
func intactRecordAfter(data []byte, offset int, expect uint64) bool {
	for at := offset + 1; at+headerSize <= len(data); at++ {
		record, _, intact, _ := parseRecord(data[at:])
		if intact && (expect == 0 || record.Seq >= expect) {
			return true
		}
	}
	return false
}

// cutSegment truncates a segment at the torn record and makes the cut durable.
func cutSegment(s *segment, offset int64, reason string) error {
	if offset < int64(len(SegmentMagic)) {
		// Not even the banner landed whole: the segment is rewritten as empty.
		if err := os.WriteFile(s.path, []byte(SegmentMagic), segmentMode); err != nil {
			return err
		}
		offset = int64(len(SegmentMagic))
	} else if err := os.Truncate(s.path, offset); err != nil {
		return fmt.Errorf("torn tail in %s at offset %d (%s) could not be cut: %w", s.path, offset, reason, err)
	}
	file, err := os.OpenFile(s.path, os.O_WRONLY, segmentMode)
	if err != nil {
		return err
	}
	err = file.Sync()
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	s.size = offset
	return err
}

func isPrefix(data []byte, of string) bool {
	return len(data) <= len(of) && string(data) == of[:len(data)]
}
