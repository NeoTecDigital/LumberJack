// Written by Richard Christopher, Copyright 2026 Richard Christopher
package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// Rebuilding the index from the segments, and repairing what a crash leaves behind.
//
// THE RULE: a put syncs its record before it is acknowledged, and the next record is not begun until
// the one before it is on the disk. So at most ONE record — the last one in the last segment — can
// ever be partial, and a record that is whole on the disk was acknowledged. That is what lets open
// tell two kinds of damage apart without guessing:
//
//   - A TORN TAIL is a record the file does not have all of, or whose CRC fails and after which there
//     is nothing but the end of the file or zeros. (An ext4 crash after the size was committed but
//     before the data was can leave the tail allocated and zero-filled.) It was never acknowledged;
//     it is cut off, and the file is whole again.
//
//   - CORRUPTION is a record whose CRC fails and which is FOLLOWED by more records. Something that
//     was acknowledged has since changed on the disk. It is NOT cut off — the objects after it were
//     acknowledged too and are not the engine's to discard. The record is indexed as corrupt, so a
//     read of that id answers ErrObjectCorrupt by name rather than "not found", and every other
//     object is served as before.

// objectRecordHeader is one record's header, decoded.
type objectRecordHeader struct {
	id     objectID
	flag   byte
	length int64
}

func decodeObjectHeader(raw []byte) objectRecordHeader {
	var header objectRecordHeader
	copy(header.id[:], raw[:objectIDSize])
	header.flag = raw[objectIDSize]
	header.length = int64(binary.LittleEndian.Uint64(raw[objectIDSize+1:]))
	return header
}

// scanSegment registers every whole record in the segment and answers where its trustworthy content
// ends, having truncated the file there if a torn tail was found past it.
func (store *objectStore) scanSegment(file *os.File, segment uint32) (int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	if err := store.checkSegmentBanner(file, segment, size); err != nil {
		return 0, err
	}
	end := int64(len(objectSegmentMagic))
	for end < size {
		next, whole, err := store.scanRecord(file, segment, end, size)
		if err != nil {
			return 0, err
		}
		if !whole {
			break
		}
		end = next
	}
	if end < size {
		if err := store.truncateTail(file, segment, end, size); err != nil {
			return 0, err
		}
	}
	return end, nil
}

// checkSegmentBanner refuses a file that is not a segment. A file SHORTER than the banner is one the
// crash caught between creation and sync; it holds nothing and is reset rather than refused.
func (store *objectStore) checkSegmentBanner(file *os.File, segment uint32, size int64) error {
	if size < int64(len(objectSegmentMagic)) {
		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := file.WriteAt([]byte(objectSegmentMagic), 0); err != nil {
			return err
		}
		if size > 0 {
			store.repairs = append(store.repairs, fmt.Sprintf("segment %08d: rewrote a banner the crash had torn", segment))
		}
		return file.Sync()
	}
	banner := make([]byte, len(objectSegmentMagic))
	if _, err := file.ReadAt(banner, 0); err != nil {
		return err
	}
	if string(banner) != objectSegmentMagic {
		return fmt.Errorf("not an object segment: the banner is missing")
	}
	return nil
}

// scanRecord examines the record at offset. It answers where the next record begins and whether this
// one was whole; a record that was not whole is the torn tail and ends the scan.
func (store *objectStore) scanRecord(file *os.File, segment uint32, offset, size int64) (int64, bool, error) {
	if size-offset < objectHeaderSize {
		return offset, false, nil
	}
	raw := make([]byte, objectHeaderSize)
	if _, err := file.ReadAt(raw, offset); err != nil {
		return 0, false, err
	}
	header := decodeObjectHeader(raw)
	if header.length < 0 || header.length > size-offset-objectHeaderSize-objectTrailerSize {
		return offset, false, nil
	}
	payloadStart := offset + objectHeaderSize
	recordEnd := payloadStart + header.length + objectTrailerSize

	stored, computed, err := recordChecksums(file, raw, payloadStart, header.length)
	if err != nil {
		return 0, false, err
	}
	if stored != computed {
		if recordEnd == size || tailIsZeros(file, offset, size) {
			return offset, false, nil
		}
		store.indexCorrupt(header, segment, payloadStart)
		return recordEnd, true, nil
	}
	if !store.flagMatches(header.flag) {
		store.indexCorrupt(header, segment, payloadStart)
		return recordEnd, true, nil
	}
	store.indexWhole(header, segment, payloadStart)
	return recordEnd, true, nil
}

// recordChecksums reads the CRC the record carries and computes the one its bytes have, streaming
// the payload through the hash rather than holding it.
func recordChecksums(file *os.File, header []byte, payloadStart, length int64) (uint32, uint32, error) {
	hasher := crc32.New(objectCRCTable)
	hasher.Write(header)
	if _, err := io.Copy(hasher, io.NewSectionReader(file, payloadStart, length)); err != nil {
		return 0, 0, err
	}
	trailer := make([]byte, objectTrailerSize)
	if _, err := file.ReadAt(trailer, payloadStart+length); err != nil {
		return 0, 0, err
	}
	return binary.LittleEndian.Uint32(trailer), hasher.Sum32(), nil
}

// tailIsZeros reports whether everything from offset to the end of the file is zero bytes — the
// shape of a tail that was allocated and never written.
func tailIsZeros(file *os.File, offset, size int64) bool {
	buffer := make([]byte, 64<<10)
	zeros := make([]byte, len(buffer))
	for offset < size {
		n, err := file.ReadAt(buffer, offset)
		if n == 0 && err != nil {
			return false
		}
		if !bytes.Equal(buffer[:n], zeros[:n]) {
			return false
		}
		offset += int64(n)
	}
	return true
}

// flagMatches says whether a record's encoding is the one this store reads. A plain record in a
// sealed store, or the reverse, is unreadable here and is indexed as corrupt rather than served.
func (store *objectStore) flagMatches(flag byte) bool {
	if store.sealer == nil {
		return flag == objectPlain
	}
	return flag == objectSealed
}

// indexWhole registers a verified record. The first record for an id wins; a later one carrying the
// same id is the same bytes and is simply not reached.
func (store *objectStore) indexWhole(header objectRecordHeader, segment uint32, payloadStart int64) {
	if existing, ok := store.index[header.id]; ok && !existing.corrupt {
		return
	}
	store.index[header.id] = objectLocation{segment: segment, offset: payloadStart, length: header.length}
}

// indexCorrupt registers a record that cannot be served, unless a whole copy of the same id is
// already known.
func (store *objectStore) indexCorrupt(header objectRecordHeader, segment uint32, payloadStart int64) {
	if _, ok := store.index[header.id]; ok {
		return
	}
	store.index[header.id] = objectLocation{segment: segment, offset: payloadStart, length: header.length, corrupt: true}
	store.repairs = append(store.repairs, fmt.Sprintf("segment %08d: object %s at offset %d is corrupt and will not be served", segment, header.id.hex(), payloadStart-objectHeaderSize))
}

// truncateTail cuts a torn tail off and makes the cut durable.
func (store *objectStore) truncateTail(file *os.File, segment uint32, end, size int64) error {
	if err := file.Truncate(end); err != nil {
		return fmt.Errorf("could not cut the torn tail: %w", err)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	store.repairs = append(store.repairs, fmt.Sprintf("segment %08d: cut %d bytes of torn tail at offset %d", segment, size-end, end))
	return nil
}
