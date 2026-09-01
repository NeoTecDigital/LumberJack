package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"time"
)

// MaxAttachmentSize is the largest file the engine will keep, and it is EXPORTED because the cap
// is a fact about the API and not a secret of the store: the route that refuses an upload has to
// name the same number in its refusal, and a test has to be able to sit exactly on it.
const MaxAttachmentSize int64 = 10 * 1024 * 1024

// ErrAttachmentTooLarge is the one refusal a caller can act on, and it is a SENTINEL rather than a
// formatted string so the route above can answer 413 for it and 500 for everything else. A caller
// told "500" about a file it could simply have made smaller is being told the server broke.
var ErrAttachmentTooLarge = errors.New("attachment is larger than the limit")

type AttachmentStore struct {
	maxSize int64 // maximum file size in bytes
}

func NewAttachmentStore() *AttachmentStore {
	return &AttachmentStore{
		maxSize: MaxAttachmentSize,
	}
}

// Store turns an uploaded file into an attachment: the bytes READ, hashed, and measured. It is the
// only way an attachment is made, so that the two upload routes cannot mean different things by
// "uploaded" — one of them used to build an attachment out of the multipart header alone, which
// answered 200 and kept nothing.
//
// The cap is enforced TWICE and on the bytes rather than on the claim. header.Size is a cheap early
// refusal; the LimitReader is the one that decides, because the size that matters is the size of
// what was actually read and not the size the form said it would be.
func (s *AttachmentStore) Store(file multipart.File, header *multipart.FileHeader, userID string) (*Attachment, error) {
	if header.Size > s.maxSize {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrAttachmentTooLarge, header.Size, s.maxSize)
	}

	// One byte past the cap is read on purpose: reading exactly the cap cannot tell a file that
	// fits from a file that was truncated to fit.
	content, err := io.ReadAll(io.LimitReader(file, s.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	if int64(len(content)) > s.maxSize {
		return nil, fmt.Errorf("%w: the limit is %d bytes", ErrAttachmentTooLarge, s.maxSize)
	}

	hash := sha256.Sum256(content)
	hashString := hex.EncodeToString(hash[:])

	attachment := &Attachment{
		// The id IS the hash: an attachment is its contents, so the same bytes uploaded twice are
		// one stored file rather than two identical ones under different names.
		ID:   hashString,
		Name: header.Filename,
		Type: header.Header.Get("Content-Type"),
		// Measured, not declared. Size and Hash describe the same bytes as Data or they describe
		// nothing, and a client that trusts Size to allocate a buffer is trusting this field.
		Size:       int64(len(content)),
		Hash:       hashString,
		Data:       content,
		UploadedBy: userID,
		UploadedAt: time.Now(),
	}

	return attachment, nil
}

// IsCompressibleType returns whether a file type should be compressed
func IsCompressibleType(mimeType string) bool {
	// List of mime types that are already compressed
	compressedTypes := map[string]bool{
		"image/jpeg":                   true,
		"image/png":                    true,
		"image/gif":                    true,
		"image/webp":                   true,
		"video/mp4":                    true,
		"video/mpeg":                   true,
		"audio/mpeg":                   true,
		"audio/mp4":                    true,
		"application/zip":              true,
		"application/x-gzip":           true,
		"application/x-rar-compressed": true,
		"application/x-7z-compressed":  true,
	}

	return !compressedTypes[mimeType]
}

// GetAttachment is the node's OWN map and nothing else, which is a question about WHERE a file is
// kept. It is not how a route resolves an id — that is FindAttachment in attachment_locate.go,
// which searches every holder. Answering an id lookup with this one is the defect that made entry
// attachments write-only.
func (n *Node) GetAttachment(attachmentID string) (*Attachment, error) {
	if attachment, exists := n.Attachments[attachmentID]; exists {
		return &attachment, nil
	}
	return nil, fmt.Errorf("attachment not found: %s", attachmentID)
}

// GetEntryAttachment is one named entry of one named event, which is again a question about WHERE.
// A caller that has only an id wants FindAttachment.
func (n *Node) GetEntryAttachment(eventID string, entryIndex int, attachmentID string) (*Attachment, error) {
	event, exists := n.Events[eventID]
	if !exists {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	if entryIndex < 0 || entryIndex >= len(event.Entries) {
		return nil, fmt.Errorf("invalid entry index: %d", entryIndex)
	}

	for _, attachment := range event.Entries[entryIndex].Attachments {
		if attachment.ID == attachmentID {
			return &attachment, nil
		}
	}

	return nil, fmt.Errorf("attachment not found: %s", attachmentID)
}
