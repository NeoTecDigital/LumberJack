// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import engine "github.com/NeoTecDigital/LumberJack/internal"

// Ordinary store requests do not consume historical projection data. Historical
// requests still decode fresh retained receipts and enforce the original actor,
// current intent, ACL, native lifecycle and durable receipt checks.
func (Adapter) IncludeRetainedReceipts(input engine.DomainInput) (bool, error) {
	request, err := decode(input)
	return request.Query.Family == HistoryFamily, err
}
