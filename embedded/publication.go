package embedded

import "github.com/NeoTecDigital/LumberJack/internal"

type CompleteEvent = internal.CompleteEvent
type PublishEventsRequest = internal.PublishEventsRequest
type PublishEventsResult = internal.PublishEventsResult

const PublishMaxEvents = internal.PublishMaxEvents
const PublishMaxBytes = internal.PublishMaxBytes

func (h *Handle) PublishEvents(request PublishEventsRequest) (PublishEventsResult, error) {
	if err := h.ensureOpen(); err != nil {
		return PublishEventsResult{}, err
	}
	return h.runtime.server.PublishEvents(h.actor(), request)
}
