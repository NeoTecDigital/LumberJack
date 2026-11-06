package core

type FeedChannels struct {
	Enabled       bool `json:"enabled"`
	Reminders     bool `json:"reminders"`
	Notifications bool `json:"notifications"`
	Alerts        bool `json:"alerts"`
}
type FeedPreferences struct {
	Revision uint64       `json:"revision"`
	InApp    FeedChannels `json:"in_app"`
}

func DefaultFeedPreferences() FeedPreferences {
	return FeedPreferences{InApp: FeedChannels{true, true, true, true}}
}
