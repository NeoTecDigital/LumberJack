// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

func (s *Server) workCommandSubscribe(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	if s.forest.Subscriptions == nil {
		s.forest.Subscriptions = map[string]map[string]bool{}
	}
	if s.forest.Subscriptions[userID] == nil {
		s.forest.Subscriptions[userID] = map[string]bool{}
	}
	s.forest.Subscriptions[userID][node.ID] = cmd.Subscribed
	return nil
}
