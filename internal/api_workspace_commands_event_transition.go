// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

func (s *Server) workCommandEventTransition(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	if err := workTransition(node, userID, cmd.EventID, cmd.Status); err != nil {
		return err
	}
	c.mutationKind = mutationEventStarted
	return nil
}
