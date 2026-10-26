// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

func (s *Server) workCommandPreferences(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	if err := workPreferences(node, userID, cmd.Preferences); err != nil {
		return err
	}
	return nil
}
