// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

func (s *Server) workCommandRun(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	var err error
	c.result, err = s.workRun(node, cmd.TemplatePath, userID)
	if err != nil {
		return err
	}
	c.mutationKind = mutationNodeCreated
	return nil
}
