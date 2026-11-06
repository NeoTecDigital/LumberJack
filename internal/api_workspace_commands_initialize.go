// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

func (s *Server) workCommandInitialize(c *workCommandContext) error {
	node := c.node
	userID := c.user
	var err error
	if node != s.forest {
		return apiErrorf(400, "Initialize from the workspace root")
	}
	c.result, err = s.workInitialize(userID)
	if err != nil {
		return err
	}
	c.mutationKind = mutationNodeCreated
	return nil
}
