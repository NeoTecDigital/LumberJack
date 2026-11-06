// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"time"
)

type workCommandContext struct {
	node                                    *core.Node
	cmd                                     WorkCommand
	user, digest, changedPath, mutationKind string
	result                                  interface{}
	response                                []byte
	replay, committed                       bool
}

// ApplyWorkCommand success receipts and alerts share one persisted snapshot.
// Final Raft commit-time admission integration is coordinator-owned.
func (s *Server) ApplyWorkCommand(user string, cmd WorkCommand) ([]byte, error) {
	raw, _ := json.Marshal(cmd)
	c := &workCommandContext{cmd: cmd, user: user, digest: fmt.Sprintf("%x", sha256.Sum256(raw)), changedPath: cmd.Path, mutationKind: mutationMetadataSet}
	err := s.changeForest(func() error { return s.applyWorkspaceCommand(c) })
	if err != nil {
		return nil, s.recordWorkRefusal(user, cmd, c.digest, err)
	}
	if c.committed {
		s.publish(mutation(c.mutationKind, c.changedPath))
		s.publish(mutation("feed_outcome", c.changedPath))
	}
	return c.response, nil
}
func (s *Server) applyWorkspaceCommand(c *workCommandContext) error {
	if err := s.prepareWorkspaceCommand(c); err != nil {
		return err
	}
	if c.replay {
		return nil
	}
	// Validation failures must not leave partial in-memory mutations that a later
	// refusal persist would accidentally commit. Restore the exact prechange graph.
	before, err := encodeState(s.forest)
	if err != nil {
		return apiErrorf(503, "Unable to establish mutation state")
	}
	if err = s.dispatchWorkspaceCommand(c); err != nil {
		restored, restoreErr := decodeState(before)
		if restoreErr != nil {
			return apiErrorf(503, "Mutation outcome unresolved")
		}
		s.forest = restored
		return err
	}
	return s.finishWorkspaceCommand(c)
}
func (s *Server) prepareWorkspaceCommand(c *workCommandContext) error {
	cmd, user := c.cmd, c.user
	if _, err := s.forest.GetUserProfile(user); err != nil {
		return apiErrorf(401, "Account unavailable")
	}
	if cmd.Path == "" || cmd.ClientID == "" || len(cmd.ClientID) > 100 {
		return apiErrorf(400, "A target and command identity are required")
	}
	node, err := s.getNodeFromPath(cmd.Path)
	if err != nil {
		return apiErrorf(404, "Work was not found")
	}
	c.node = node
	required := core.WritePermission
	if cmd.Command == "subscribe" {
		required = core.ReadPermission
	}
	if !(cmd.Command == "initialize" && node == s.forest) && !node.CheckPermission(user, required) {
		return apiErrorf(403, "You can view this work but cannot change it")
	}
	receipt, found, err := s.existingFeedReceipt(user, cmd, c.digest)
	if err != nil {
		return err
	}
	if found {
		if receipt.Status != 200 {
			return apiErrorf(receipt.Status, "This command was definitively refused")
		}
		c.response, c.replay = append([]byte(nil), receipt.Result...), true
		return nil
	}
	return s.prepareFreshWorkspaceCommand(c)
}
func (s *Server) prepareFreshWorkspaceCommand(c *workCommandContext) error {
	cmd, user, node := c.cmd, c.user, c.node
	if cmd.Command == "share" || cmd.Shared {
		return apiErrorf(410, "Legacy sharing is retired. Use /access/preview and /access/apply.")
	}
	if cmd.Command == "chat" {
		return apiErrorf(410, "Legacy chat is retired. Use /conversations with explicit invitations.")
	}
	if node.Metadata == nil {
		node.Metadata = map[string]interface{}{}
	}
	if previous, ok := node.CommandReceipts[user+":"+cmd.ClientID].(map[string]interface{}); ok {
		if previous["digest"] != c.digest {
			return apiErrorf(409, "This command identity was already used")
		}
		c.response, _ = json.Marshal(previous["result"])
		s.commitFeedSuccess(user, cmd, c.digest, node, cmd.Path, c.response)
		c.replay = true
		return nil
	}
	if (cmd.Command == "update" || cmd.Command == "temporal") && (cmd.Revision == "" || cmd.Revision != workRevision(node)) {
		return apiErrorf(409, "This work changed while you were editing. Reload its latest version before saving your draft.")
	}
	if s.forest.Correspondence != nil && len(s.forest.Correspondence.Pending) >= 4096 {
		return apiErrorf(503, "Change delivery is behind. Try again shortly.")
	}
	return nil
}
func (s *Server) finishWorkspaceCommand(c *workCommandContext) error {
	node, cmd := c.node, c.cmd
	node.ModifiedBy, node.ModifiedAt = c.user, time.Now().UTC()
	answer := map[string]interface{}{"client_id": cmd.ClientID, "path": c.changedPath, "result": c.result}
	response, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	if node.CommandReceipts == nil {
		node.CommandReceipts = map[string]interface{}{}
	}
	node.CommandReceipts[c.user+":"+cmd.ClientID] = map[string]interface{}{"digest": c.digest, "result": workMetadataValue(answer), "at": time.Now().UTC().Format(time.RFC3339Nano)}
	s.defaultWorkSubscriptions(node, node.CreatedBy, cmd.AssignedTo)
	s.enqueueCorrespondence(c.user, cmd, c.changedPath)
	alertNode := node
	if changed, err := s.getNodeFromPath(c.changedPath); err == nil {
		alertNode = changed
	}
	s.commitFeedSuccess(c.user, cmd, c.digest, alertNode, c.changedPath, response)
	c.response, c.committed = response, true
	return nil
}
func (s *Server) dispatchWorkspaceCommand(c *workCommandContext) error {
	handlers := map[string]func(*workCommandContext) error{
		"subscribe": s.workCommandSubscribe, "initialize": s.workCommandInitialize,
		"preferences": s.workCommandPreferences, "event_transition": s.workCommandEventTransition,
		"create": s.workCommandCreate, "update": s.workCommandUpdate, "log": s.workCommandLog,
		"timer_start": s.workCommandTimerStart, "timer_stop": s.workCommandTimerStop,
		"time": s.workCommandTime, "plan": s.workCommandPlan, "run": s.workCommandRun,
		"temporal": s.workCommandTemporal, "examples": s.workCommandExamples,
	}
	handler := handlers[c.cmd.Command]
	if handler == nil {
		return apiErrorf(400, "Unknown workspace command")
	}
	return handler(c)
}
