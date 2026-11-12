// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/core"
)

type workDefinition struct {
	definitions map[string]*core.Node
	ordered     []*core.Node
	clones      map[string]*core.Node
	user        string
}

func (s *Server) workRun(parent *core.Node, path, user string) (interface{}, error) {
	template, err := s.getNodeFromPath(path)
	if err != nil || !template.CheckPermission(user, core.ReadPermission) {
		return nil, apiErrorf(404, "Procedure not found")
	}
	if template.Kind != "procedure" && template.Kind != "workflow" {
		return nil, apiErrorf(400, "Choose a procedure or workflow")
	}
	definition := &workDefinition{definitions: map[string]*core.Node{}, clones: map[string]*core.Node{}, user: user}
	if err := definition.inspect(template); err != nil {
		return nil, err
	}
	title := workDefinitionTitle(template)
	revision := definition.revision()
	run, err := s.workChild(parent, title+" · run", "run", user)
	if err != nil {
		return nil, err
	}
	run.Metadata["procedure_id"], run.Metadata["procedure_revision"], run.Metadata["status"] = template.ID, revision, "active"
	definition.clones[template.ID] = run
	if err := s.cloneWorkDefinition(definition, template, run); err != nil {
		return nil, err
	}
	return map[string]interface{}{"id": run.ID}, nil
}
func (d *workDefinition) inspect(node *core.Node) error {
	if d.definitions[node.ID] != nil {
		return nil
	}
	if len(d.definitions) >= 1000 {
		return apiErrorf(400, "A workflow can contain at most 1000 items")
	}
	if !node.CheckPermission(d.user, core.ReadPermission) {
		return apiErrorf(403, "You must be able to read every workflow step")
	}
	d.definitions[node.ID] = node
	d.ordered = append(d.ordered, node)
	for _, child := range childrenByName(node) {
		if err := d.inspect(child); err != nil {
			return err
		}
	}
	return nil
}
func (d *workDefinition) revision() string {
	parts := []interface{}{}
	for _, step := range d.ordered {
		edges := []string{}
		for _, child := range childrenByName(step) {
			edges = append(edges, child.ID)
		}
		parts = append(parts, []interface{}{step.ID, step.Kind, workMetadata(step), edges})
	}
	raw, _ := json.Marshal(parts)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func workDefinitionTitle(node *core.Node) string {
	title, _ := node.Metadata["title"].(string)
	if title == "" {
		return node.Name
	}
	return title
}
func (s *Server) cloneWorkDefinition(d *workDefinition, source, target *core.Node) error {
	for index, step := range childrenByName(source) {
		if d.definitions[step.ID] == nil {
			continue
		}
		if existing := d.clones[step.ID]; existing != nil {
			target.AddChild(existing)
			continue
		}
		child, err := s.workChild(target, workDefinitionTitle(step), "action", d.user)
		if err != nil {
			return err
		}
		d.clones[step.ID] = child
		child.Metadata["procedure_step_id"], child.Metadata["order"], child.Metadata["status"] = step.ID, index, "planned"
		child.Metadata["description"] = copyValue(step.Metadata["description"])
		if err := s.cloneWorkDefinition(d, step, child); err != nil {
			return err
		}
	}
	return nil
}
