package internal

import (
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"strings"
)

// One durable, private home per account. A fixed name makes initialization
// idempotent even after command receipts expire, or two devices sign in at once.
func (server *Server) workInitialize(userID string) (interface{}, error) {
	if _, err := server.forest.GetUserProfile(userID); err != nil {
		return nil, apiErrorf(401, "Account unavailable")
	}
	name := "personal-" + userID
	for _, node := range server.forest.Children {
		if node.Name == name {
			if node.Metadata["personal_owner"] != userID || !node.CheckPermission(userID, core.AdminPermission) {
				return nil, apiErrorf(409, "Your workspace needs an owner's attention")
			}
			return map[string]interface{}{"id": node.ID}, nil
		}
	}
	node, err := server.forest.AddChildNode(name, core.BranchNode, userID)
	if err != nil {
		return nil, err
	}
	node.Users = []core.User{{ID: userID, Permissions: []core.Permission{core.AdminPermission}}}
	node.Kind = "workspace"
	node.Metadata = map[string]interface{}{"title": "My workspace", "personal_owner": userID, "default_version": 1, "preferences": map[string]interface{}{"onboarding_completed": false, "view": "home"}}
	for _, title := range []string{"Inbox", "Goals", "Procedures", "Documents"} {
		child, err := server.workChild(node, title, "collection", userID)
		if err != nil {
			return nil, err
		}
		child.Metadata["collection"] = strings.ToLower(title)
		if title == "Inbox" {
			node.Metadata["preferences"].(map[string]interface{})["selected_id"] = child.ID
		}
	}
	return map[string]interface{}{"id": node.ID}, nil
}

func workPreferences(node *core.Node, userID string, patch map[string]interface{}) error {
	if node.Metadata["personal_owner"] != userID {
		return apiErrorf(403, "Preferences belong to your private workspace")
	}
	for key, value := range patch {
		switch key {
		case "onboarding_completed":
			if _, ok := value.(bool); !ok {
				return apiErrorf(400, "Expected onboarding completion")
			}
		case "selected_id":
			if _, ok := value.(string); !ok {
				return apiErrorf(400, "Expected a work identity")
			}
		case "view":
			if !strings.Contains("|home|workspace|timeline|diagram|", fmt.Sprintf("|%v|", value)) {
				return apiErrorf(400, "Unknown view")
			}
		default:
			return apiErrorf(400, "Unknown preference: %s", key)
		}
	}
	preferences, _ := node.Metadata["preferences"].(map[string]interface{})
	if preferences == nil {
		preferences = map[string]interface{}{}
	}
	for key, value := range patch {
		preferences[key] = value
	}
	node.Metadata["preferences"] = preferences
	return nil
}
