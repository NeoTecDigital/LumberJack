package core

const (
	ReadPermission Permission = iota
	WritePermission
	AdminPermission
)

const (
	AccountLeaf LeafType = iota
	ProgressLeaf
	EventLogLeaf
	NoteLeaf
	AssetLeaf
	TimedEventLeaf // New leaf type for timed events
)

const (
	EventPending  EventStatus = "pending"
	EventOngoing  EventStatus = "ongoing"
	EventFinished EventStatus = "finished"
)

const (
	LeafNode NodeType = iota
	BranchNode
)

// NewNode creates a new node with updated fields
func NewNode(nodeType NodeType, name string) *Node {
	return &Node{
		ID:            GenerateNodeID(),
		Type:          nodeType,
		Name:          name,
		Parents:       make(map[string]string),
		Children:      make(map[string]*Node),
		Events:        make(map[string]Event),
		PlannedEvents: make(map[string]Event),
		Users:         []User{},
		Entries:       []Entry{},
	}
}

// NewForest initializes a new forest with a root node
func NewForest(rootNodeName string) *Node {
	rootNode := NewNode(BranchNode, rootNodeName)
	return rootNode
}
