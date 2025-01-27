package metal

import (
	"time"
)

// Base implements common fields for most basic entity types (not all).
type Base struct {
	ID          string    `rethinkdb:"id,omitempty" json:"id,omitempty"`
	Name        string    `rethinkdb:"name" json:"name"`
	Description string    `rethinkdb:"description" json:"description"`
	Created     time.Time `rethinkdb:"created" json:"created"`
	Changed     time.Time `rethinkdb:"changed" json:"changed"`
}

// GetID returns the ID of the entity
func (b *Base) GetID() string {
	return b.ID
}

// SetID sets the ID of the entity
func (b *Base) SetID(id string) {
	b.ID = id
}

// GetChanged returns the last changed timestamp of the entity
func (b *Base) GetChanged() time.Time {
	return b.Changed
}

// SetChanged sets the last changed timestamp of the entity
func (b *Base) SetChanged(changed time.Time) {
	b.Changed = changed
}

// GetCreated returns the creation timestamp of the entity
func (b *Base) GetCreated() time.Time {
	return b.Created
}

// SetCreated sets the creation timestamp of the entity
func (b *Base) SetCreated(created time.Time) {
	b.Created = created
}
