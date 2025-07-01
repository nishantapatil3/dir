package types

// Record represents a unified interface for working with record objects
// regardless of their underlying proto version or format.
type Record interface {
	// GetCID returns the content identifier of the record
	GetCID() string

	// GetType returns the type of the record
	GetType() string

	// GetData returns the underlying record data
	GetData() interface{}

	// GetSchemaVersion returns the schema version of the record
	GetSchemaVersion() string
}

// ObjectRef represents a unified interface for working with object references
// regardless of their underlying proto version or format.
type ObjectRef interface {
	// GetCID returns the globally-unique content identifier (CID) of the object
	GetCID() string
}

// Object represents a unified interface for working with objects
// regardless of their underlying proto version or format.
type Object interface {
	// GetCID returns the globally-unique content identifier of the object
	GetCID() string

	// GetType returns the type of the object
	GetType() string

	// GetAnnotations returns metadata associated with the object
	GetAnnotations() map[string]string

	// GetCreatedAt returns the creation timestamp in RFC3339 format
	GetCreatedAt() string

	// GetSize returns the size of the object in bytes
	GetSize() uint64

	// GetData returns the opaque data held by this object
	// Returns nil if no data is present
	GetData() []byte

	// HasData returns true if the object contains data
	HasData() bool
}
