package adapters

import (
	corev1 "github.com/agntcy/dir/api/core/v1"
	"github.com/agntcy/dir/server/types"
)

// ObjectRefV1Adapter implements the ObjectRef interface for core.v1.ObjectRef
type ObjectRefV1Adapter struct {
	proto *corev1.ObjectRef
}

// NewObjectRefV1 creates a new ObjectRefV1Adapter
func NewObjectRefV1(proto *corev1.ObjectRef) types.ObjectRef {
	return &ObjectRefV1Adapter{proto: proto}
}

func (a *ObjectRefV1Adapter) GetCID() string { return a.proto.Cid }

// ObjectV1Adapter implements the Object interface for core.v1.Object
type ObjectV1Adapter struct {
	proto *corev1.Object
}

// NewObjectV1 creates a new ObjectV1Adapter
func NewObjectV1(proto *corev1.Object) types.Object {
	return &ObjectV1Adapter{proto: proto}
}

func (a *ObjectV1Adapter) GetCID() string                    { return a.proto.Cid }
func (a *ObjectV1Adapter) GetType() string                   { return a.proto.Type.String() }
func (a *ObjectV1Adapter) GetAnnotations() map[string]string { return a.proto.Annotations }
func (a *ObjectV1Adapter) GetCreatedAt() string              { return a.proto.CreatedAt }
func (a *ObjectV1Adapter) GetSize() uint64                   { return a.proto.Size }
func (a *ObjectV1Adapter) GetData() []byte                   { return a.proto.Data }
func (a *ObjectV1Adapter) HasData() bool                     { return a.proto.Data != nil }

// Adapter functions

// ObjectRefProtoToDomain converts a core.v1.ObjectRef to the domain ObjectRef interface
func ObjectRefProtoToDomain(ref *corev1.ObjectRef) types.ObjectRef {
	return NewObjectRefV1(ref)
}

// DomainToObjectRefProto converts a domain ObjectRef to core.v1.ObjectRef
func DomainToObjectRefProto(ref types.ObjectRef) *corev1.ObjectRef {
	return &corev1.ObjectRef{
		Cid: ref.GetCID(),
	}
}

// ObjectProtoToDomain converts a core.v1.Object to the domain Object interface
func ObjectProtoToDomain(obj *corev1.Object) types.Object {
	return NewObjectV1(obj)
}

// DomainToObjectProto converts a domain Object to core.v1.Object
func DomainToObjectProto(obj types.Object) *corev1.Object {
	objectType := corev1.ObjectType_OBJECT_TYPE_UNSPECIFIED

	// Determine the correct ObjectType based on type string
	switch obj.GetType() {
	case "OBJECT_TYPE_RAW":
		objectType = corev1.ObjectType_OBJECT_TYPE_RAW
		// Add more cases as needed for other object types
	}

	var data []byte
	if obj.HasData() {
		data = obj.GetData()
	}

	return &corev1.Object{
		Cid:         obj.GetCID(),
		Type:        objectType,
		Annotations: obj.GetAnnotations(),
		CreatedAt:   obj.GetCreatedAt(),
		Size:        obj.GetSize(),
		Data:        data,
	}
}
