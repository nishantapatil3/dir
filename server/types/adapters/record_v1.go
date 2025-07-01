package adapters

import (
	corev1 "github.com/agntcy/dir/api/core/v1"
	"github.com/agntcy/dir/server/types"
)

// RecordV1Adapter implements the Record interface for core.v1.RecordObject
type RecordV1Adapter struct {
	proto *corev1.RecordObject
}

// NewRecordV1 creates a new RecordV1Adapter
func NewRecordV1(proto *corev1.RecordObject) types.Record {
	return &RecordV1Adapter{proto: proto}
}

func (a *RecordV1Adapter) GetCID() string       { return a.proto.Cid }
func (a *RecordV1Adapter) GetType() string      { return a.proto.Type.String() }
func (a *RecordV1Adapter) GetData() interface{} { return a.proto.Record }
func (a *RecordV1Adapter) GetSchemaVersion() string {
	// Schema version can be derived from the type or set explicitly
	switch a.proto.Type {
	case corev1.RecordObjectType_RECORD_OBJECT_TYPE_OASF_V1ALPHA1_JSON:
		return "v1alpha1"
	case corev1.RecordObjectType_RECORD_OBJECT_TYPE_OASF_V1ALPHA2_JSON:
		return "v1alpha2"
	default:
		return "unknown"
	}
}

// Adapter functions

// RecordProtoToDomain converts a core.v1.RecordObject to the domain Record interface
func RecordProtoToDomain(rec *corev1.RecordObject) types.Record {
	return NewRecordV1(rec)
}

// DomainToRecordProto converts a domain Record to core.v1.RecordObject
func DomainToRecordProto(rec types.Record) *corev1.RecordObject {
	recordType := corev1.RecordObjectType_RECORD_OBJECT_TYPE_UNSPECIFIED

	// Determine the correct RecordObjectType based on schema version or type
	switch rec.GetSchemaVersion() {
	case "v1alpha1":
		recordType = corev1.RecordObjectType_RECORD_OBJECT_TYPE_OASF_V1ALPHA1_JSON
	case "v1alpha2":
		recordType = corev1.RecordObjectType_RECORD_OBJECT_TYPE_OASF_V1ALPHA2_JSON
	}

	return &corev1.RecordObject{
		Cid:  rec.GetCID(),
		Type: recordType,
		// Note: You'll need to handle the conversion of rec.GetData() to RecordObjectData
		// This might require type assertion based on the actual data type
		Record: rec.GetData().(*corev1.RecordObjectData),
	}
}
