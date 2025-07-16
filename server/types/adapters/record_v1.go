package adapters

import (
	"fmt"

	corev1 "github.com/agntcy/dir/api/core/v1"
	oasfv1alpha1 "github.com/agntcy/dir/api/oasf/v1alpha1"
	oasfv1alpha2 "github.com/agntcy/dir/api/oasf/v1alpha2"
	"github.com/agntcy/dir/server/types"
	"google.golang.org/protobuf/types/known/structpb"
)

// RecordAdapter adapts corev1.Record to types.Record interface
type RecordAdapter struct {
	record *corev1.Record
}

// NewRecordAdapter creates a new RecordAdapter
func NewRecordAdapter(record *corev1.Record) *RecordAdapter {
	return &RecordAdapter{record: record}
}

// GetCid implements types.Record interface
func (r *RecordAdapter) GetCid() string {
	return r.record.GetCid()
}

// GetRecordData implements types.Record interface
func (r *RecordAdapter) GetRecordData() types.RecordData {
	switch data := r.record.GetData().(type) {
	case *corev1.Record_V1Alpha1:
		return NewV1Alpha1DataAdapter(data.V1Alpha1)
	case *corev1.Record_V1Alpha2:
		return NewV1Alpha2DataAdapter(data.V1Alpha2)
	default:
		return nil
	}
}

// V1Alpha1DataAdapter adapts oasfv1alpha1.Agent to types.RecordData interface
type V1Alpha1DataAdapter struct {
	agent *oasfv1alpha1.Agent
}

// NewV1Alpha1DataAdapter creates a new V1Alpha1DataAdapter
func NewV1Alpha1DataAdapter(agent *oasfv1alpha1.Agent) *V1Alpha1DataAdapter {
	return &V1Alpha1DataAdapter{agent: agent}
}

// GetAnnotations implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetAnnotations() map[string]string {
	if a.agent == nil {
		return nil
	}
	return a.agent.GetAnnotations()
}

// GetSchemaVersion implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetSchemaVersion() string {
	if a.agent == nil {
		return ""
	}
	return a.agent.GetSchemaVersion()
}

// GetName implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetName() string {
	if a.agent == nil {
		return ""
	}
	return a.agent.GetName()
}

// GetVersion implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetVersion() string {
	if a.agent == nil {
		return ""
	}
	return a.agent.GetVersion()
}

// GetDescription implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetDescription() string {
	if a.agent == nil {
		return ""
	}
	return a.agent.GetDescription()
}

// GetAuthors implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetAuthors() []string {
	if a.agent == nil {
		return nil
	}
	return a.agent.GetAuthors()
}

// GetCreatedAt implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetCreatedAt() string {
	if a.agent == nil {
		return ""
	}
	return a.agent.GetCreatedAt()
}

// GetSkills implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetSkills() []types.Skill {
	if a.agent == nil {
		return nil
	}
	skills := a.agent.GetSkills()
	result := make([]types.Skill, len(skills))
	for i, skill := range skills {
		result[i] = NewV1Alpha1SkillAdapter(skill)
	}
	return result
}

// GetLocators implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetLocators() []types.Locator {
	if a.agent == nil {
		return nil
	}
	locators := a.agent.GetLocators()
	result := make([]types.Locator, len(locators))
	for i, locator := range locators {
		result[i] = NewV1Alpha1LocatorAdapter(locator)
	}
	return result
}

// GetExtensions implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetExtensions() []types.Extension {
	if a.agent == nil {
		return nil
	}
	extensions := a.agent.GetExtensions()
	result := make([]types.Extension, len(extensions))
	for i, extension := range extensions {
		result[i] = NewV1Alpha1ExtensionAdapter(extension)
	}
	return result
}

// GetSignature implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetSignature() types.Signature {
	if a.agent == nil || a.agent.GetSignature() == nil {
		return nil
	}
	return NewV1Alpha1SignatureAdapter(a.agent.GetSignature())
}

// GetPreviousRecordCid implements types.RecordData interface
func (a *V1Alpha1DataAdapter) GetPreviousRecordCid() string {
	// V1Alpha1 doesn't have previous record CID
	return ""
}

// V1Alpha2DataAdapter adapts oasfv1alpha2.Record to types.RecordData interface
type V1Alpha2DataAdapter struct {
	record *oasfv1alpha2.Record
}

// NewV1Alpha2DataAdapter creates a new V1Alpha2DataAdapter
func NewV1Alpha2DataAdapter(record *oasfv1alpha2.Record) *V1Alpha2DataAdapter {
	return &V1Alpha2DataAdapter{record: record}
}

// GetAnnotations implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetAnnotations() map[string]string {
	if a.record == nil {
		return nil
	}
	return a.record.GetAnnotations()
}

// GetSchemaVersion implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetSchemaVersion() string {
	if a.record == nil {
		return ""
	}
	return a.record.GetSchemaVersion()
}

// GetName implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetName() string {
	if a.record == nil {
		return ""
	}
	return a.record.GetName()
}

// GetVersion implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetVersion() string {
	if a.record == nil {
		return ""
	}
	return a.record.GetVersion()
}

// GetDescription implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetDescription() string {
	if a.record == nil {
		return ""
	}
	return a.record.GetDescription()
}

// GetAuthors implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetAuthors() []string {
	if a.record == nil {
		return nil
	}
	return a.record.GetAuthors()
}

// GetCreatedAt implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetCreatedAt() string {
	if a.record == nil {
		return ""
	}
	return a.record.GetCreatedAt()
}

// GetSkills implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetSkills() []types.Skill {
	if a.record == nil {
		return nil
	}
	skills := a.record.GetSkills()
	result := make([]types.Skill, len(skills))
	for i, skill := range skills {
		result[i] = NewV1Alpha2SkillAdapter(skill)
	}
	return result
}

// GetLocators implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetLocators() []types.Locator {
	if a.record == nil {
		return nil
	}
	locators := a.record.GetLocators()
	result := make([]types.Locator, len(locators))
	for i, locator := range locators {
		result[i] = NewV1Alpha2LocatorAdapter(locator)
	}
	return result
}

// GetExtensions implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetExtensions() []types.Extension {
	if a.record == nil {
		return nil
	}
	extensions := a.record.GetExtensions()
	result := make([]types.Extension, len(extensions))
	for i, extension := range extensions {
		result[i] = NewV1Alpha2ExtensionAdapter(extension)
	}
	return result
}

// GetSignature implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetSignature() types.Signature {
	if a.record == nil || a.record.GetSignature() == nil {
		return nil
	}
	return NewV1Alpha2SignatureAdapter(a.record.GetSignature())
}

// GetPreviousRecordCid implements types.RecordData interface
func (a *V1Alpha2DataAdapter) GetPreviousRecordCid() string {
	if a.record == nil {
		return ""
	}
	return a.record.GetPreviousRecordCid()
}

// V1Alpha1SignatureAdapter adapts oasfv1alpha1.Signature to types.Signature interface
type V1Alpha1SignatureAdapter struct {
	signature *oasfv1alpha1.Signature
}

// NewV1Alpha1SignatureAdapter creates a new V1Alpha1SignatureAdapter
func NewV1Alpha1SignatureAdapter(signature *oasfv1alpha1.Signature) *V1Alpha1SignatureAdapter {
	return &V1Alpha1SignatureAdapter{signature: signature}
}

// GetAnnotations implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetAnnotations() map[string]string {
	// V1Alpha1 signature doesn't have annotations
	return nil
}

// GetSignedAt implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetSignedAt() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetSignedAt()
}

// GetAlgorithm implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetAlgorithm() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetAlgorithm()
}

// GetSignature implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetSignature() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetSignature()
}

// GetCertificate implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetCertificate() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetCertificate()
}

// GetContentType implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetContentType() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetContentType()
}

// GetContentBundle implements types.Signature interface
func (s *V1Alpha1SignatureAdapter) GetContentBundle() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetContentBundle()
}

// V1Alpha2SignatureAdapter adapts oasfv1alpha2.Signature to types.Signature interface
type V1Alpha2SignatureAdapter struct {
	signature *oasfv1alpha2.Signature
}

// NewV1Alpha2SignatureAdapter creates a new V1Alpha2SignatureAdapter
func NewV1Alpha2SignatureAdapter(signature *oasfv1alpha2.Signature) *V1Alpha2SignatureAdapter {
	return &V1Alpha2SignatureAdapter{signature: signature}
}

// GetAnnotations implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetAnnotations() map[string]string {
	if s.signature == nil {
		return nil
	}
	return s.signature.GetAnnotations()
}

// GetSignedAt implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetSignedAt() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetSignedAt()
}

// GetAlgorithm implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetAlgorithm() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetAlgorithm()
}

// GetSignature implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetSignature() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetSignature()
}

// GetCertificate implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetCertificate() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetCertificate()
}

// GetContentType implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetContentType() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetContentType()
}

// GetContentBundle implements types.Signature interface
func (s *V1Alpha2SignatureAdapter) GetContentBundle() string {
	if s.signature == nil {
		return ""
	}
	return s.signature.GetContentBundle()
}

// V1Alpha1ExtensionAdapter adapts oasfv1alpha1.Extension to types.Extension interface
type V1Alpha1ExtensionAdapter struct {
	extension *oasfv1alpha1.Extension
}

// NewV1Alpha1ExtensionAdapter creates a new V1Alpha1ExtensionAdapter
func NewV1Alpha1ExtensionAdapter(extension *oasfv1alpha1.Extension) *V1Alpha1ExtensionAdapter {
	return &V1Alpha1ExtensionAdapter{extension: extension}
}

// GetAnnotations implements types.Extension interface
func (e *V1Alpha1ExtensionAdapter) GetAnnotations() map[string]string {
	if e.extension == nil {
		return nil
	}
	return e.extension.GetAnnotations()
}

// GetName implements types.Extension interface
func (e *V1Alpha1ExtensionAdapter) GetName() string {
	if e.extension == nil {
		return ""
	}
	return e.extension.GetName()
}

// GetVersion implements types.Extension interface
func (e *V1Alpha1ExtensionAdapter) GetVersion() string {
	if e.extension == nil {
		return ""
	}
	return e.extension.GetVersion()
}

// GetData implements types.Extension interface
func (e *V1Alpha1ExtensionAdapter) GetData() map[string]any {
	if e.extension == nil || e.extension.GetData() == nil {
		return nil
	}
	return convertStructToMap(e.extension.GetData())
}

// V1Alpha2ExtensionAdapter adapts oasfv1alpha2.Extension to types.Extension interface
type V1Alpha2ExtensionAdapter struct {
	extension *oasfv1alpha2.Extension
}

// NewV1Alpha2ExtensionAdapter creates a new V1Alpha2ExtensionAdapter
func NewV1Alpha2ExtensionAdapter(extension *oasfv1alpha2.Extension) *V1Alpha2ExtensionAdapter {
	return &V1Alpha2ExtensionAdapter{extension: extension}
}

// GetAnnotations implements types.Extension interface
func (e *V1Alpha2ExtensionAdapter) GetAnnotations() map[string]string {
	if e.extension == nil {
		return nil
	}
	return e.extension.GetAnnotations()
}

// GetName implements types.Extension interface
func (e *V1Alpha2ExtensionAdapter) GetName() string {
	if e.extension == nil {
		return ""
	}
	return e.extension.GetName()
}

// GetVersion implements types.Extension interface
func (e *V1Alpha2ExtensionAdapter) GetVersion() string {
	if e.extension == nil {
		return ""
	}
	return e.extension.GetVersion()
}

// GetData implements types.Extension interface
func (e *V1Alpha2ExtensionAdapter) GetData() map[string]any {
	if e.extension == nil || e.extension.GetData() == nil {
		return nil
	}
	return convertStructToMap(e.extension.GetData())
}

// V1Alpha1SkillAdapter adapts oasfv1alpha1.Skill to types.Skill interface
type V1Alpha1SkillAdapter struct {
	skill *oasfv1alpha1.Skill
}

// NewV1Alpha1SkillAdapter creates a new V1Alpha1SkillAdapter
func NewV1Alpha1SkillAdapter(skill *oasfv1alpha1.Skill) *V1Alpha1SkillAdapter {
	return &V1Alpha1SkillAdapter{skill: skill}
}

// GetAnnotations implements types.Skill interface
func (s *V1Alpha1SkillAdapter) GetAnnotations() map[string]string {
	if s.skill == nil {
		return nil
	}
	return s.skill.GetAnnotations()
}

// GetName implements types.Skill interface
func (s *V1Alpha1SkillAdapter) GetName() string {
	if s.skill == nil {
		return ""
	}
	// TODO: maybe we should use the categoryName/className instead of just className
	return s.skill.GetClassName()
}

// GetId implements types.Skill interface
func (s *V1Alpha1SkillAdapter) GetId() uint64 {
	if s.skill == nil {
		return 0
	}
	return s.skill.GetClassUid()
}

// V1Alpha2SkillAdapter adapts oasfv1alpha2.Skill to types.Skill interface
type V1Alpha2SkillAdapter struct {
	skill *oasfv1alpha2.Skill
}

// NewV1Alpha2SkillAdapter creates a new V1Alpha2SkillAdapter
func NewV1Alpha2SkillAdapter(skill *oasfv1alpha2.Skill) *V1Alpha2SkillAdapter {
	return &V1Alpha2SkillAdapter{skill: skill}
}

// GetAnnotations implements types.Skill interface
func (s *V1Alpha2SkillAdapter) GetAnnotations() map[string]string {
	if s.skill == nil {
		return nil
	}
	return s.skill.GetAnnotations()
}

// GetName implements types.Skill interface
func (s *V1Alpha2SkillAdapter) GetName() string {
	if s.skill == nil {
		return ""
	}
	return s.skill.GetName()
}

// GetId implements types.Skill interface
func (s *V1Alpha2SkillAdapter) GetId() uint64 {
	if s.skill == nil {
		return 0
	}
	return uint64(s.skill.GetId())
}

// V1Alpha1LocatorAdapter adapts oasfv1alpha1.Locator to types.Locator interface
type V1Alpha1LocatorAdapter struct {
	locator *oasfv1alpha1.Locator
}

// NewV1Alpha1LocatorAdapter creates a new V1Alpha1LocatorAdapter
func NewV1Alpha1LocatorAdapter(locator *oasfv1alpha1.Locator) *V1Alpha1LocatorAdapter {
	return &V1Alpha1LocatorAdapter{locator: locator}
}

// GetAnnotations implements types.Locator interface
func (l *V1Alpha1LocatorAdapter) GetAnnotations() map[string]string {
	if l.locator == nil {
		return nil
	}
	return l.locator.GetAnnotations()
}

// GetType implements types.Locator interface
func (l *V1Alpha1LocatorAdapter) GetType() string {
	if l.locator == nil {
		return ""
	}
	return l.locator.GetType()
}

// GetUrl implements types.Locator interface
func (l *V1Alpha1LocatorAdapter) GetUrl() string {
	if l.locator == nil {
		return ""
	}
	return l.locator.GetUrl()
}

// GetSize implements types.Locator interface
func (l *V1Alpha1LocatorAdapter) GetSize() uint64 {
	if l.locator == nil {
		return 0
	}
	return l.locator.GetSize()
}

// GetDigest implements types.Locator interface
func (l *V1Alpha1LocatorAdapter) GetDigest() string {
	if l.locator == nil {
		return ""
	}
	return l.locator.GetDigest()
}

// V1Alpha2LocatorAdapter adapts oasfv1alpha2.Locator to types.Locator interface
type V1Alpha2LocatorAdapter struct {
	locator *oasfv1alpha2.Locator
}

// NewV1Alpha2LocatorAdapter creates a new V1Alpha2LocatorAdapter
func NewV1Alpha2LocatorAdapter(locator *oasfv1alpha2.Locator) *V1Alpha2LocatorAdapter {
	return &V1Alpha2LocatorAdapter{locator: locator}
}

// GetAnnotations implements types.Locator interface
func (l *V1Alpha2LocatorAdapter) GetAnnotations() map[string]string {
	if l.locator == nil {
		return nil
	}
	return l.locator.GetAnnotations()
}

// GetType implements types.Locator interface
func (l *V1Alpha2LocatorAdapter) GetType() string {
	if l.locator == nil {
		return ""
	}
	return l.locator.GetType()
}

// GetUrl implements types.Locator interface
func (l *V1Alpha2LocatorAdapter) GetUrl() string {
	if l.locator == nil {
		return ""
	}
	return l.locator.GetUrl()
}

// GetSize implements types.Locator interface
func (l *V1Alpha2LocatorAdapter) GetSize() uint64 {
	if l.locator == nil {
		return 0
	}
	return l.locator.GetSize()
}

// GetDigest implements types.Locator interface
func (l *V1Alpha2LocatorAdapter) GetDigest() string {
	if l.locator == nil {
		return ""
	}
	return l.locator.GetDigest()
}

// convertStructToMap converts a protobuf Struct to a map[string]any
func convertStructToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	result := make(map[string]any)
	for k, v := range s.GetFields() {
		result[k] = convertValue(v)
	}
	return result
}

// convertValue converts a protobuf Value to any
func convertValue(v *structpb.Value) any {
	if v == nil {
		return nil
	}
	switch v := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return nil
	case *structpb.Value_NumberValue:
		return v.NumberValue
	case *structpb.Value_StringValue:
		return v.StringValue
	case *structpb.Value_BoolValue:
		return v.BoolValue
	case *structpb.Value_StructValue:
		return convertStructToMap(v.StructValue)
	case *structpb.Value_ListValue:
		result := make([]any, len(v.ListValue.GetValues()))
		for i, item := range v.ListValue.GetValues() {
			result[i] = convertValue(item)
		}
		return result
	default:
		return fmt.Sprintf("unsupported type: %T", v)
	}
}
