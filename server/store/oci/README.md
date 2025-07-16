# OCI Storage Architecture

## Overview

The OCI storage system implements a **three-layer discovery architecture** that repurposes OCI registries as content-addressable storage for agent records. This design enables powerful discovery capabilities while maintaining compatibility with existing OCI tooling.

**Discovery Flow:** `Tags → Manifest → Blob`

1. **Tags** - Primary discovery mechanism (registry-indexed, human-readable)
2. **Manifest Annotations** - Secondary filtering (discovery & search metadata)  
3. **Descriptor Annotations** - Technical metadata (storage implementation details)

## Storage Architecture

### Core Storage Flow

```
Agent Record → Canonical JSON → Blob
     ↓
Manifest (contains Blob reference + Discovery Annotations)
     ↓
Multiple Tags (point to same Manifest for discovery)
```

### Access Pattern

**Critical**: OCI registries require following the proper access pattern:

```
Tag → Manifest → Blob
```

**Not**: Direct blob access by digest (may fail on remote registries)

This pattern ensures:
- Registry security validation
- Access control enforcement  
- Content integrity verification
- Universal OCI registry compatibility

### Layer Details

## 1. Tags (Primary Discovery)

Tags are **registry-indexed, human-readable names** that provide the primary entry point for discovery. They follow OCI registry standards and are automatically generated using configurable strategies.

### Tag Categories

#### **Content-Addressable Tags**
- **Purpose**: Immutable reference to specific content
- **Format**: `<CID>`
- **Example**: `bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi`

#### **Name-Based Tags**
- **Purpose**: Human-readable agent discovery
- **Formats**:
  - Basic name: `<name>`
  - Versioned: `<name>_<version>` (underscores for OCI compliance)
  - Latest: `<name>_latest`
- **Examples**: 
  - `nlp-agent`
  - `nlp-agent_v1.0.0`
  - `nlp-agent_latest`

#### **Capability-Based Tags**
- **Purpose**: Functional discovery by skills/extensions
- **Formats**:
  - Skills: `skill.<skill-name>`
  - Extensions: `ext.<extension-name>`
- **Examples**:
  - `skill.processing`
  - `skill.inference`
  - `ext.security`
  - `ext.monitoring`

#### **Infrastructure-Based Tags**
- **Purpose**: Deployment method discovery
- **Format**: `deploy.<locator-type>`
- **Examples**:
  - `deploy.docker`
  - `deploy.helm`
  - `deploy.k8s`

#### **Team-Based Tags**
- **Purpose**: Organizational discovery
- **Formats**:
  - Team: `team.<team-name>`
  - Organization: `org.<org-name>`
  - Project: `project.<project-name>`
- **Examples**:
  - `team.ai-research`
  - `org.acme`
  - `project.chatbot`

### Tag Strategy Configuration

```go
type TagStrategy struct {
    EnableNameTags           bool  // Name-based discovery
    EnableCapabilityTags     bool  // Skill/extension discovery  
    EnableInfrastructureTags bool  // Deployment discovery
    EnableTeamTags           bool  // Organizational discovery
    EnableContentAddressable bool  // Content-addressable (recommended)
    MaxTagsPerRecord         int   // Prevent tag explosion
}
```

### Tag Normalization

All tags are normalized for OCI compliance:
- Converted to lowercase
- Invalid characters replaced (`/` → `.`, ` ` → `-`)
- Length limited to 128 characters
- Must match pattern: `[a-zA-Z0-9_][a-zA-Z0-9._-]*`

## 2. Manifest Annotations (Discovery Metadata)

Manifest annotations provide **structured discovery and search metadata** that describe what the agent does. These are used for secondary filtering after initial tag-based discovery.

### Annotation Schema

All manifest keys use the prefix: `org.agntcy.dir/`

#### **Core Identity**
```
org.agntcy.dir/name: "nlp-processing-agent"
org.agntcy.dir/version: "v1.2.0" 
org.agntcy.dir/description: "Advanced NLP processing with sentiment analysis"
org.agntcy.dir/oasf-version: "v1alpha1"
```

#### **Lifecycle Metadata**
```
org.agntcy.dir/schema-version: "v1alpha1"
org.agntcy.dir/created-at: "2023-01-01T00:00:00Z"
org.agntcy.dir/authors: "alice@example.com,bob@example.com"
```

#### **Capability Discovery**
```
org.agntcy.dir/skills: "processing,inference,classification"
org.agntcy.dir/locator-types: "docker,helm"
org.agntcy.dir/extension-names: "security,monitoring,logging"
```

#### **Security & Integrity**
```
org.agntcy.dir/signed: "true"
org.agntcy.dir/signature-algorithm: "ed25519"
org.agntcy.dir/signed-at: "2023-01-01T12:00:00Z"
```

#### **Versioning & Linking**
```
org.agntcy.dir/previous-cid: "QmPreviousVersionCID123"
```

#### **Custom Annotations**
```
org.agntcy.dir/custom.team: "ai-research"
org.agntcy.dir/custom.environment: "production"
org.agntcy.dir/custom.cost-center: "engineering"
```

## 3. Descriptor Annotations (Technical Metadata)

Descriptor annotations provide **technical storage metadata** that describe how the blob is stored and encoded. These are primarily for internal system use.

### Technical Schema

#### **Format Information**
```
org.agntcy.dir/encoding: "json"
org.agntcy.dir/blob-type: "oasf-record"
org.agntcy.dir/schema: "oasf.v1alpha1.Agent"
org.agntcy.dir/compression: "none"
```

#### **Integrity Information**
```
org.agntcy.dir/content-cid: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
org.agntcy.dir/signed: "true"
```

#### **Storage Information**
```
org.agntcy.dir/stored-at: "2023-01-01T12:00:00Z"
org.agntcy.dir/store-version: "v1"
```

## Complete Example

### Agent Record (Input)
```go
record := &corev1.Record{
    Data: &corev1.Record_V1Alpha1{
        V1Alpha1: &oasfv1alpha1.Agent{
            Name:          "nlp-agent",
            Version:       "v1.0.0", 
            Description:   "NLP processing agent",
            SchemaVersion: "v1alpha1",
            CreatedAt:     "2023-01-01T00:00:00Z",
            Authors:       []string{"alice@example.com"},
            Skills: []*oasfv1alpha1.Skill{
                {CategoryName: stringPtr("nlp"), ClassName: stringPtr("processing")},
                {CategoryName: stringPtr("ml"), ClassName: stringPtr("inference")},
            },
            Locators: []*oasfv1alpha1.Locator{
                {Type: "docker"},
                {Type: "helm"},
            },
            Extensions: []*oasfv1alpha1.Extension{
                {Name: "security"},
                {Name: "monitoring"},
            },
            Annotations: map[string]string{
                "team":        "ai-research",
                "environment": "production",
            },
        },
    },
}
```

### Generated Tags
```
bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi  # Content-addressable
nlp-agent                                                      # Name
nlp-agent_v1.0.0                                              # Name + version (OCI compliant)  
nlp-agent_latest                                              # Name + latest (OCI compliant)
skill.processing                                              # Capability
skill.inference                                               # Capability
ext.security                                                  # Extension
ext.monitoring                                                # Extension
deploy.docker                                                 # Infrastructure
deploy.helm                                                   # Infrastructure
team.ai-research                                              # Team
```

### Manifest Annotations
```json
{
  "org.agntcy.dir/type": "record",
  "org.agntcy.dir/name": "nlp-agent",
  "org.agntcy.dir/version": "v1.0.0",
  "org.agntcy.dir/description": "NLP processing agent", 
  "org.agntcy.dir/oasf-version": "v1alpha1",
  "org.agntcy.dir/schema-version": "v1alpha1",
  "org.agntcy.dir/created-at": "2023-01-01T00:00:00Z",
  "org.agntcy.dir/authors": "alice@example.com",
  "org.agntcy.dir/skills": "processing,inference",
  "org.agntcy.dir/locator-types": "docker,helm",
  "org.agntcy.dir/extension-names": "security,monitoring",
  "org.agntcy.dir/signed": "false",
  "org.agntcy.dir/custom.team": "ai-research",
  "org.agntcy.dir/custom.environment": "production"
}
```

### Descriptor Annotations  
```json
{
  "org.agntcy.dir/encoding": "json",
  "org.agntcy.dir/blob-type": "oasf-record", 
  "org.agntcy.dir/schema": "oasf.v1alpha1.Agent",
  "org.agntcy.dir/compression": "none",
  "org.agntcy.dir/content-cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "org.agntcy.dir/signed": "false",
  "org.agntcy.dir/stored-at": "2023-01-01T12:00:00Z",
  "org.agntcy.dir/store-version": "v1"
}
```

## Discovery Workflows

### 1. Browse by Capability
```bash
# Find all NLP processing agents
oras repo tags <registry>/agents | grep "skill.processing"

# Get manifest for specific tag
oras manifest fetch <registry>/agents:skill.processing

# Filter by additional criteria using manifest annotations
jq '.annotations["org.agntcy.dir/locator-types"]' manifest.json
```

### 2. Find Latest Version
```bash
# Get latest version of specific agent
oras manifest fetch <registry>/agents:nlp-agent_latest

# Check version history via annotations
jq '.annotations["org.agntcy.dir/previous-cid"]' manifest.json
```

### 3. Security Verification
```bash
# Find signed agents only
oras manifest fetch <registry>/agents:nlp-agent
jq '.annotations["org.agntcy.dir/signed"]' manifest.json

# Verify signature details
jq '.annotations["org.agntcy.dir/signature-algorithm"]' manifest.json
jq '.annotations["org.agntcy.dir/signed-at"]' manifest.json
```

## API Integration

### Metadata Extraction
```go
// Extract discovery metadata from stored record
func (s *store) GetRecordMeta(cid string) (*corev1.RecordMeta, error) {
    // Fetch manifest by CID tag
    manifest := s.fetchManifest(cid)
    
    // Parse annotations into structured metadata
    return parseManifestAnnotations(manifest.Annotations), nil
}
```

### Tag Reconstruction
```go
// Rebuild discovery tags from stored metadata  
func (s *store) ReconstructTags(metadata map[string]string, cid string) []string {
    return generateTagsFromMetadata(metadata, cid, DefaultTagStrategy)
}
```

## Implementation Notes

### Critical: OCI Access Pattern Compliance

**Always use**: `Tag → Manifest → Blob` flow for record retrieval

```go
// ✅ CORRECT: Follow proper OCI flow
manifestDesc, err := repo.Resolve(ctx, cid)  // Tag → Manifest
manifest := parseManifest(manifestDesc)      // Parse manifest  
blobDesc := manifest.Layers[0]              // Get blob descriptor
reader, err := repo.Fetch(ctx, blobDesc)    // Manifest → Blob
```

```go
// ❌ INCORRECT: Direct blob access (may fail on remote registries)
digest, _ := getDigestFromCID(cid)
reader, err := repo.Fetch(ctx, ocispec.Descriptor{Digest: digest})
```

**Why this matters**:
- Remote OCI registries often require manifest resolution for security
- Direct blob access bypasses registry validation mechanisms
- Tag-based access ensures universal OCI registry compatibility

## File Reference

- **`constants.go`** - Complete annotation schema and key definitions
- **`tags.go`** - Tag generation strategies and normalization logic  
- **`annotations.go`** - Manifest/descriptor annotation handling
- **`oci.go`** - Main storage implementation with Push/Pull operations

## Schema Versioning

The annotation schema supports evolution through:

- **Store Version**: `org.agntcy.dir/store-version` tracks storage format changes
- **OASF Version**: `org.agntcy.dir/oasf-version` tracks agent schema changes  
- **Schema Version**: `org.agntcy.dir/schema-version` tracks agent content schema

This enables backward compatibility and migration paths as the system evolves. 