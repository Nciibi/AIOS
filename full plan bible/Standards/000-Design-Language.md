# AIOS Standards
## 000 — Design Language

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Standards |
| Document ID | STD-DL-000 |
| Source Laws | All |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This standard defines the visual and verbal design language for AIOS documentation, diagrams, and interfaces. Consistent design language ensures that every AIOS document, diagram, and UI element communicates clearly and follows the same conventions.

## Document Typography

### Headings

```
# AIOS <Section> — Document Title (H1, document title only)
## <Number> — Subtitle (H2, section header)
### Topic (H3, subsection)
#### Detail (H4, sub-subsection)
```

### Emphasis
- **Bold** for key terms and concepts on first use
- `Code` for identifiers, commands, file paths, code references
- *Italic* for emphasis and cross-references to external documents
- `| table |` for structured data

### Code Blocks
Use fenced code blocks with language tag for code examples:

```python
def example():
    pass
```

For configuration, command output, and diagrams, use plain fenced blocks without a language tag.

## Diagram Conventions

### ASCII Architecture Diagrams
- Use `┌───┐`, `│`, `└───┘` for component boxes
- Use `▼`, `▲` for data flow direction
- Use `───` for connections between components
- Label each box with the component name and single-line description
- Keep diagrams left-aligned, no indentation

### Component Hierarchy
- Top-level components: wide boxes spanning full width
- Sub-components: narrower boxes indented
- Infrastructure: bottom layer, full width

### Pipeline Diagrams
```
Stage N: Abbreviation │ Description
┌─────────────┐
│ Stage N: ABB │  Description
└──────┬──────┘
       ▼
```

## Vocabulary Standard

### Acronyms
- Define every acronym on first use in each document: `IDS (Identity Service)`
- Use the canonical acronym consistently across all docs
- Maintain a registry of all acronyms in Bible/09-Reference/001-Glossary.md

### Naming Styles

| Context | Style | Example |
|---------|-------|---------|
| Document IDs | UPPER-KEBAB | `AIOS-BBL-008-SDK-000` |
| Service names | lowercase | `lms`, `evs`, `psap` |
| ACF topics | lowercase, dot-separated | `aios.security.auth` |
| Event types | PascalCase with dot prefix | `Session.Created`, `Auth.Failed` |
| File names | 3-digit prefix + kebab-case | `005-Platform-Architecture.md` |
| Entity types | lowercase in IDs | `org`, `session`, `engine` |
| Laws | "Law N — Name" | `Law 4 — Law of Evidence` |
| Error codes | UPPER-SNAKE with source prefix | `SESSION_001`, `AUTH_002` |

## Color and Visual Style

For diagrams and UI:
- **Primary**: Constitutional entities (Sou, Security Council) — bold borders
- **Service**: Platform and infrastructure services — standard borders
- **Data**: Events and evidence — dashed borders
- **External**: Human interface and external systems — double borders
- **Error/Failure**: Red highlight, cross-hatch fill in ASCII

## Document Structure

Every Standards document follows:
1. H1 + H2 header
2. Metadata table
3. Purpose section
4. Body content organized by topic
5. Cross-Cutting Concerns section (Security, Evidence, Lifecycle, Capability Bounds, Interoperability)
6. Related Documents section

## Cross-Cutting Concerns

### Security
Standards define conventions that affect system security. Naming, addressing, and registration standards must prevent spoofing, injection, and misdirection.

### Evidence
Standards documents are versioned and amended through RFC. Changes to standards produce Events tracked in the evidence chain.

### Lifecycle
Standards follow the governance lifecycle defined in Bible/01-Governance. Standards may be Deprecated or Superseded as the system evolves.

### Capability Bounds
Standards define the boundaries of what is allowed. Deviations require RFC approval.

### Interoperability
Standards exist to ensure interoperability. Every standard must consider backward compatibility and migration paths.

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-Naming-Conventions.md | Naming conventions — detailed naming rules |
| 002-BAS.md | Bible Authoring Standards — document format |
| 003-DQC.md | Document Quality Checklist — quality criteria |
| Bible/00-Foundations/007-Naming-Conventions.md | Identity ID format |
| Bible/09-Reference/001-Glossary.md | Acronym and term registry |
