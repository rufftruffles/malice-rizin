package main

const tpl = `#### RIZIN (rz-bin)
- **Status:** {{ .Results.Status }}
{{- if .Results.Error }}
- **Error:** {{ .Results.Error }}
{{- end }}
{{- if .Results.Info }}

##### Binary
  - **Class:** {{ .Results.Info.Class }} ({{ .Results.Info.Arch }} {{ .Results.Info.Bits }}-bit, {{ .Results.Info.Endian }})
  - **Compiler:** {{ .Results.Info.Compiler }}
  - **OS:** {{ .Results.Info.Os }} / {{ .Results.Info.Subsys }}
  - **PIE:** {{ if .Results.Info.Pie }}yes{{ else }}no{{ end }} | **NX:** {{ if .Results.Info.Nx }}yes{{ else }}no{{ end }} | **RELRO:** {{ if .Results.Info.Relrocs }}full{{ else }}{{ .Results.Info.Relro }}{{ end }} | **Canary:** {{ if .Results.Info.Canary }}yes{{ else }}no{{ end }} | **Stripped:** {{ if .Results.Info.Stripped }}yes{{ else }}no{{ end }}
{{- end }}
{{- if .Results.Headers }}

##### Headers
{{range .Results.Headers}}
  - **{{ .Name }}:** {{ .Comment }}
{{- end }}
{{- end }}
{{- if .Results.Sections }}

##### Sections ({{ len .Results.Sections }})
| Name | Type | Perm | Size | Vaddr |
|------|------|------|------|-------|
{{range .Results.Sections}}
| {{ .Name }} | {{ .Type }} | {{ .Perm }} | {{ .Size }} | 0x{{ printf "%x" .Vaddr }} |
{{- end }}
{{- end }}
{{- if .Results.Libs }}

##### Linked Libraries
{{range .Results.Libs}}
  - {{ . }}
{{- end }}
{{- end }}
{{- if .Results.Entries }}

##### Entry Points
{{range .Results.Entries}}
  - {{ .Type }}: 0x{{ printf "%x" .Vaddr }}
{{- end }}
{{- end }}
{{- if .Results.Imports }}

##### Imports ({{ len .Results.Imports }})
{{range .Results.Imports}}
  - {{ .Name }} ({{ .Type }})
{{- end }}
{{- end }}
{{- if .Results.Exports }}

##### Exports ({{ len .Results.Exports }})
{{range .Results.Exports}}
  - {{ .Name }} ({{ .Type }})
{{- end }}
{{- end }}
{{- if .Results.Strings }}

##### Strings ({{ len .Results.Strings }})
{{range .Results.Strings}}
  - {{ .String }}
{{- end }}
{{- end }}
`
