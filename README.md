# malice/rizin

`malice/rizin` is a [malice](https://github.com/maliceio/malice) scan engine
that runs [rizin](https://github.com/rizinorg/rizin) v0.9.0 (`rz-bin`, the
headless binary-analysis tool) to extract a binary's metadata: file headers,
sections, imports, exports, symbols, strings, linked libraries, and entry
points.

`rz-bin` is a static, headless analyzer — it needs no GUI and no target
architecture match. The engine is a thin Go wrapper that shells out to the
prebuilt static Linux `rz-bin` CLI, parses its `-j` (JSON) output, and stores a
curated result in Elasticsearch under `plugins.exe.rizin`.

This is a NEW engine (there is no classic malice/rizin or radare2 plugin to
preserve); the document shape was designed fresh for the `exe` category.

## Engine

- **Backend:** rizin v0.9.0 `rz-bin` — the prebuilt **static** Linux x86-64
  binary from the official release (no runtime shared-library dependencies).
  The tarball is checksum-pinned in the Dockerfile.
- **Base image:** `alpine:3.20` (the static binary runs on musl with no extra
  packages).
- **Category:** `exe`
- **MIME:** `*` (all file types)
- **Invocation:** a single combined `rz-bin -I -S -H -i -E -s -l -e -z -j`
  call extracts every section at once (far faster than one process per flag).

## Result document (`plugins.exe.rizin`)

```json
{
  "found": true,
  "status": "ok",
  "info": { "class": "ELF64", "bintype": "elf", "arch": "x86", "bits": 64,
            "compiler": "GCC: (GNU) 14.3.1 ...", "pie": false, "nx": true,
            "relrocs": true, "canary": false, "stripped": false, "...": "..." },
  "headers":  [ { "name": "MAGIC", "comment": "7f 45 4c 46 ..." } ],
  "sections": [ { "name": ".text", "type": "PROGBITS", "perm": "-r-x", "size": 295, "vaddr": 4198496, "paddr": 4192 } ],
  "imports":  [ { "name": "free", "bind": "GLOBAL", "type": "FUNC", "ordinal": 1 } ],
  "exports":  [ { "name": "_fini", "type": "FUNC", "bind": "GLOBAL", "vaddr": 4198792 } ],
  "symbols":  [ { "name": "__abi_tag", "type": "OBJ", "bind": "LOCAL", "vaddr": 4195228 } ],
  "strings":  [ { "string": "puts", "section": ".dynstr", "type": "ascii", "vaddr": 4195489 } ],
  "libs":     [ "libc.so.6" ],
  "entries":  [ { "type": "program", "vaddr": 4198496, "paddr": 4192 } ],
  "markdown": "#### RIZIN (rz-bin)\n..."
}
```

- `found` — rz-bin recognized a known binary format (a `class`/`bintype` was
  reported). Non-binary input yields `found:false` with `status:"ok"`.
- `status` — `ok` when the scan ran, `error` on rz-bin/parse failure,
  `skipped` when the sample is not staged.
- `info` — binary metadata from `rz-bin -I`, including the security properties
  `pie` / `nx` / `relrocs` / `canary` / `stripped` (always emitted, since a
  `false` value is itself a finding).
- `headers` — file-header fields from `rz-bin -H` (ELF/PE/Mach-O header).
- `sections` — sections from `rz-bin -S` (capped at 500). A missing virtual
  address is normalized to `0`.
- `imports` / `exports` / `symbols` — from `rz-bin -i` / `-E` / `-s` (capped at
  1000 each).
- `strings` — extracted strings from `rz-bin -z` (capped at 1000).
- `libs` — linked libraries from `rz-bin -l`.
- `entries` — entry points from `rz-bin -e`.
- `markdown` — human-readable summary rendered by the malice UI.

The engine always writes a document (even `found:false` on error / no-match /
skipped) so a scan is never left unwritten.

## Build

```
docker build --build-context pkgs=../malice-plugins -t malice/rizin:latest .
```

## Usage

```
scan [OPTIONS] <sha256>
  -t, --table          output as Markdown table
  -V, --verbose        verbose output
      --elasticsearch  elasticsearch url (env MALICE_ELASTICSEARCH_URL)
      --timeout        malice plugin timeout in seconds (env MALICE_TIMEOUT)
```
