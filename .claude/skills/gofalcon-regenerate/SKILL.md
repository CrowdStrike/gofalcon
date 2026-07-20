---
name: gofalcon-regenerate
description: Regenerate gofalcon SDK code after modifying the swagger spec or transformation.jq. Use when the user asks to make a field nullable, fix a swagger definition, add a model, rename an operationId, regenerate a model/operation/collection/endpoint, or make any change to the gofalcon generated code.
license: MIT
metadata:
  author: github.com/ffalor
  version: "1.0"
---

# gofalcon Regenerate

Modify the gofalcon swagger spec transformations and regenerate SDK code.

## When to Use

Use this skill when the user wants to:
- Make a field nullable (`x-nullable: true`) so pointer types are generated
- Make a field not omit empty (`x-omitempty: false`)
- Add or fix a model definition in the swagger spec
- Rename an operationId
- Fix response codes or schema references
- Regenerate a specific model, operation, collection, or endpoint
- Any change that touches `specs/transformation.jq` and requires code regeneration

## Key Files

- `specs/swagger.json` — The raw CrowdStrike OpenAPI spec (obtained manually)
- `specs/transformation.jq` — JQ transformations applied to the spec before generation
- `specs/swagger-patched.json` — Output after applying transformation.jq
- `specs/swagger-stripped-oauth.json` — Final spec used for code generation
- `falcon/models/` — Generated model files
- `falcon/client/` — Generated client files

## Instructions

### 1. Identify the definition name

Find the exact definition name in the swagger spec. Model names in Go don't always match the spec:

```bash
# Search for the definition by keyword
cat specs/swagger.json | jq '.definitions | keys[]' | grep -i "<search-term>"

# Inspect a specific definition's properties
cat specs/swagger.json | jq '.definitions."<definition-name>".properties.<field>'
```

You can also find the spec definition name by looking at the generated Go file for a comment or the swagger annotation.

### 2. Edit specs/transformation.jq

Add the transformation at the appropriate location in the file. Follow the existing patterns:

**Make a field nullable** (generates `*type` instead of `type`):
```jq
| .definitions."<definition>".properties.<field> += {"x-nullable": true}
```

**Make a field not omit empty** (always serializes, even zero values):
```jq
| .definitions."<definition>".properties.<field> += {"x-omitempty": false}
```

**Both nullable and not omit empty:**
```jq
| .definitions."<definition>".properties.<field> += {"x-nullable": true, "x-omitempty": false}
```

**Add a new model definition:**
```jq
| .definitions."<new.ModelName>" = {
    "properties": {
        "field_name": {"type": "string"}
    }
}
```

**Rename an operationId:**
```jq
| .paths."<path>".<method>.operationId = "<NewOperationId>"
```

**Fix a response schema reference:**
```jq
| .paths."<path>".<method>.responses."<code>".schema = {"$ref": "#/definitions/<definition>"}
```

Always add a short comment above the transformation explaining why.

### 3. Regenerate the code

Use the `generate` CLI tool for selective regeneration. This is much faster than a full `make clean-generate`.

```bash
# Regenerate a specific model
generate model <definition-name>

# Regenerate a specific operation by operationId
generate operation <OperationId>

# Regenerate all operations in a collection (by tag)
generate collection <TagName>

# Regenerate all operations on an endpoint path
generate endpoint <path>
```

**Important:** When using `generate collection`, `generate operation`, or `generate endpoint`, the tool will remove other collection references from `falcon/client/crowd_strike_api_specification_client.go`. Discard those deletions and only keep the additions/updates for what you generated. The `generate model` command does not have this issue.

### 4. Verify the change

Check that the generated Go code reflects the intended change:

```bash
# For nullable fields, verify pointer type was generated
grep -n "<FieldName>" falcon/models/<generated_file>.go
```

## Common Patterns

### Bool fields with omitempty

Go's `encoding/json` omits `false` for `bool` with `omitempty`. Use `x-nullable: true` to generate `*bool`, allowing `false` to serialize and `nil` to omit.

### String fields that need empty string support

Use `x-nullable: true` to generate `*string`, allowing empty string `""` to serialize and `nil` to omit.

### Fields that must always be present in JSON

Use `x-omitempty: false` to ensure the field is always serialized, even when zero-valued.

## Full Regeneration

For a full SDK regeneration (rarely needed):

```bash
make clean-generate
```

This requires `specs/swagger.json` to be present and will regenerate all models and clients.
