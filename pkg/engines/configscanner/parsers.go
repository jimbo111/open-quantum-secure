package configscanner

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// parseYAML flattens YAML documents into dotted key-value pairs. Supports
// multi-document YAML (separated by ---). Nested maps produce dot-separated
// keys (e.g. "spring.datasource.password"). Line numbers are taken from the
// yaml.Node position information.
func parseYAML(data []byte) ([]KeyValue, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var kvs []KeyValue
	for {
		var root yaml.Node
		if err := dec.Decode(&root); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Return what we have so far plus the error.
			if len(kvs) > 0 {
				return kvs, fmt.Errorf("yaml parse: %w", err)
			}
			return nil, fmt.Errorf("yaml parse: %w", err)
		}
		if root.Kind == 0 {
			continue
		}
		flattenYAMLNode(&root, "", &kvs)
	}
	return kvs, nil
}

// maxYAMLDepth limits recursion depth to prevent stack overflow from deeply nested documents.
const maxYAMLDepth = 64

// maxYAMLEntries limits the total number of KV entries to prevent alias bomb expansion.
const maxYAMLEntries = 100_000

// flattenYAMLNode recursively walks a yaml.Node tree, collecting leaf scalar
// values as KeyValue entries with dot-separated key paths.
// It tracks visited nodes to detect cycles, limits depth, and caps total output.
func flattenYAMLNode(node *yaml.Node, prefix string, out *[]KeyValue) {
	seen := make(map[*yaml.Node]bool)
	flattenYAMLNodeRec(node, prefix, out, seen, 0)
}

func flattenYAMLNodeRec(node *yaml.Node, prefix string, out *[]KeyValue, seen map[*yaml.Node]bool, depth int) {
	if depth > maxYAMLDepth || len(*out) >= maxYAMLEntries {
		return
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			flattenYAMLNodeRec(child, prefix, out, seen, depth+1)
		}

	case yaml.MappingNode:
		// Content is alternating key/value pairs.
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			key := keyNode.Value
			if prefix != "" {
				key = prefix + "." + key
			}
			flattenYAMLNodeRec(valNode, key, out, seen, depth+1)
		}

	case yaml.SequenceNode:
		// For sequences, index each element with "[n]" suffix.
		for i, child := range node.Content {
			key := fmt.Sprintf("%s[%d]", prefix, i)
			flattenYAMLNodeRec(child, key, out, seen, depth+1)
		}

	case yaml.ScalarNode:
		if prefix == "" {
			return
		}
		*out = append(*out, KeyValue{
			Key:   prefix,
			Value: node.Value,
			Line:  node.Line,
		})

	case yaml.AliasNode:
		// Resolve alias by following to the anchor node.
		// Use full visited set (not path-based) to prevent alias bomb expansion:
		// once an anchor subtree is flattened, skip subsequent aliases to the same node.
		if node.Alias != nil {
			if seen[node.Alias] {
				return // already visited or cycle — skip
			}
			seen[node.Alias] = true
			flattenYAMLNodeRec(node.Alias, prefix, out, seen, depth+1)
			// Do NOT delete from seen — prevents exponential re-traversal (alias bomb).
		}
	}
}

// parseJSON flattens a JSON object into dotted key-value pairs. Only string
// and numeric leaf values are captured. Line numbers are not available from
// the standard library decoder so they are left as 0.
func parseJSON(data []byte) ([]KeyValue, error) {
	var raw interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // preserve numeric precision
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}
	var kvs []KeyValue
	flattenJSONValue(raw, "", &kvs)
	return kvs, nil
}

// maxJSONDepth limits recursion depth to prevent stack overflow from deeply nested JSON.
const maxJSONDepth = 64

// maxJSONEntries limits total output entries (same bound as YAML).
const maxJSONEntries = 100_000

// flattenJSONValue recursively walks a decoded JSON value with depth and entry limits.
func flattenJSONValue(v interface{}, prefix string, out *[]KeyValue) {
	flattenJSONValueRec(v, prefix, out, 0)
}

func flattenJSONValueRec(v interface{}, prefix string, out *[]KeyValue, depth int) {
	if depth > maxJSONDepth || len(*out) >= maxJSONEntries {
		return
	}
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenJSONValueRec(child, key, out, depth+1)
		}
	case []interface{}:
		for i, child := range val {
			key := fmt.Sprintf("%s[%d]", prefix, i)
			flattenJSONValueRec(child, key, out, depth+1)
		}
	case string:
		if prefix != "" {
			*out = append(*out, KeyValue{Key: prefix, Value: val, Line: 0})
		}
	case json.Number:
		if prefix != "" {
			*out = append(*out, KeyValue{Key: prefix, Value: val.String(), Line: 0})
		}
	case bool:
		if prefix != "" {
			s := "false"
			if val {
				s = "true"
			}
			*out = append(*out, KeyValue{Key: prefix, Value: s, Line: 0})
		}
	// nil / other types: skip
	}
}

// parseProperties parses a Java-style .properties file. Supported syntax:
//   - key=value
//   - key: value
//   - Lines starting with # or ! are comments.
//   - Continuation lines ending in \ are joined.
//   - Leading/trailing whitespace is stripped from keys and values.
func parseProperties(data []byte) ([]KeyValue, error) {
	var kvs []KeyValue
	lines := splitLines(data)
	lineNum := 0
	for i := 0; i < len(lines) && len(kvs) < maxHCLEntries; {
		lineNum++
		line := strings.TrimSpace(lines[i])
		i++

		// Skip blank lines and comments.
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}

		// Record the starting line for this entry (before consuming
		// continuation lines).
		startLine := lineNum

		// Handle continuation lines using a builder to avoid O(n²) concatenation.
		if strings.HasSuffix(line, "\\") {
			var b strings.Builder
			b.WriteString(line[:len(line)-1])
			for i < len(lines) {
				cont := strings.TrimLeft(lines[i], " \t")
				i++
				lineNum++
				if strings.HasSuffix(cont, "\\") {
					b.WriteString(cont[:len(cont)-1])
				} else {
					b.WriteString(cont)
					break
				}
			}
			line = b.String()
		}

		// Split on = or : (first occurrence).
		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		kvs = append(kvs, KeyValue{
			Key:   strings.TrimSpace(key),
			Value: strings.TrimSpace(value),
			Line:  startLine,
		})
	}
	return kvs, nil
}

// parseEnv parses a .env file. Supported syntax:
//   - KEY=VALUE or KEY="VALUE" or KEY='VALUE'
//   - Lines starting with # are comments.
//   - Empty lines are skipped.
//   - export KEY=VALUE is supported.
func parseEnv(data []byte) ([]KeyValue, error) {
	var kvs []KeyValue
	lines := splitLines(data)
	for lineNum, raw := range lines {
		if len(kvs) >= maxHCLEntries {
			break
		}
		line := strings.TrimSpace(raw)

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip optional "export " prefix (case-insensitive).
		if len(line) >= 7 && strings.EqualFold(line[:7], "export ") {
			line = line[7:]
		}
		line = strings.TrimSpace(line)

		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Handle quoted values: find the matching closing quote and discard
		// any trailing inline comment. The previous approach checked
		// value[len(value)-1] for a closing quote, which fails when the
		// value is followed by an inline comment (e.g. KEY="val # x" # comment).
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
			q := value[0]
			if ci := strings.IndexByte(value[1:], q); ci >= 0 {
				// Extract content between matching quotes.
				value = value[1 : ci+1]
			} else {
				// No matching closing quote — best-effort: strip the leading quote.
				value = value[1:]
			}
		} else {
			// Unquoted value: strip inline comment introduced by " #".
			if ci := strings.Index(value, " #"); ci >= 0 {
				value = strings.TrimSpace(value[:ci])
			}
		}

		kvs = append(kvs, KeyValue{
			Key:   key,
			Value: value,
			Line:  lineNum + 1,
		})
	}
	return kvs, nil
}

// maxTOMLDepth limits recursion depth to prevent stack overflow from deeply nested TOML.
const maxTOMLDepth = 64

// maxTOMLEntries limits total output entries (same bound as YAML/JSON).
const maxTOMLEntries = 100_000

// parseTOML flattens a TOML document into dotted key-value pairs. Nested
// tables produce dot-separated keys (e.g. "server.tls.cipher"). Arrays of
// tables are indexed with "[n]" suffixes. Line numbers are not available
// from BurntSushi/toml, so Line fields are 0 (consistent with parseJSON).
func parseTOML(data []byte) ([]KeyValue, error) {
	var raw interface{}
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return nil, fmt.Errorf("toml parse: %w", err)
	}
	var kvs []KeyValue
	flattenTOMLValue(raw, "", &kvs, 0)
	return kvs, nil
}

// flattenTOMLValue recursively walks a decoded TOML value with depth and
// entry limits. Line numbers are not available from BurntSushi/toml, so all
// Line fields are set to 0 (consistent with parseJSON behaviour).
func flattenTOMLValue(v interface{}, prefix string, out *[]KeyValue, depth int) {
	if depth > maxTOMLDepth || len(*out) >= maxTOMLEntries {
		return
	}
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenTOMLValue(child, key, out, depth+1)
		}
	case []map[string]interface{}:
		// Arrays of tables ([[section]]) decode as []map[string]interface{}.
		for i, child := range val {
			key := fmt.Sprintf("%s[%d]", prefix, i)
			flattenTOMLValue(child, key, out, depth+1)
		}
	case []interface{}:
		for i, child := range val {
			key := fmt.Sprintf("%s[%d]", prefix, i)
			flattenTOMLValue(child, key, out, depth+1)
		}
	case string:
		if prefix != "" {
			*out = append(*out, KeyValue{Key: prefix, Value: val, Line: 0})
		}
	case int64:
		if prefix != "" {
			*out = append(*out, KeyValue{Key: prefix, Value: fmt.Sprintf("%d", val), Line: 0})
		}
	case float64:
		if prefix != "" {
			*out = append(*out, KeyValue{Key: prefix, Value: fmt.Sprintf("%g", val), Line: 0})
		}
	case bool:
		if prefix != "" {
			s := "false"
			if val {
				s = "true"
			}
			*out = append(*out, KeyValue{Key: prefix, Value: s, Line: 0})
		}
	// nil, toml.LocalDate, toml.LocalTime, toml.LocalDatetime, time.Time: skip
	}
}

// maxXMLDepth limits element nesting depth to prevent stack exhaustion on
// pathological documents.
const maxXMLDepth = 64

// maxXMLEntries limits total KV output entries (same bound as YAML/JSON).
const maxXMLEntries = 100_000

// parseXML flattens an XML document into dotted key-value pairs using
// Go's encoding/xml streaming token decoder.
//
// Nesting is flattened with dot-separated keys:
//
//	<server><ssl><protocol>TLS 1.2</protocol></ssl></server>
//	→ Key="server.ssl.protocol", Value="TLS 1.2"
//
// Attributes are recorded with the [@attr] notation:
//
//	<ssl enabled="true"> → Key="ssl[@enabled]", Value="true"
//
// Security: Go's xml.Decoder does NOT fetch external entities by default
// (it has no HTTP client and does not resolve SYSTEM or PUBLIC identifiers).
// Setting Strict=true (the default) ensures well-formedness is enforced and
// entity references that cannot be resolved from the inline DTD are rejected,
// which prevents blind XXE expansion.
//
// Line numbers are not directly exposed by encoding/xml; all Line fields are
// set to 0 (consistent with parseJSON).
func parseXML(data []byte) ([]KeyValue, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	// Strict mode is the default and enforces well-formedness.
	// AutoClose and Entity are deliberately left at zero-value (nil) so that
	// no external entity resolution can occur.
	dec.Strict = true

	var kvs []KeyValue

	// Stack tracks the element name path from root to current node.
	// We pre-allocate a reasonable capacity to avoid repeated growths.
	stack := make([]string, 0, 16)

	for {
		if len(kvs) >= maxXMLEntries {
			break
		}

		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return kvs, fmt.Errorf("xml parse: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxXMLDepth {
				// Skip this subtree: keep reading tokens until its EndElement.
				if skipErr := skipXMLElement(dec); skipErr != nil && !errors.Is(skipErr, io.EOF) {
					return kvs, fmt.Errorf("xml parse: %w", skipErr)
				}
				continue
			}

			// Strip namespace prefix from local name for simpler dotted keys.
			localName := t.Name.Local

			stack = append(stack, localName)
			prefix := strings.Join(stack, ".")

			// Emit attributes as <prefix>[@attrName] = value.
			for _, attr := range t.Attr {
				if len(kvs) >= maxXMLEntries {
					break
				}
				attrLocal := attr.Name.Local
				kvs = append(kvs, KeyValue{
					Key:   prefix + "[@" + attrLocal + "]",
					Value: attr.Value,
					Line:  0,
				})
			}

		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case xml.CharData:
			// Trim whitespace; skip pure-whitespace text nodes (indentation etc.).
			text := strings.TrimSpace(string(t))
			if text == "" || len(stack) == 0 {
				continue
			}
			if len(kvs) >= maxXMLEntries {
				break
			}
			kvs = append(kvs, KeyValue{
				Key:   strings.Join(stack, "."),
				Value: text,
				Line:  0,
			})

		// xml.Comment, xml.ProcInst, xml.Directive: intentionally skipped.
		}
	}

	return kvs, nil
}

// skipXMLElement consumes tokens until the matching EndElement for the element
// whose StartElement has already been consumed by the caller.
func skipXMLElement(dec *xml.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

// parseINI parses an INI/CFG file. Supported syntax:
//   - [section] headers produce dotted key prefixes.
//   - key=value or key: value assignments.
//   - Lines starting with ; or # are comments.
//   - Continuation lines ending in \ are joined (same as .properties).
//   - Leading/trailing whitespace is stripped from keys and values.
//   - Nested sections via "." in section name (e.g. [server.ssl]).
//   - Inline comments after ; or # (unquoted) are stripped.
func parseINI(data []byte) ([]KeyValue, error) {
	var kvs []KeyValue
	lines := splitLines(data)
	section := ""
	lineNum := 0

	for i := 0; i < len(lines) && len(kvs) < maxHCLEntries; {
		lineNum++
		line := strings.TrimSpace(lines[i])
		i++

		// Skip blank lines and comments.
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Section header: [section.name]
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end > 0 {
				section = strings.TrimSpace(line[1:end])
			}
			continue
		}

		startLine := lineNum

		// Handle continuation lines.
		if strings.HasSuffix(line, "\\") {
			var b strings.Builder
			b.WriteString(line[:len(line)-1])
			for i < len(lines) {
				cont := strings.TrimLeft(lines[i], " \t")
				i++
				lineNum++
				if strings.HasSuffix(cont, "\\") {
					b.WriteString(cont[:len(cont)-1])
				} else {
					b.WriteString(cont)
					break
				}
			}
			line = b.String()
		}

		// Split on = or : (first occurrence).
		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		// Handle quoted values: extract content between matching quotes,
		// discarding any trailing inline comment.
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
			quote := value[0]
			// Find the matching closing quote (skip the opening one).
			if ci := strings.IndexByte(value[1:], quote); ci >= 0 {
				value = value[1 : 1+ci] // content between quotes
			} else {
				value = stripQuotes(value) // fallback: unterminated quote
			}
		} else {
			// Strip inline comment after ; or # (with leading space).
			if ci := strings.Index(value, " ;"); ci >= 0 {
				value = strings.TrimSpace(value[:ci])
			} else if ci := strings.Index(value, " #"); ci >= 0 {
				value = strings.TrimSpace(value[:ci])
			}
		}

		// Skip entries with empty keys (e.g., line with only "=").
		if key == "" {
			continue
		}

		// Prefix key with section if present.
		if section != "" {
			key = section + "." + key
		}

		kvs = append(kvs, KeyValue{
			Key:   key,
			Value: value,
			Line:  startLine,
		})
	}
	return kvs, nil
}

// maxHCLDepth limits nesting depth for HCL blocks.
const maxHCLDepth = 64

// maxHCLEntries limits total output entries (same bound as other parsers).
const maxHCLEntries = 100_000

// parseHCL parses an HCL/Terraform file into dotted key-value pairs.
// Block labels are joined with dots to form key prefixes:
//
//	resource "tls_private_key" "example" {
//	  algorithm = "RSA"
//	}
//	→ Key="resource.tls_private_key.example.algorithm", Value="RSA"
//
// Supports:
//   - key = "value" (string), key = 123 (number), key = true/false (boolean)
//   - Nested blocks with optional labels
//   - Line comments (# and //) and block comments (/* */)
//   - Heredoc strings (<<EOF ... EOF and <<-EOF ... EOF)
//   - Quoted strings with escaped characters
//
// Line numbers are tracked per key-value assignment.
func parseHCL(data []byte) ([]KeyValue, error) {
	lines := splitLines(data)
	var kvs []KeyValue
	parseHCLLines(lines, "", &kvs, 0, 0)
	return kvs, nil
}

// parseHCLLines recursively parses HCL from a set of lines, using a shared
// line index to track position. baseLineOffset is the 0-based offset from the
// start of the original file (so that recursive calls into block bodies
// produce correct 1-based line numbers). Returns the next unprocessed line index.
func parseHCLLines(lines []string, prefix string, out *[]KeyValue, depth int, baseLineOffset int) int {
	lineIdx := 0
	inBlockComment := false

	for lineIdx < len(lines) && len(*out) < maxHCLEntries {
		if depth > maxHCLDepth {
			// Consume remaining lines until matching closing brace so that
			// unconsumed `}` tokens don't prematurely close parent blocks.
			braceDepth := 1
			for lineIdx < len(lines) && braceDepth > 0 {
				l := strings.TrimSpace(lines[lineIdx])
				lineIdx++
				if strings.HasSuffix(l, "{") {
					braceDepth++
				}
				if l == "}" || strings.HasPrefix(l, "}") {
					braceDepth--
				}
			}
			return lineIdx
		}

		raw := lines[lineIdx]
		lineNum := baseLineOffset + lineIdx + 1 // 1-based line number in original file
		line := strings.TrimSpace(raw)
		lineIdx++

		// Handle block comments.
		if inBlockComment {
			if idx := strings.Index(line, "*/"); idx >= 0 {
				inBlockComment = false
				// Process remainder after close.
				line = strings.TrimSpace(line[idx+2:])
				if line == "" {
					continue
				}
			} else {
				continue
			}
		}

		// Strip block comment openings. Only match `/*` that appears OUTSIDE
		// a quoted string — a literal `/*` inside "..." is string data, not
		// a comment start.
		if idx := indexOutsideHCLStrings(line, "/*"); idx >= 0 {
			before := strings.TrimSpace(line[:idx])
			after := line[idx+2:]
			if closeIdx := indexOutsideHCLStrings(after, "*/"); closeIdx >= 0 {
				// Inline block comment — remove and continue with rest.
				line = before + " " + strings.TrimSpace(after[closeIdx+2:])
				line = strings.TrimSpace(line)
			} else {
				inBlockComment = true
				line = before
			}
			if line == "" {
				continue
			}
		}

		// Skip empty lines and line comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Closing brace — return to parent block.
		if line == "}" || strings.HasPrefix(line, "}") {
			return lineIdx
		}

		// Check for key = value assignment.
		if eqIdx := strings.Index(line, "="); eqIdx > 0 {
			key := strings.TrimSpace(line[:eqIdx])
			valPart := strings.TrimSpace(line[eqIdx+1:])

			// Skip if key contains spaces (likely a block header, not assignment).
			if strings.ContainsAny(key, " \t") {
				// Could be a block definition — fall through to block handling.
			} else {
				// Strip trailing inline comment.
				val := hclExtractValue(valPart)

				// Handle heredoc — only when the raw RHS (valPart) starts with
				// `<<`. If valPart begins with a quote, the `<<` belongs to the
				// string literal's content and is NOT a heredoc marker.
				if strings.HasPrefix(valPart, "<<") && strings.HasPrefix(val, "<<") {
					marker := strings.TrimPrefix(val, "<<")
					marker = strings.TrimPrefix(marker, "-")
					marker = strings.TrimSpace(marker)
					marker = strings.Trim(marker, `"`) // handle <<"EOF" syntax
					// Read until closing marker.
					var heredocLines []string
					for lineIdx < len(lines) {
						hline := lines[lineIdx]
						lineIdx++
						if strings.TrimSpace(hline) == marker {
							break
						}
						heredocLines = append(heredocLines, hline)
					}
					val = strings.Join(heredocLines, "\n")
				}

				fullKey := key
				if prefix != "" {
					fullKey = prefix + "." + key
				}
				*out = append(*out, KeyValue{
					Key:   fullKey,
					Value: val,
					Line:  lineNum,
				})
				continue
			}
		}

		// Block definition: "block_type [label...] {"
		if strings.HasSuffix(line, "{") {
			blockPrefix := hclBlockPrefix(line, prefix)

			// Parse block body recursively.
			consumed := parseHCLLines(lines[lineIdx:], blockPrefix, out, depth+1, baseLineOffset+lineIdx)
			lineIdx += consumed
			continue
		}

		// Block definition split across lines: "block_type label" then next line "{"
		// Peek ahead for opening brace.
		if lineIdx < len(lines) && strings.TrimSpace(lines[lineIdx]) == "{" {
			blockPrefix := hclBlockPrefix(line+" {", prefix)
			lineIdx++ // consume the "{"
			consumed := parseHCLLines(lines[lineIdx:], blockPrefix, out, depth+1, baseLineOffset+lineIdx)
			lineIdx += consumed
			continue
		}
	}
	return lineIdx
}

// hclBlockPrefix extracts the block type and labels from a line ending with "{".
// Returns the dotted prefix for keys inside the block.
func hclBlockPrefix(line, currentPrefix string) string {
	// Remove trailing "{" and whitespace.
	line = strings.TrimSuffix(strings.TrimSpace(line), "{")
	line = strings.TrimSpace(line)

	// Tokenize: block_type "label1" "label2"
	parts := hclTokenize(line)
	if len(parts) == 0 {
		return currentPrefix
	}

	// Build dotted prefix from all tokens.
	blockPath := strings.Join(parts, ".")
	if currentPrefix != "" {
		return currentPrefix + "." + blockPath
	}
	return blockPath
}

// hclTokenize splits a block header into type and label tokens.
// Quoted strings have their quotes removed.
func hclTokenize(s string) []string {
	var tokens []string
	s = strings.TrimSpace(s)
	for len(s) > 0 {
		if s[0] == '"' {
			// Quoted token — find closing quote.
			end := strings.IndexByte(s[1:], '"')
			if end >= 0 {
				tokens = append(tokens, s[1:end+1])
				s = strings.TrimSpace(s[end+2:])
			} else {
				tokens = append(tokens, s[1:])
				break
			}
		} else {
			// Unquoted token — split on whitespace.
			end := strings.IndexAny(s, " \t")
			if end >= 0 {
				tokens = append(tokens, s[:end])
				s = strings.TrimSpace(s[end:])
			} else {
				tokens = append(tokens, s)
				break
			}
		}
	}
	return tokens
}

// indexOutsideHCLStrings returns the byte index of substr in s, skipping any
// occurrence that falls inside a double-quoted HCL string literal on the same
// line. Returns -1 if substr does not occur outside string literals.
//
// Backslash escapes `\"` inside "..." are honoured so a value like
// "contains \"quote\"" is correctly treated as one string. HCL does not use
// single-quoted strings, so apostrophes are not treated as quote delimiters.
func indexOutsideHCLStrings(s, substr string) int {
	if substr == "" {
		return 0
	}
	inString := false
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '"' {
			// Count preceding backslashes to honour `\"` escape.
			bs := 0
			for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				inString = !inString
			}
			i++
			continue
		}
		if !inString && i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return i
		}
		i++
	}
	return -1
}

// hclExtractValue extracts a value from an HCL assignment RHS, handling:
// - Quoted strings (with escape sequences)
// - Bare values (numbers, booleans, references)
// - Trailing inline comments
func hclExtractValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return ""
	}

	// Quoted string.
	if s[0] == '"' {
		end := 1
		for end < len(s) {
			if s[end] == '\\' {
				end += 2
				// A trailing backslash (or backslash + EOF) means the string
				// is unterminated. Break out so we return best-effort content
				// rather than indexing past the end of the slice.
				if end >= len(s) {
					break
				}
				continue
			}
			if s[end] == '"' {
				return s[1:end]
			}
			end++
		}
		// No closing quote — best effort.
		return s[1:]
	}

	// Unquoted value — strip trailing comments.
	if ci := strings.Index(s, " #"); ci >= 0 {
		s = strings.TrimSpace(s[:ci])
	}
	if ci := strings.Index(s, " //"); ci >= 0 {
		s = strings.TrimSpace(s[:ci])
	}
	return s
}

// --- helpers ---

// splitLines splits data on \n, handling \r\n.
func splitLines(data []byte) []string {
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

// splitKeyValue splits a "key=value" or "key: value" line at the first = or :.
// Returns false if no separator is found.
func splitKeyValue(line string) (key, value string, ok bool) {
	// Find the first = or :
	eqIdx := strings.IndexByte(line, '=')
	colIdx := strings.IndexByte(line, ':')

	switch {
	case eqIdx == -1 && colIdx == -1:
		return "", "", false
	case eqIdx == -1:
		return line[:colIdx], line[colIdx+1:], true
	case colIdx == -1:
		return line[:eqIdx], line[eqIdx+1:], true
	default:
		// Use whichever separator comes first.
		if eqIdx < colIdx {
			return line[:eqIdx], line[eqIdx+1:], true
		}
		return line[:colIdx], line[colIdx+1:], true
	}
}

// stripQuotes removes a matched pair of surrounding single or double quotes.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
