package keycloakb

import (
	"encoding/json"
	"fmt"
)

// DynamicRepresentation defines an interface that any struct with dynamic JSON fields must implement.
//
// It allows known fields to be handled via normal struct tags, and unknown fields to be stored in a dynamic map.
// - GetDynamicFields returns the currently stored dynamic fields.
// - SetDynamicFields updates the dynamic field map after JSON parsing.
type DynamicRepresentation interface {
	GetDynamicFields() map[string]any
	SetDynamicFields(dynamicFields map[string]any)
}

// DynamicallyMarshalJSON marshals both the known and dynamic fields of a struct implementing DynamicRepresentation.
//
// This function:
// 1. Marshals to the underlying alias struct.
// 2. Parses the resulting JSON into a map[string]any.
// 3. Injects the dynamic fields into the map.
// 4. Re-encodes the combined map back to JSON.
//
// The input must be an alias type that implements DynamicRepresentation (see important note below).
func DynamicallyMarshalJSON(toBeMarshalled DynamicRepresentation) ([]byte, error) {
	result := map[string]any{}

	// Marshal the known fields
	resultJSON, err := json.Marshal(toBeMarshalled)
	if err != nil {
		return nil, err
	}
	// Convert known field JSON back into a map
	err = json.Unmarshal(resultJSON, &result)
	if err != nil {
		return nil, err
	}

	// Inject dynamic fields
	for k, v := range toBeMarshalled.GetDynamicFields() {
		result[k] = v
	}

	// Final JSON encoding with both known + dynamic fields
	return json.Marshal(result)
}

// DynamicallyUnmarshalJSON unmarshals JSON into known and dynamic fields.
//
// Steps:
// 1. Decodes all fields into the provided alias type (must implement DynamicRepresentation).
// 2. Decodes the original JSON into a map to identify unknown fields.
// 3. Identifies known keys by re-marshalling the alias and unmarshalling it back into a map.
// 4. Removes known keys from the raw JSON map.
// 5. Remaining fields are treated as dynamic and stored via SetDynamicFields.
//
// IMPORTANT: The `dynamic` parameter MUST be a pointer to an alias of the underlying struct,
// not the struct itself. This avoids recursion when MarshalJSON/UnmarshalJSON is overridden.
func DynamicallyUnmarshalJSON(data []byte, dynamic DynamicRepresentation) error {
	// Step 1: Unmarshal known fields into alias
	if err := json.Unmarshal(data, &dynamic); err != nil {
		return err
	}

	// Step 2: Unmarshal entire input into raw map
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Step 3:  Identifies known keys
	knownJSON, err := json.Marshal(dynamic)
	if err != nil {
		return fmt.Errorf("re-marshal alias: %w", err)
	}
	var knownMap map[string]any
	if err := json.Unmarshal(knownJSON, &knownMap); err != nil {
		return fmt.Errorf("unmarshal known fields: %w", err)
	}

	// Step 4: Remove known keys from rawMap
	for key := range knownMap {
		delete(rawMap, key)
	}

	// Step 5: What's left in rawMap is dynamic
	dynamicFields := make(map[string]any, len(rawMap))
	for key, raw := range rawMap {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("decoding dynamic field %q: %w", key, err)
		}
		if v != nil {
			dynamicFields[key] = v
		}
	}
	dynamic.SetDynamicFields(dynamicFields)

	return nil
}
