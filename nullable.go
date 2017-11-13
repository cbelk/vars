package vars

import (
	"database/sql"
	"encoding/json"
)

// VarsNullString holds a sql.NullString. Needed for marshaling/unmarshaling.
type VarsNullString struct {
	sql.NullString
}

// MarshalJSON will marshal the string if it is valid.
func (v VarsNullString) MarshalJSON() ([]byte, error) {
	if v.Valid {
		return json.Marshal(v.String)
	} else {
		return json.Marshal(nil)
	}
}

// UnmarshalJSON will unmarshal the string if it is valid and set valid to true, otherwise valid is set to false.
func (v *VarsNullString) UnmarshalJSON(data []byte) error {
	// Unmarshalling into a pointer will let us detect null
	var x *string
	if err := json.Unmarshal(data, &x); err != nil {
		return err
	}
	if x != nil {
		v.Valid = true
		v.String = *x
	} else {
		v.Valid = false
	}
	return nil
}

// VarsNullBool holds a sql.NullBool. Needed for marshaling/unmarshaling.
type VarsNullBool struct {
	sql.NullBool
}

// MarshalJSON will marshal the string if it is valid.
func (v VarsNullBool) MarshalJSON() ([]byte, error) {
	if v.Valid {
		return json.Marshal(v.Bool)
	} else {
		return json.Marshal(nil)
	}
}

// UnmarshalJSON will unmarshal the string if it is valid and set valid to true, otherwise valid is set to false.
func (v *VarsNullBool) UnmarshalJSON(data []byte) error {
	// Unmarshalling into a pointer will let us detect null
	var x *bool
	if err := json.Unmarshal(data, &x); err != nil {
		return err
	}
	if x != nil {
		v.Valid = true
		v.Bool = *x
	} else {
		v.Valid = false
	}
	return nil
}
