package saml

import (
	"encoding/base64"
	"encoding/xml"
)

type SamlID interface{ NameID | BaseID | EncryptedID }

type Base64String string

// EncodeBase64String encodes either a string or []byte to a Base64String.
// If v is not a valid type, s will be empty.
func EncodeBase64String(v any) (s Base64String) {
	s.Encode(v)
	return
}

// Decode decodes the Base64String as a string
func (s Base64String) Decode() (string, error) {
	b, err := s.DecodeBytes()
	return string(b), err
}

// Decode decodes the Base64String as []byte
func (s Base64String) DecodeBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(s))
}

// Encode encodes either a string or []byte to a Base64String.
// If v is not a valid type, s will be empty.
func (s *Base64String) Encode(v any) {
	switch v := v.(type) {
	case string:
		*s = Base64String(base64.StdEncoding.EncodeToString([]byte(v)))
	case []byte:
		*s = Base64String(base64.StdEncoding.EncodeToString(v))
	default:
		*s = ""
	}
}

// Parse casts the given string as Base64String and checks that it is valid
func (s *Base64String) Parse(v string) error {
	*s = Base64String(v)
	return s.Validate()
}

// Validate checks to see if the given Base64String can be decoded
func (s Base64String) Validate() error {
	_, err := s.DecodeBytes()
	return err
}

type URI string

// Parse casts the given string as URI and checks that it is valid
func (u *URI) Parse(v string) error {
	*u = URI(v)
	return u.Validate()
}

// Validate checks to see if the given URI can be decoded
func (s URI) Validate() error {
	return nil // TODO implement URI Validation
}

type Node struct {
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
	Children   []Node     `xml:",any,omitempty"`
	Value      string     `xml:",chardata"`
}
