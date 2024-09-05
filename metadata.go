package saml

import (
	"encoding/xml"
	"time"

	"github.com/jason-jackson/xmlsecurity"
)

// The complex type Endpoint describes a SAML protocol binding endpoint at which a SAML entity can
// be sent protocol messages. Various protocol or profile-specific metadata elements are bound to this type.
//
// In most contexts, elements of this type appear in unbounded sequences in the schema. This is to permit a
// protocol or profile to be offered by an entity at multiple endpoints, usually with different protocol bindings,
// allowing the metadata consumer to choose an appropriate endpoint for its needs. Multiple endpoints might
// also offer "client-side" load-balancing or failover, particular in the case of a synchronous protocol binding.
//
// This element also permits the use of arbitrary elements and attributes defined in a non-SAML namespace.
// Any such content MUST be namespace-qualified.
type Endpoint struct {
	// A required attribute that specifies the SAML binding supported by the endpoint. Each binding
	// is assigned a URI to identify it.
	Binding Binding `xml:",attr"`

	// A required URI attribute that specifies the location of the endpoint. The allowable syntax of
	// this URI depends on the protocol binding.
	Location string `xml:",attr"`

	// Optionally specifies a different location to which response messages sent as part of the
	// protocol or profile should be sent. The allowable syntax of this URI depends on the protocol
	// binding.
	//
	// The ResponseLocation attribute is used to enable different endpoints to be specified for
	// receiving request and response messages associated with a protocol or profile, not as a means
	// of load-balancing or redundancy (multiple elements of this type can be included for this
	// purpose). When a role contains an element of this type pertaining to a protocol or profile
	// for which only a single type of message (request or response) is applicable, then the
	// ResponseLocation attribute is unused.
	ResponseLocation string `xml:",attr,omitempty"`

	Attributes []xml.Attr `xml:",any,attr,omitempty"`
	Children   []Node     `xml:",any,omitempty"`
}
type Endpoints []Endpoint

// Indexed converts the Endpoints into a slice of IndexedEndpoints
func (e Endpoints) Indexed() []IndexedEndpoint {
	indexed := make([]IndexedEndpoint, len(e))
	for i, ep := range e {
		indexed[i] = IndexedEndpoint{
			Endpoint: ep,
			Index:    i,
		}
	}
	return indexed
}

// The complex type IndexedEndpoint extends Endpoint with a pair of attributes to permit the
// indexing of otherwise identical endpoints so that they can be referenced by protocol messages.
//
// In any such sequence of like endpoints based on this type, the default endpoint is the first such endpoint
// with the isDefault attribute set to true. If no such endpoints exist, the default endpoint is the first such
// endpoint without the isDefault attribute set to false. If no such endpoints exist, the default endpoint is
// the first element in the sequence.
type IndexedEndpoint struct {
	// A required attribute that assigns a unique integer value to the endpoint so that it can be
	// referenced in a protocol message. The index value need only be unique within a collection of
	// like elements contained within the same parent element (i.e., they need not be unique across
	// the entire instance).
	Index int `xml:",attr"`

	// An optional boolean attribute used to designate the default endpoint among an indexed set. If
	// omitted, the value is assumed to be false.
	IsDefault *bool `xml:",attr,omitempty"`

	Endpoint
}

// The localizedName complex type extends a string-valued element with a standard XML language attribute.
type LocalizedName struct {
	Lang  string `xml:"xml:lang,attr"`
	Value string `xml:",chardata"`
}

// The localizedURI complex type extends a URI-valued element with a standard XML language attribute.
type LocalizedURI struct {
	Lang  string `xml:"xml:lang,attr"`
	Value URI    `xml:",chardata"`
}

// The <EntitiesDescriptor> element contains the metadata for an optionally named group of SAML entities.
//
// When used as the root element of a metadata instance, this element MUST contain either a validUntil or
// cacheDuration attribute. It is RECOMMENDED that only the root element of a metadata instance contain
// either attribute.
type EntitiesDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`

	// A document-unique identifier for the element, typically used as a reference point when
	// signing.
	ID string `xml:",attr,omitempty"`

	// Optional attribute indicates the expiration time of the metadata contained in the element and
	// any contained elements.
	ValidUntil *time.Time `xml:"validUntil,attr,omitempty"`

	// Optional attribute indicates the maximum length of time a consumer should cache the metadata
	// contained in the element and any contained elements.
	CacheDuration *time.Duration `xml:"cacheDuration,attr,omitempty"`

	// A string name that identifies a group of SAML entities in the context of some deployment.
	Name string `xml:",attr,omitempty"`

	// An XML signature that authenticates the containing element and its contents, as described in
	// Section 3.
	Signature *xmlsecurity.Signature `xml:",omitempty"`

	// This contains optional metadata extensions that are agreed upon between a metadata publisher
	// and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`

	// Contains the metadata for a nested group of additional metadata.
	EntitiesDescriptor *EntitiesDescriptor `xml:"EntitiesDescriptor,omitempty"`

	// Contains the metadata for one or more SAML entities.
	EntityDescriptors []EntityDescriptor `xml:"EntityDescriptor,omitempty"`
}

/*
The <EntityDescriptor> element specifies metadata for a single SAML entity. A single entity may act in
many different roles in the support of multiple profiles. This specification directly supports the
following concrete roles as well as the abstract <RoleDescriptor> element for extensibility (see
subsequent sections for more details):

  - SSO Identity Provider
  - SSO Service Provider
  - Authentication Authority
  - Attribute Authority
  - Policy Decision Point
  - Affiliation

When used as the root element of a metadata instance, this element MUST contain either a validUntil
or cacheDuration attribute. It is RECOMMENDED that only the root element of a metadata instance
contain either attribute.

It is RECOMMENDED that if multiple role descriptor elements of the same type appear, that they do not
share overlapping protocolSupportEnumeration values. Selecting from among multiple role descriptor
elements of the same type that do share a protocolSupportEnumeration value is undefined within this
specification, but MAY be defined by metadata profiles, possibly through the use of other distinguishing
extension attributes.
*/
type EntityDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`

	// Specifies the unique identifier of the SAML entity whose metadata is described by the
	// element's contents.
	EntityID string `xml:"entityID,attr"`

	// A document-unique identifier for the element, typically used as a reference point when signing.
	ID string `xml:",attr,omitempty"`

	// Optional attribute indicates the expiration time of the metadata contained in the element and
	// any contained elements.
	ValidUntil *time.Time `xml:"validUntil,attr,omitempty"`

	// Optional attribute indicates the maximum length of time a consumer should cache the metadata
	// contained in the element and any contained elements.
	CacheDuration *time.Duration `xml:"cacheDuration,attr,omitempty"`

	// An XML signature that authenticates the containing element and its contents, as described in
	// Section 3.
	Signature *xmlsecurity.Signature `xml:",omitempty"`

	// This contains optional metadata extensions that are agreed upon between a metadata publisher
	// and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	RoleDescriptors RoleDescriptors `xml:"RoleDescriptor,omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	IdpSSODescriptors IdPSSODescriptors `xml:"IDPSSODescriptor,omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	SpSSODescriptors SPSSODescriptors `xml:"SPSSODescriptor,omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	AuthnAuthorityDescriptors AuthnAuthorityDescriptors `xml:"AuthnAuthorityDescriptor,omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	AttributeAuthorityDescriptors AttributeAuthorityDescriptors `xml:"AttributeAuthorityDescriptor,omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	PDPDescriptors PDPDescriptors `xml:"PDPDescriptor,omitempty"`

	// The primary content of the element is either a sequence of one or more role descriptor
	// elements, or a specialized descriptor that defines an affiliation.
	AffiliationDescriptor *AffiliationDescriptor `xml:",omitempty"`

	// Optional element identifying the organization responsible for the SAML entity described by
	// the element.
	Organization *Organization `xml:",omitempty"`

	// Optional sequence of elements identifying various kinds of contact personnel.
	ContactPersons []ContactPerson `xml:"ContactPerson,omitempty"`

	// Optional sequence of namespace-qualified locations where additional metadata exists for the
	// SAML entity. This may include metadata in alternate formats or describing adherence to other
	// non-SAML specifications.
	AdditionalMetadataLocations []AdditionalMetadataLocation `xml:"AdditionalMetadataLocation,omitempty"`

	// Arbitrary namespace-qualified attributes from non-SAML-defined namespaces may also be included.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
}

// The <Organization> element specifies basic information about an organization responsible for a
// SAML entity or role. The use of this element is always optional. Its content is informative in
// nature and does not directly map to any core SAML elements or attributes.
type Organization struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata Organization"`

	// This contains optional metadata extensions that are agreed upon between a metadata publisher
	// and consumer. Extensions MUST NOT include global (non-namespace-qualified) elements or
	// elements qualified by a SAML-defined namespace within this element.
	Extensions *Extensions `xml:",omitempty"`

	// One or more language-qualified names that may or may not be suitable for human consumption.
	Names []LocalizedName `xml:"OrganizationName"`

	// One or more language-qualified names that are suitable for human consumption.
	DisplayNames []LocalizedName `xml:"OrganizationDisplayName"`

	// One or more language-qualified URIs that specify a location to which to direct a user for
	// additional information. Note that the language qualifier refers to the content of the
	// material at the specified location.
	Urls []LocalizedURI `xml:"OrganizationURL"`

	// Arbitrary namespace-qualified attributes from non-SAML-defined namespaces may also be included.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
}

type OrganizationName struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationName"`
	LocalizedName
}

type OrganizationDisplayName struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationDisplayName"`
	LocalizedName
}

type OrganizationURL struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationURL"`
	LocalizedName
}

// The <ContactPerson> element specifies basic contact information about a person responsible in
// some capacity for a SAML entity or role. The use of this element is always optional. Its content
// is informative in nature and does not directly map to any core SAML elements or attributes.
type ContactPerson struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata ContactPerson"`

	// Specifies the type of contact using the ContactTypeType enumeration.
	// The possible values are technical, support, administrative, billing, and other.
	ContactType ContactType `xml:"contactType,attr,omitempty"`

	// This contains optional metadata extensions that are agreed upon between a metadata publisher
	// and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`

	// Optional string element that specifies the name of the company for the contact person.
	Company string `xml:",omitempty"`

	// Optional string element that specifies the given (first) name of the contact person.
	GivenName string `xml:",omitempty"`

	// Optional string element that specifies the surname of the contact person.
	Surname string `xml:"SurName,omitempty"`

	// Zero or more elements containing mailto: URIs representing e-mail addresses belonging to the
	// contact person.
	EmailAddresses []URI `xml:"EmailAddress,omitempty"`

	// Zero or more string elements specifying a telephone number of the contact person.
	PhoneNumbers []string `xml:"TelephoneNumber,omitempty"`

	// Arbitrary namespace-qualified attributes from non-SAML-defined namespaces may also be included.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
}

// The <AdditionalMetadataLocation> element is a namespace-qualified URI that specifies where
// additional XML-based metadata may exist for a SAML entity. Its AdditionalMetadataLocationType
// complex type extends the anyURI type with a namespace attribute (also of type anyURI). This required
// attribute MUST contain the XML namespace of the root element of the instance document found at the
// specified location.
type AdditionalMetadataLocation struct {
	XMLName   xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AdditionalMetadataLocation"`
	Namespace URI      `xml:"namespace,attr"`
	Value     URI      `xml:",chardata"`
}

// The <RoleDescriptor> element is an abstract extension point that contains common descriptive
// information intended to provide processing commonality across different roles. New roles can be defined
// by extending its abstract RoleDescriptorType complex type
type RoleDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata RoleDescriptor"`

	// A document-unique identifier for the element, typically used as a reference point when signing.
	ID string `xml:",attr,omitempty"`

	// Optional attribute indicates the expiration time of the metadata contained in the element and
	// any contained elements.
	ValidUntil *time.Time `xml:"validUntil,attr,omitempty"`

	// Optional attribute indicates the maximum length of time a consumer should cache the metadata
	// contained in the element and any contained elements.
	CacheDuration *time.Duration `xml:"cacheDuration,attr,omitempty"`

	// A whitespace-delimited set of URIs that identify the set of protocol specifications supported
	// by the role element. For SAML V2.0 entities, this set MUST include the SAML protocol
	// namespace URI, urn:oasis:names:tc:SAML:2.0:protocol. Note that future SAML specifications
	// might share the same namespace URI, but SHOULD provide alternate "protocol support"
	// identifiers to ensure discrimination when necessary.
	ProtocolSupportEnumeration Protocol `xml:"protocolSupportEnumeration,attr,omitempty"`

	// Optional URI attribute that specifies a location to direct a user for problem resolution and
	// additional support related to this role.
	ErrorUrl string `xml:"errorURL,attr,omitempty"`

	// An XML signature that authenticates the containing element and its contents, as described in
	// Section 3.
	Signature *xmlsecurity.Signature `xml:",omitempty"`

	// This contains optional metadata extensions that are agreed upon between a metadata publisher
	// and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`

	// Optional sequence of elements that provides information about the cryptographic keys that the
	// entity uses when acting in this role.
	KeyDescriptors []KeyDescriptor `xml:"KeyDescriptor,omitempty"`

	// Optional element specifies the organization associated with this role. Identical to the
	// element used within the <EntityDescriptor> element.
	Organization *Organization `xml:",omitempty"`

	// Optional sequence of elements specifying contacts associated with this role. Identical to the
	// element used within the <EntityDescriptor> element.
	ContactPersons []ContactPerson `xml:"ContactPerson,omitempty"`

	// Arbitrary namespace-qualified attributes from non-SAML-defined namespaces may also be included.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
}
type RoleDescriptors []RoleDescriptor

// The <KeyDescriptor> element provides information about the cryptographic key(s) that an entity
// uses to sign data or receive encrypted keys, along with additional cryptographic details.
type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`

	// Optional attribute specifying the purpose of the key being described. Values are drawn from
	// the KeyType enumeration, and consist of the values encryption and signing.
	Use KeyType `xml:"use,attr,omitempty"`

	// Optional element that directly or indirectly identifies a key. See [XMLSig] for additional
	// details on the use of this element.
	KeyInfo xmlsecurity.KeyInfo `xml:"KeyInfo"`

	// Optional element specifying an algorithm and algorithm-specific settings supported by the
	// entity. The exact content varies based on the algorithm supported. See [XMLEnc] for the
	// definition of this element's xenc:EncryptionMethodType complex type.
	EncryptionMethods []xmlsecurity.EncryptionMethod `xml:"EncryptionMethod"`
}

// The SSODescriptorType abstract type is a common base type for the concrete types
// SPSSODescriptorType and IDPSSODescriptorType, described in subsequent sections. It extends
// RoleDescriptorType with elements reflecting profiles common to both identity providers and
// service providers that support SSO
type SSODescriptor struct {
	// Zero or more elements of type IndexedEndpoint that describe indexed endpoints that
	// support the Artifact Resolution profile defined in [SAMLProf]. The ResponseLocation
	// attribute MUST be omitted.
	ArtifactResolutionServices []IndexedEndpoint `xml:"ArtifactResolutionService,omitempty"`

	// Zero or more elements of type Endpoint that describe endpoints that support the Single
	// Logout profiles defined in [SAMLProf].
	SingleLogoutServices Endpoints `xml:"SingleLogoutService,omitempty"`

	// Zero or more elements of type Endpoint that describe endpoints that support the Name
	// Identifier Management profiles defined in [SAMLProf].
	ManageNameIDServices Endpoints `xml:"ManageNameIDService,omitempty"`

	// Zero or more elements of type anyURI that enumerate the name identifier formats supported by
	// this system entity acting in this role. See Section 8.3 of [SAMLCore] for some possible
	// values for this element.
	NameIDFormats []NameIdFormat `xml:"NameIDFormat,omitempty"` // TODO custom type?

	RoleDescriptor
}

func (d SSODescriptor) GetArtifactResolutionService(binding ...Binding) *IndexedEndpoint {
	for _, e := range d.ArtifactResolutionServices {
		if (len(binding) == 0 || contains(binding, e.Binding)) && e.Location != "" {
			return &e
		}
	}
	return nil
}

func (d SSODescriptor) GetManageNameIDService(binding ...Binding) *Endpoint {
	for _, e := range d.ManageNameIDServices {
		if (len(binding) == 0 || contains(binding, e.Binding)) && e.Location != "" {
			return &e
		}
	}
	return nil
}

func (d SSODescriptor) GetSLOService(binding ...Binding) *Endpoint {
	for _, e := range d.SingleLogoutServices {
		if (len(binding) == 0 || contains(binding, e.Binding)) && e.Location != "" {
			return &e
		}
	}
	return nil
}

// The <IDPSSODescriptor> element extends SSODescriptorType with content reflecting profiles
// specific to identity providers supporting SSO.
type IdPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`

	// Optional attribute that indicates a requirement for the <samlp:AuthnRequest> messages
	// received by this identity provider to be signed. If omitted, the value is assumed as false.
	WantAuthnRequestsSigned *bool `xml:",attr,omitempty"`

	// One or more elements of type Endpoint that describe endpoints that support the profiles
	// of the Authentication Request protocol defined in [SAMLProf]. All identity providers support
	// at least one such endpoint, by definition. The ResponseLocation attribute MUST be omitted.
	SingleSignOnServices Endpoints `xml:"SingleSignOnService"`

	// Zero or more elements of type Endpoint that describe endpoints that support the Name
	// Identifier Mapping profile defined in [SAMLProf]. The ResponseLocation attribute MUST be
	// omitted.
	NameIDMappingServices Endpoints `xml:"NameIDMappingService"`

	// Zero or more elements of type Endpoint that describe endpoints that support the profile
	// of the Assertion Request protocol defined in [SAMLProf] or the special URI binding for
	// assertion requests defined in [SAMLBind].
	AssertionIDRequestServices Endpoints `xml:"AssertionIDRequestService,omitempty"`

	// Zero or more elements of type anyURI that enumerate the attribute profiles supported by this
	// identity provider. See [SAMLProf] for some possible values for this element.
	AttributeProfiles []string `xml:"AttributeProfile"`

	// Zero or more elements that identify the SAML attributes supported by the identity provider.
	// Specific values MAY optionally be included, indicating that only certain values permitted by
	// the attribute's definition are supported. In this context, "support" for an attribute means
	// that the identity provider has the capability to include it when delivering assertions during
	// single sign-on.
	Attributes []Attribute `xml:"Attribute"`

	SSODescriptor
}
type IdPSSODescriptors []IdPSSODescriptor

func (d IdPSSODescriptor) GetSSOService(binding ...Binding) *Endpoint {
	for _, e := range d.SingleSignOnServices {
		if (len(binding) == 0 || contains(binding, e.Binding)) && e.Location != "" {
			return &e
		}
	}
	return nil
}

func (d IdPSSODescriptors) Get(protocol Protocol) *IdPSSODescriptor {
	for _, v := range d {
		if v.ProtocolSupportEnumeration == protocol {
			return &v
		}
	}
	return nil
}

// The <SPSSODescriptor> element extends SSODescriptorType with content reflecting profiles
// specific to service providers.
type SPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`

	// Optional attribute that indicates whether the <samlp:AuthnRequest> messages sent by this
	// service provider will be signed. If omitted, the value is assumed to be false.
	AuthnRequestsSigned bool `xml:"AuthnRequestsSigned,attr"`

	// Optional attribute that indicates a requirement for the <saml:Assertion> elements received by
	// this service provider to be signed. If omitted, the value is assumed to be false. This
	// requirement is in addition to any requirement for signing derived from the use of a
	// particular profile/binding combination.
	WantAssertionsSigned bool `xml:"WantAssertionsSigned,attr"`

	// One or more elements that describe indexed endpoints that support the profiles of the
	// Authentication Request protocol defined in [SAMLProf]. All service providers support at least
	// one such endpoint, by definition.
	AssertionConsumerServices []IndexedEndpoint `xml:"AssertionConsumerService"`

	// Zero or more elements that describe an application or service provided by the service
	// provider that requires or desires the use of SAML attributes.
	//
	// At most one <AttributeConsumingService> element can have the attribute isDefault set to true.
	// It is permissible for none of the included elements to contain an isDefault attribute set to
	// true.
	AttributeConsumingServices []AttributeConsumingService `xml:"AttributeConsumingService"`

	SSODescriptor
}
type SPSSODescriptors []SPSSODescriptor

func (d SPSSODescriptor) GetACSService(binding ...Binding) (acs *IndexedEndpoint) {
	for _, e := range d.AssertionConsumerServices {
		if (len(binding) > 0 && !contains(binding, e.Binding)) || e.Location == "" {
			continue
		}

		// if acs is not set, set it, otherwise check if isDefault is set and use it if isDefault == true
		if acs == nil || (e.IsDefault != nil && *e.IsDefault) {
			acs = &e
		}
	}

	return
}

func (d SPSSODescriptors) Get(protocol Protocol) *SPSSODescriptor {
	for _, v := range d {
		if v.ProtocolSupportEnumeration == protocol {
			return &v
		}
	}
	return nil
}

// The <AttributeConsumingService> element defines a particular service offered by the
// service provider in terms of the attributes the service requires or desires.
type AttributeConsumingService struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AttributeConsumingService"`

	// A required attribute that assigns a unique integer value to the element so that it can be
	// referenced in a protocol message.
	Index int `xml:"index,attr"`

	// Identifies the default service supported by the service provider. Useful if the specific
	// service is not otherwise indicated by application context. If omitted, the value is assumed
	// to be false.
	IsDefault *bool `xml:"isDefault,attr,omitempty"`

	// One or more language-qualified names for the service.
	ServiceNames []LocalizedName `xml:"ServiceName"`

	// Zero or more language-qualified strings that describe the service.
	ServiceDescriptions []LocalizedName `xml:"ServiceDescription,omitempty"`

	// One or more elements specifying attributes required or desired by this service.
	RequestedAttributes []RequestedAttribute `xml:"RequestedAttribute"`
}

// The <RequestedAttribute> element specifies a service provider's interest in a specific
// SAML attribute, optionally including specific values.
//
// If specific <saml:AttributeValue> elements are included, then only matching values are
// relevant to the service. See [SAMLCore] for more information on attribute value matching.
type RequestedAttribute struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata RequestedAttribute"`

	// Optional XML attribute indicates if the service requires the corresponding SAML attribute in
	// order to function at all (as opposed to merely finding an attribute useful or desirable).
	IsRequired *bool `xml:"isRequired,attr,omitempty"`

	Attribute
}

// The <AuthnAuthorityDescriptor> element extends RoleDescriptorType with content reflecting profiles
// specific to authentication authorities, SAML authorities that respond to <samlp:AuthnQuery> messages.
type AuthnAuthorityDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AuthnAuthorityDescriptor"`

	// One or more elements of type Endpoint that describe endpoints that support the profile of
	// the Authentication Query protocol defined in [SAMLProf]. All authentication authorities
	// support at least one such endpoint, by definition.
	AuthnQueryServices Endpoints `xml:"AuthnQueryService"`

	// Zero or more elements of type Endpoint that describe endpoints that support the profile of
	// the Assertion Request protocol defined in [SAMLProf] or the special URI binding for
	// assertion requests defined in [SAMLBind].
	AssertionIDRequestServices Endpoints `xml:"AssertionIDRequestService,omitempty"`

	// Zero or more elements of type anyURI that enumerate the name identifier formats supported by
	// this authority. See Section 8.3 of [SAMLCore] for some possible values for this element.
	NameIDFormats []NameIdFormat `xml:"NameIDFormat,omitempty"`

	RoleDescriptor
}
type AuthnAuthorityDescriptors []AuthnAuthorityDescriptor

func (d AuthnAuthorityDescriptors) Get(protocol Protocol) *AuthnAuthorityDescriptor {
	for _, v := range d {
		if v.ProtocolSupportEnumeration == protocol {
			return &v
		}
	}
	return nil
}

// The <PDPDescriptor> element extends RoleDescriptorType with content reflecting profiles specific
// to policy decision points, SAML authorities that respond to <samlp:AuthzDecisionQuery> messages.
type PDPDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata PDPDescriptor"`

	// One or more elements of type Endpoint that describe endpoints that support the profile of
	// the Authorization Decision Query protocol defined in [SAMLProf]. All policy decision points
	// support at least one such endpoint, by definition.
	AuthzServices Endpoints `xml:"AuthzService"`

	// Zero or more elements of type Endpoint that describe endpoints that support the profile of
	// the Assertion Request protocol defined in [SAMLProf] or the special URI binding for
	// assertion requests defined in [SAMLBind].
	AssertionIDRequestServices Endpoints `xml:"AssertionIDRequestService,omitempty"`

	// Zero or more elements of type anyURI that enumerate the name identifier formats supported by
	// this authority. See Section 8.3 of [SAMLCore] for some possible values for this element.
	NameIDFormats []NameIdFormat `xml:"NameIDFormat,omitempty"`

	RoleDescriptor
}
type PDPDescriptors []PDPDescriptor

func (d PDPDescriptors) Get(protocol Protocol) *PDPDescriptor {
	for _, v := range d {
		if v.ProtocolSupportEnumeration == protocol {
			return &v
		}
	}
	return nil
}

// The <AttributeAuthorityDescriptor> element extends RoleDescriptorType with content reflecting profiles
// specific to attribute authorities, SAML authorities that respond to <samlp:AttributeQuery> messages.
type AttributeAuthorityDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AttributeAuthorityDescriptor"`

	// One or more elements of type Endpoint that describe endpoints that support the profile of
	// the Attribute Query protocol defined in [SAMLProf]. All attribute authorities support at
	// least one such endpoint, by definition.
	AttributeService Endpoints `xml:"AttributeService"`

	// Zero or more elements of type Endpoint that describe endpoints that support the profile of
	// the Assertion Request protocol defined in [SAMLProf] or the special URI binding for
	// assertion requests defined in [SAMLBind].
	AssertionIDRequestServices Endpoints `xml:"AssertionIDRequestService,omitempty"`

	// Zero or more elements of type anyURI that enumerate the name identifier formats supported by
	// this authority. See Section 8.3 of [SAMLCore] for some possible values for this element.
	NameIDFormats []NameIdFormat `xml:"NameIDFormat,omitempty"`

	// Zero or more elements of type anyURI that enumerate the attribute profiles supported by this
	// authority. See [SAMLProf] for some possible values for this element.
	AttributeProfiles []string `xml:"AttributeProfile,omitempty"`

	// Zero or more elements that identify the SAML attributes supported by the authority. Specific
	// values MAY optionally be included, indicating that only certain values permitted by the
	// attribute's definition are supported.
	Attributes []Attribute `xml:"Attribute,omitempty"`

	RoleDescriptor
}
type AttributeAuthorityDescriptors []AttributeAuthorityDescriptor

func (d AttributeAuthorityDescriptors) Get(protocol Protocol) *AttributeAuthorityDescriptor {
	for _, v := range d {
		if v.ProtocolSupportEnumeration == protocol {
			return &v
		}
	}
	return nil
}

// The <AffiliationDescriptor> element is an alternative to the sequence of role descriptors
// described in Section 2.4 that is used when an <EntityDescriptor> describes an affiliation
// of SAML entities (typically service providers) rather than a single entity.
// The <AffiliationDescriptor> element provides a summary of the individual entities that make
// up the affiliation along with general information about the affiliation itself.
type AffiliationDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AffiliationDescriptor"`

	// Specifies the unique identifier of the entity responsible for the affiliation. The owner is
	// NOT presumed to be a member of the affiliation; if it is a member, its identifier MUST also
	// appear in an <AffiliateMember> element.
	AffiliationOwnerID string `xml:"affiliationOwnerID,attr,omitempty"`

	// A document-unique identifier for the element, typically used as a reference point when signing.
	ID string `xml:",attr,omitempty"`

	// Optional attribute indicates the expiration time of the metadata contained in the element and
	// any contained elements.
	ValidUntil *time.Time `xml:"validUntil,attr,omitempty"`

	// Optional attribute indicates the maximum length of time a consumer should cache the metadata
	// contained in the element and any contained elements.
	CacheDuration *time.Duration `xml:"cacheDuration,attr,omitempty"`

	// An XML signature that authenticates the containing element and its contents, as described in
	// Section 3.
	Signature *xmlsecurity.Signature `xml:",omitempty"`

	// This contains optional metadata extensions that are agreed upon between a metadata publisher
	// and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`

	// One or more elements enumerating the members of the affiliation by specifying each member's
	// unique identifier. See also Section 8.3.6 of [SAMLCore].
	AffiliateMembers []string `xml:"AffiliateMember"`

	// Optional sequence of elements that provides information about the cryptographic keys that the
	// affiliation uses as a whole, as distinct from keys used by individual members of the
	// affiliation, which are published in the metadata for those entities.
	KeyDescriptors []KeyDescriptor `xml:"KeyDescriptor,omitempty"`

	// Arbitrary namespace-qualified attributes from non-SAML-defined namespaces may also be included.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`
}

type NameIDFormat struct {
	XMLName xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	Value   NameIdFormat `xml:",chardata"`
}

type Extensions struct {
	XMLName       xml.Name                  `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	DigestMethod  *xmlsecurity.DigestMethod `xml:",omitempty"`
	SigningMethod *SigningMethod            `xml:",omitempty"`

	Children []Node `xml:",any,omitempty"`
}

type SigningMethod struct {
	Algorithm  string `xml:",attr"`
	MinKeySize string `xml:",attr,omitempty"`
	MaxKeySize string `xml:",attr,omitempty"`
}
