package saml

import (
	"encoding/xml"
	"time"

	"github.com/jason-jackson/xmlsecurity"
)

// The <Action> element specifies an action on the specified resource for which permission is
// sought. Its string-data content provides the label for an action sought to be performed on
// the specified resource
type Action struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Action"`

	// A URI reference representing the namespace in which the name of the specified action is
	// to be interpreted. If this element is absent, the namespace
	// urn:oasis:names:tc:SAML:1.0:action:rwedc-negation specified in Section 8.1.2 is in effect.
	Namespace string `xml:",attr"`

	Value string `xml:",chardata"`
}

/*
The <Advice> element contains any additional information that the SAML authority wishes to provide.
This information MAY be ignored by applications without affecting either the semantics or the validity of
the assertion.

The <Advice> element contains a mixture of zero or more <Assertion>, <EncryptedAssertion>,
<AssertionIDRef>, and <AssertionURIRef> elements, and namespace-qualified elements in
other non-SAML namespaces.

Following are some potential uses of the <Advice> element:
  - Include evidence supporting the assertion claims to be cited, either directly (through incorporating
    the claims) or indirectly (by reference to the supporting assertions).
  - State a proof of the assertion claims.
  - Specify the timing and distribution points for updates to the assertion.
*/
type Advice struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	// The <AssertionIDRef> element makes a reference to a SAML assertion by its unique identifier. The
	// specific authority who issued the assertion or from whom the assertion can be obtained is not specified as
	// part of the reference.
	AssertionIDRefs []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AssertionIDRef"` // TODO remove namespace?

	// The <AssertionURIRef> element makes a reference to a SAML assertion by URI reference. The URI
	// reference MAY be used to retrieve the corresponding assertion in a manner specific to the URI reference.
	AssertionURIRefs    []string             `xml:"urn:oasis:names:tc:SAML:2.0:assertion AssertionURIRef"` // TODO remove namespace?
	Assertions          []Assertion          `xml:"saml:Assertion"`
	EncryptedAssertions []EncryptedAssertion `xml:"saml:EncryptedAssertion"`
	Children            []Node               `xml:",any,omitempty"`
}

// The <Assertion> element is of the AssertionType complex type. This type specifies the basic
// information that is common to all assertions
type Assertion struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	// The SAML version of this assertion.
	Version string `xml:",attr"`

	// The identifier for this assertion. It is of type xs:ID, and MUST follow the requirements specified in
	// Section 1.3.4 for identifier uniqueness.
	ID string `xml:",attr"`

	// The time instant of issue in UTC, as described in Section 1.3.3.
	IssueInstant time.Time `xml:",attr"`

	// The SAML authority that is making the claim(s) in the assertion. The issuer SHOULD be unambiguous
	// to the intended relying parties.
	//
	// This specification defines no particular relationship between the entity represented by this element
	// and the signer of the assertion (if any). Any such requirements imposed by a relying party that
	// consumes the assertion or by specific profiles are application-specific.
	Issuer Issuer

	// An XML Signature that protects the integrity of and authenticates the issuer of the assertion, as
	// described below and in Section 5.
	Signature *Signature `xml:",omitempty"`

	// The subject of the statement(s) in the assertion.
	Subject *Subject `xml:",omitempty"`

	// Conditions that MUST be evaluated when assessing the validity of and/or when using the assertion.
	// See Section 2.5 for additional information on how to evaluate conditions.
	Conditions *Conditions `xml:",omitempty"`

	// Additional information related to the assertion that assists processing in certain situations but which
	// MAY be ignored by applications that do not understand the advice or do not wish to make use of it.
	Advice *Advice `xml:",omitempty"`

	// A statement of a type defined in an extension schema. An xsi:type attribute MUST be used to
	// indicate the actual statement type.
	Statements []Statement `xml:"Statement,omitempty"`

	// Authentication statements
	AuthnStatements []AuthnStatement `xml:"AuthnStatement,omitempty"`

	// Authorization decision statements
	AuthzDecisionStatements []AuthzDecisionStatement `xml:"AuthzDecisionStatement,omitempty"`

	// Attribute statements
	AttributeStatements []AttributeStatement `xml:"AttributeStatement,omitempty"`
}

// The <AssertionIDRef> element makes a reference to a SAML assertion by its unique identifier. The
// specific authority who issued the assertion or from whom the assertion can be obtained is not specified as
// part of the reference.
type AssertionIDRef struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AssertionIDRef"`
	Value   string   `xml:",chardata"`
}

// The <AssertionURIRef> element makes a reference to a SAML assertion by URI reference. The URI
// reference MAY be used to retrieve the corresponding assertion in a manner specific to the URI reference.
type AssertionURIRef struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AssertionURIRef"`
	Value   string   `xml:",chardata"`
}

// The <Attribute> element identifies an attribute by name and optionally includes its value(s). It has the
// AttributeType complex type. It is used within an attribute statement to express particular attributes and
// values associated with an assertion subject, as described in the previous section. It is also used in an
// attribute query to request that the values of specific SAML attributes be returned
type Attribute struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`

	// The name of the attribute.
	Name string `xml:",attr"`

	// A URI reference representing the classification of the attribute name for purposes of interpreting the
	// name. See Section 8.2 for some URI references that MAY be used as the value of the NameFormat
	// attribute and their associated descriptions and processing rules. If no NameFormat value is provided,
	// the identifier urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified (see Section
	// 8.2.1) is in effect.
	NameFormat string `xml:",attr,omitempty"`

	// A string that provides a more human-readable form of the attribute's name, which may be useful in
	// cases in which the actual Name is complex or opaque, such as an OID or a UUID. This attribute's
	// value MUST NOT be used as a basis for formally identifying SAML attributes.
	FriendlyName string `xml:",attr,omitempty"`

	// This complex type uses an <xs:anyAttribute> extension point to allow arbitrary XML attributes to
	// be added to <Attribute> constructs without the need for an explicit schema extension. This allows
	// additional fields to be added as needed to supply additional parameters to be used, for example, in an
	// attribute query. SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or
	// XML attributes qualified by a SAML-defined namespace to the AttributeType complex type or a
	// derivation of it; such attributes are reserved for future maintenance and enhancement of SAML itself.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`

	// Contains a value of the attribute. If an attribute contains more than one discrete value, it is
	// RECOMMENDED that each value appear in its own <AttributeValue> element. If more than
	// one <AttributeValue> element is supplied for an attribute, and any of the elements have a
	// datatype assigned through xsi:type, then all of the <AttributeValue> elements must have
	// the identical datatype assigned.
	//
	// The meaning of an <Attribute> element that contains no <AttributeValue> elements depends on
	// its context. Within an <AttributeStatement>, if the SAML attribute exists but has no values, then the
	// <AttributeValue> element MUST be omitted. Within a <samlp:AttributeQuery>, the absence of
	// values indicates that the requester is interested in any or all of the named attribute's values (see also
	// Section 3.3.2.3).
	//
	// Any other uses of the <Attribute> element by profiles or other specifications MUST define the
	// semantics of specifying or omitting <AttributeValue> elements.
	Values []AttributeValue `xml:"AttributeValue"`
}

// The <AttributeStatement> element describes a statement by the SAML authority asserting that the
// assertion subject is associated with the specified attributes. Assertions containing
// <AttributeStatement> elements MUST contain a <Subject> element.
type AttributeStatement struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`

	// The <Attribute> element specifies an attribute of the assertion subject.
	Attributes []Attribute `xml:"Attribute"`

	// An encrypted SAML attribute may be included with the <EncryptedAttribute> element.
	EncryptedAttributes []EncryptedAttribute `xml:"EncryptedAttribute"`
}

/*
The <AttributeValue> element supplies the value of a specified SAML attribute. It is of the
xs:anyType type, which allows any well-formed XML to appear as the content of the element.
If the data content of an <AttributeValue> element is of an XML Schema simple type (such as
xs:integer or xs:string), the datatype MAY be declared explicitly by means of an xsi:type declaration
in the <AttributeValue> element. If the attribute value contains structured data, the necessary data
elements MAY be defined in an extension schema.

> Note: Specifying a datatype other than an XML Schema simple type on <AttributeValue> using xsi:type
will require the presence of the extension schema that defines the datatype in order for schema
processing to proceed.

If a SAML attribute includes an empty value, such as the empty string, the corresponding
<AttributeValue> element MUST be empty (generally this is serialized as <AttributeValue/>). This
overrides the requirement in Section 1.3.1 that string values in SAML content contain at least one
non-whitespace character.
*/
type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Type    string   `xml:"xsi:type,attr,omitempty"`

	// If a SAML attribute includes a "null" value, the corresponding <AttributeValue> element MUST
	// be empty and MUST contain the reserved xsi:nil XML attribute with a value of "true" or "1".
	Nil   bool   `xml:"xsi:nil,attr,omitempty"`
	Value string `xml:",chardata"`
}

// A URI reference that identifies an intended audience. The URI reference MAY identify a document
// that describes the terms and conditions of audience membership. It MAY also contain the unique
// identifier URI from a SAML name identifier that describes a system entity
type Audience struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	Value   string   `xml:",chardata"`
}

// The <AudienceRestriction> element specifies that the assertion is addressed to one or more
// specific audiences identified by <Audience> elements. Although a SAML relying party that is outside the
// audiences specified is capable of drawing conclusions from an assertion, the SAML asserting party
// explicitly makes no representation as to accuracy or trustworthiness to such a party.
//
// The SAML asserting party cannot prevent a party to whom the assertion is disclosed from taking action on
// the basis of the information provided. However, the <AudienceRestriction> element allows the
// SAML asserting party to state explicitly that no warranty is provided to such a party in a machine- and
// human-readable form. While there can be no guarantee that a court would uphold such a warranty
// exclusion in every circumstance, the probability of upholding the warranty exclusion is considerably
// improved.
//
// Note that multiple <AudienceRestriction> elements MAY be included in a single assertion, and each
// MUST be evaluated independently. The effect of this requirement and the preceding definition is that
// within a given condition, the audiences form a disjunction (an "OR") while multiple conditions form a
// conjunction (an "AND").
type AudienceRestriction struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`

	// A URI reference that identifies an intended audience. The URI reference MAY identify a document
	// that describes the terms and conditions of audience membership. It MAY also contain the unique
	// identifier URI from a SAML name identifier that describes a system entity
	Audiences []URI `xml:"Audience"`
}

// The <AuthnContext> element specifies the context of an authentication event. The element can
// contain an authentication context class reference, an authentication context declaration or
// declaration reference, or both.
type AuthnContext struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`

	// A URI reference identifying an authentication context class that describes the authentication
	// context declaration that follows.
	AuthnContextClassRef URI `xml:",omitempty"`

	// An authentication context declaration provided by value
	AuthnContextDecl string `xml:",omitempty"`

	// Either an authentication context declaration provided by a URI reference that identifies
	// such a declaration. The URI reference MAY directly resolve into an XML document containing
	// the referenced declaration.
	AuthnContextDeclRef URI `xml:",omitempty"`

	// Zero or more unique identifiers of authentication authorities that were involved in the
	// authentication of the principal (not including the assertion issuer, who is presumed to have
	// been involved without being explicitly named here).
	AuthenticatingAuthorities []URI `xml:"AuthenticatingAuthority"`
}

type AuthnContextClassRef struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	Value   string   `xml:",chardata"`
}

type AuthnContextDeclRef struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	Value   string   `xml:",chardata"`
}

type AuthnContextDecl struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDecl"`
	Value   string   `xml:",chardata"`
}

// The <AuthnStatement> element describes a statement by the SAML authority asserting that the
// assertion subject was authenticated by a particular means at a particular time. Assertions containing
// <AuthnStatement> elements MUST contain a <Subject> element.
type AuthnStatement struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`

	// Specifies the time at which the authentication took place. The time value is encoded in UTC
	AuthnInstant time.Time `xml:"AuthnInstant,attr,omitempty"`

	/*
		Specifies the index of a particular session between the principal identified by the subject and the
		authenticating authority.

		In general, any string value MAY be used as a SessionIndex value. However, when privacy is a
		consideration, care must be taken to ensure that the SessionIndex value does not invalidate
		other privacy mechanisms. Accordingly, the value SHOULD NOT be usable to correlate activity
		by a principal across different session participants. Two solutions that achieve this goal
		are provided below and are RECOMMENDED:
		 - Use small positive integers (or reoccurring constants in a list) for the SessionIndex. The
		   SAML authority SHOULD choose the range of values such that the cardinality of any one integer
		   will be sufficiently high to prevent a particular principal's actions from being correlated
		   across multiple session participants. The SAML authority SHOULD choose values for SessionIndex
		   randomly from within this range (except when required to ensure unique values for subsequent
		   statements given to the same session participant but as part of a distinct session).
		 - Use the enclosing assertion's ID value in the SessionIndex.
	*/
	SessionIndex string `xml:"SessionIndex,attr,omitempty"`

	// Specifies a time instant at which the session between the principal identified by the subject
	// and the SAML authority issuing this statement MUST be considered ended. The time value is encoded
	// in UTC, as described in Section 1.3.3. There is no required relationship between this attribute
	// and a NotOnOrAfter condition attribute that may be present in the assertion.
	SessionNotOnOrAfter *time.Time `xml:"SessionNotOnOrAfter,attr,omitempty"`

	// Specifies the DNS domain name and IP address for the system from which the assertion subject was
	// apparently authenticated.
	SubjectLocality *SubjectLocality `xml:"SubjectLocality,omitempty"`

	// The context used by the authenticating authority up to and including the authentication event that
	// yielded this statement. Contains an authentication context class reference, an authentication context
	// declaration or declaration reference, or both.
	AuthnContext AuthnContext `xml:"AuthnContext"`
}

/*
> Note: The <AuthzDecisionStatement> feature has been frozen as of SAML V2.0, with no future
enhancements planned. Users who require additional functionality may want to consider the
eXtensible Access Control Markup Language [XACML], which offers enhanced authorization decision features.

The <AuthzDecisionStatement> element describes a statement by the SAML authority asserting that a request
for access by the assertion subject to the specified resource has resulted in the specified authorization
decision on the basis of some optionally specified evidence. Assertions containing <AuthzDecisionStatement>
elements MUST contain a <Subject> element.

The resource is identified by means of a URI reference. In order for the assertion to be interpreted
correctly and securely, the SAML authority and SAML relying party MUST interpret each URI reference in a
consistent manner. Failure to achieve a consistent URI reference interpretation can result in different
authorization decisions depending on the encoding of the resource URI reference. Rules for normalizing
URI references are to be found in IETF RFC 2396 [RFC 2396] Section 6:

> In general, the rules for equivalence and definition of a normal form, if any, are scheme dependent.
When a scheme uses elements of the common syntax, it will also use the common syntax equivalence rules,
namely that the scheme and hostname are case insensitive and a URL with an explicit ":port", where the
port is the default for the scheme, is equivalent to one where the port is elided.

To avoid ambiguity resulting from variations in URI encoding, SAML system entities SHOULD employ the URI
normalized form wherever possible as follows:
  - SAML authorities SHOULD encode all resource URI references in normalized form.
  - Relying parties SHOULD convert resource URI references to normalized form prior to processing.

Inconsistent URI reference interpretation can also result from differences between the URI reference
syntax and the semantics of an underlying file system. Particular care is required if URI references
are employed to specify an access control policy language. The following security conditions SHOULD be
satisfied by the system which employs SAML assertions:
  - Parts of the URI reference syntax are case sensitive. If the underlying file system is case insensitive,
    a requester SHOULD NOT be able to gain access to a denied resource by changing the case of a part of the
    resource URI reference.
  - Many file systems support mechanisms such as logical paths and symbolic links, which allow users to
    establish logical equivalences between file system entries. A requester SHOULD NOT be able to gain
    access to a denied resource by creating such an equivalence.
*/
type AuthzDecisionStatement struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthzDecisionStatement"`

	// A URI reference identifying the resource to which access authorization is sought. This attribute
	// MAY have the value of the empty URI reference (""), and the meaning is defined to be "the start
	// of the current document", as specified by IETF RFC 2396 [RFC 2396] Section 4.2.
	Resource URI `xml:",attr"`

	// The decision rendered by the SAML authority with respect to the specified resource. The value is of
	// the DecisionType simple type.
	Decision DecisionType `xml:",attr"`

	// The set of actions authorized to be performed on the specified resource.
	Actions []Action `xml:"Action,omitempty"`

	// A set of assertions that the SAML authority relied on in making the decision.
	Evidence *Evidence `xml:",omitempty"`

	SessionNotOnOrAfter *time.Time `xml:",attr,omitempty"`
}

// BaseID is an extension point that allows applications to add new kinds of identifiers.
//
// The NameQualifier and SPNameQualifier attributes SHOULD be omitted unless the
// identifier's type definition explicitly defines their use and semantics.
type BaseID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`
	IDNameQualifiers
}

type Conditions struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`

	// Specifies the earliest time instant at which the assertion is valid. The time value is encoded in UTC.
	NotBefore *time.Time `xml:",attr,omitempty"`

	// Specifies the time instant at which the assertion has expired. The time value is encoded in UTC.
	NotOnOrAfter *time.Time `xml:",attr,omitempty"`

	// A condition of a type defined in an extension schema.
	// An xsi:type attribute MUST be used to indicate the actual condition type.
	Conditions []Condition `xml:",omitempty"`

	// Specifies that the assertion is addressed to a particular audience.
	AudienceRestrictions []AudienceRestriction `xml:",omitempty"`

	// Specifies that the assertion SHOULD be used immediately and MUST NOT be retained for future
	// use. Although the schema permits multiple occurrences, there MUST be at most one instance of
	// this element.
	OneTimeUse *OneTimeUse `xml:",omitempty"`

	// Specifies limitations that the asserting party imposes on relying parties that wish to subsequently act
	// as asserting parties themselves and issue assertions of their own on the basis of the information
	// contained in the original assertion. Although the schema permits multiple occurrences, there MUST
	// be at most one instance of this element.
	ProxyRestriction *ProxyRestriction `xml:",omitempty"`
}

// Nothing is defined, the only thing it mentions is in Conditions where it says it needs a xsi:type attribute
type Condition struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Condition"`
	Type    string   `xml:"xsi:type,attr"`
	Value   string   `xml:",chardata"`
}

// The <EncryptedAssertion> element represents an assertion in encrypted fashion,
// as defined by the XML Encryption Syntax and Processing specification [XMLEnc].
type EncryptedAssertion struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
	EncryptedElementType
}

// The <EncryptedAttribute> element represents an attribute in encrypted fashion,
// as defined by the XML Encryption Syntax and Processing specification [XMLEnc].
type EncryptedAttribute struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAttribute"`
	EncryptedElementType
}

// The <EncryptedID> element is of type EncryptedElementType, and carries the content of an
// unencrypted identifier element in encrypted fashion, as defined by the XML Encryption Syntax and
// Processing specification [XMLEnc].
type EncryptedID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
	EncryptedElementType
}

type EncryptedElementType struct {
	// The encrypted content and associated encryption details, as defined by the XML Encryption
	// Syntax and Processing specification [XMLEnc]. The Type attribute SHOULD be present and, if
	// present, MUST contain a value of http://www.w3.org/2001/04/xmlenc#Element. The
	// encrypted content MUST contain an element that has a type of NameIDType or AssertionType,
	// or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType.
	EncryptedData xmlsecurity.EncryptedData `xml:"xenc:EncryptedData"`

	// Wrapped decryption keys, as defined by [XMLEnc]. Each wrapped key SHOULD include a
	// Recipient attribute that specifies the entity for whom the key has been encrypted. The value of
	// the Recipient attribute SHOULD be the URI identifier of a SAML system entity
	EncryptedKeys []xmlsecurity.EncryptedKey `xml:"xenc:EncryptedKey"`
}

// The <Evidence> element contains one or more assertions or assertion references that the SAML
// authority relied on in issuing the authorization decision.
//
// Providing an assertion as evidence MAY affect the reliance agreement between the SAML relying party
// and the SAML authority making the authorization decision. For example, in the case that the SAML relying
// party presented an assertion to the SAML authority in a request, the SAML authority MAY use that
// assertion as evidence in making its authorization decision without endorsing the <Evidence> element’s
// assertion as valid either to the relying party or any other third party.
type Evidence struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Evidence"`

	// Specifies an assertion by reference to the value of the assertion’s ID attribute.
	AssertionIDRefs []string `xml:"AssertionIDRef"`

	// Specifies an assertion by means of a URI reference.
	AssertionURIRefs []URI `xml:"saml:AssertionURIRef"`

	// Specifies an assertion by value.
	Assertions []Assertion `xml:"saml:Assertion"`

	// Specifies an encrypted assertion by value.
	EncryptedAssertions []EncryptedAssertion `xml:"saml:EncryptedAssertion"`
}

// The NameQualifier and SPNameQualifier attributes SHOULD be omitted unless the
// identifier's type definition explicitly defines their use and semantics.
type IDNameQualifiers struct {
	// The security or administrative domain that qualifies the identifier. This attribute
	// provides a means to federate identifiers from disparate user stores without collision.
	NameQualifier string `xml:",attr,omitempty"`

	// Further qualifies an identifier with the name of a service provider or affiliation of
	// providers. This attribute provides an additional means to federate identifiers on the
	// basis of the relying party or parties.
	SPNameQualifier string `xml:",attr,omitempty"`
}

// The <Issuer> element, with complex type NameIDType, provides information about the issuer of a
// SAML assertion or protocol message. The element requires the use of a string to carry the issuer's name,
// but permits various pieces of descriptive data.
//
// Overriding the usual rule for this element's type, if no Format value is provided with this element, then the
// value urn:oasis:names:tc:SAML:2.0:nameid-format:entity is in effect.
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDType
}

// The KeyInfoConfirmationDataType complex type constrains a <SubjectConfirmationData>
// element to contain one or more <ds:KeyInfo> elements that identify cryptographic keys that are used in
// some way to authenticate an attesting entity. The particular confirmation method MUST define the exact
// mechanism by which the confirmation data can be used. The optional attributes defined by the
// SubjectConfirmationDataType complex type MAY also appear.
//
// This complex type, or a type derived from it, SHOULD be used by any confirmation method that defines its
// confirmation data in terms of the <ds:KeyInfo> element.
//
// Note that in accordance with [XMLSig], each <ds:KeyInfo> element MUST identify a single
// cryptographic key. Multiple keys MAY be identified with separate <ds:KeyInfo> elements,
// such as when a principal uses different keys to confirm itself to different relying parties.
type KeyInfoConfirmationDataType struct {
	KeyInfos []xmlsecurity.KeyInfo `xml:"KeyInfo"`

	SubjectConfirmationData
}

// The <NameID> element is of type NameIDType, and is used in various SAML assertion constructs
// such as the <Subject> and <SubjectConfirmation> elements, and in various protocol messages
type NameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	NameIDType
}

// The NameIDType complex type is used when an element serves to represent an entity by a string-valued
// name. It is a more restricted form of identifier than the <BaseID> element and is the type underlying both
// the <NameID> and <Issuer> elements.
//
// The NameQualifier and SPNameQualifier attributes SHOULD be omitted unless the
// identifier's type definition explicitly defines their use and semantics.
type NameIDType struct {
	// A URI reference representing the classification of string-based identifier information.
	// Unless otherwise specified by an element based on this type, if no Format value is
	// provided, then the value urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified is in effect.
	//
	// When a Format value other than one specified in Section 8.3 is used, the content of an element
	// of this type is to be interpreted according to the definition of that format as provided outside of this
	// specification. If not otherwise indicated by the definition of the format, issues of anonymity,
	// pseudonymity, and the persistence of the identifier with respect to the asserting and relying parties
	// are implementation-specific.
	Format NameIdFormat `xml:",attr,omitempty"`

	// A name identifier established by a service provider or affiliation of providers for the entity, if
	// different from the primary name identifier given in the content of the element. This attribute
	// provides a means of integrating the use of SAML with existing identifiers already in use by a
	// service provider.
	SPProvidedID string `xml:",attr,omitempty"`

	Value string `xml:",chardata"`

	IDNameQualifiers
}

// In general, relying parties may choose to retain assertions, or the information they contain in some other
// form, for reuse. The <OneTimeUse> condition element allows an authority to indicate that the information
// in the assertion is likely to change very soon and fresh information should be obtained for each use. An
// example would be an assertion containing an <AuthzDecisionStatement> which was the result of a
// policy which specified access control which was a function of the time of day.
// If system clocks in a distributed environment could be precisely synchronized, then this requirement could
// be met by careful use of the validity interval. However, since some clock skew between systems will
// always be present and will be combined with possible transmission delays, there is no convenient way for
// the issuer to appropriately limit the lifetime of an assertion without running a substantial risk that it will
// already have expired before it arrives.
//
// The <OneTimeUse> element indicates that the assertion SHOULD be used immediately by the relying
// party and MUST NOT be retained for future use. Relying parties are always free to request a fresh
// assertion for every use. However, implementations that choose to retain assertions for future use MUST
// observe the <OneTimeUse> element. This condition is independent from the NotBefore and
// NotOnOrAfter condition information.
//
// To support the single use constraint, a relying party should maintain a cache of the assertions it has
// processed containing such a condition. Whenever an assertion with this condition is processed, the cache
// should be checked to ensure that the same assertion has not been previously received and processed by
// the relying party.
//
// A SAML authority MUST NOT include more than one <OneTimeUse> element within a <Conditions>
// element of an assertion.
//
// For the purposes of determining the validity of the <Conditions> element, the <OneTimeUse> is
// considered to always be valid. That is, this condition does not affect validity but is a condition on use.
type OneTimeUse struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion OneTimeUse"`
}

// Specifies limitations that the asserting party imposes on relying parties that in turn wish to act as asserting
// parties and issue subsequent assertions of their own on the basis of the information contained in the
// original assertion. A relying party acting as an asserting party MUST NOT issue an assertion that itself
// violates the restrictions specified in this condition on the basis of an assertion containing such a condition.
//
// A SAML authority MUST NOT include more than one <ProxyRestriction> element within a <Conditions> element of an assertion.
//
// For the purposes of determining the validity of the <Conditions> element, the <ProxyRestriction> condition
// is considered to always be valid. That is, this condition does not affect validity but is a condition on use.
type ProxyRestriction struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion ProxyRestriction"`

	// Specifies the maximum number of indirections that the asserting party permits to exist between this
	// assertion and an assertion which has ultimately been issued on the basis of it.
	//
	// A Count value of zero indicates that a relying party MUST NOT issue an assertion to another relying party
	// on the basis of this assertion. If greater than zero, any assertions so issued MUST themselves contain a
	// <ProxyRestriction> element with a Count value of at most one less than this value.
	Count *int `xml:"Count,attr,omitempty"`

	// Specifies the set of audiences to whom the asserting party permits new assertions to be issued on
	// the basis of this assertion.
	//
	// If no <Audience> elements are specified, then no audience restrictions are imposed on the relying
	// parties to whom subsequent assertions can be issued. Otherwise, any assertions so issued MUST
	// themselves contain an <AudienceRestriction> element with at least one of the <Audience>
	// elements present in the previous <ProxyRestriction> element, and no <Audience> elements
	// present that were not in the previous <ProxyRestriction> element.
	Audience []string `xml:"Audience"`
}

type Signature struct {
	SignatureDocument []byte `xml:",innerxml"`
}

// The <Statement> element is an extension point that allows other assertion-based applications to reuse
// the SAML assertion framework. SAML itself derives its core statements from this extension point. Its
// StatementAbstractType complex type is abstract and is thus usable only as the base of a derived type.
type Statement struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Statement"`
}

// The optional <Subject> element specifies the principal that is the subject
// of all of the (zero or more) statements in the assertion. It contains an
// identifier, a series of one or more subject confirmations, or both.
//
// A <Subject> element can contain both an identifier and zero or more subject
// confirmations which a relying party can verify when processing an assertion.
// If any one of the included subject confirmations are verified, the relying
// party MAY treat the entity presenting the assertion as one that the asserting
// party has associated with the principal identified in the name identifier and
// associated with the statements in the assertion. This attesting entity and the
// actual subject may or may not be the same entity.
//
// If there are no subject confirmations included, then any relationship between
// the presenter of the assertion and the actual subject is unspecified.
//
// A <Subject> element SHOULD NOT identify more than one principal.
type Subject struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion saml:Subject"`

	BaseID      *BaseID      `xml:",omitempty"` // Identifies the subject.
	NameID      *NameID      `xml:",omitempty"` // Identifies the subject.
	EncryptedID *EncryptedID `xml:",omitempty"` // Identifies the subject.

	// Information that allows the subject to be confirmed. If more than one
	// subject confirmation is provided, then satisfying any one of them is
	// sufficient to confirm the subject for the purpose of applying the assertion.
	SubjectConfirmations []SubjectConfirmation `xml:"SubjectConfirmation"`
}

// The <SubjectConfirmation> element provides the means for a relying party
// to verify the correspondence of the subject of the assertion with the party
// with whom the relying party is communicating.
type SubjectConfirmation struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`

	// A URI reference that identifies a protocol or mechanism to be used to
	// confirm the subject. URI references identifying SAML-defined confirmation
	// methods are currently defined in the SAML profiles specification [SAMLProf].
	// Additional methods MAY be added by defining new URIs and profiles or by private agreement.
	Method string `xml:"Method,attr"`

	BaseID      *BaseID      `xml:",omitempty"` // Identifies the entity expected to satisfy the enclosing subject confirmation requirements.
	NameID      *NameID      `xml:",omitempty"` // Identifies the entity expected to satisfy the enclosing subject confirmation requirements.
	EncryptedID *EncryptedID `xml:",omitempty"` // Identifies the entity expected to satisfy the enclosing subject confirmation requirements.

	// Additional confirmation information to be used by a specific confirmation method.
	// For example, typical content of this element might be a <ds:KeyInfo> element as
	// defined in the XML Signature Syntax and Processing specification [XMLSig], which
	// identifies a cryptographic key. Particular confirmation methods MAY define a
	// schema type to describe the elements, attributes, or content that may appear in
	// the <SubjectConfirmationData> element.Additional confirmation information to be
	// used by a specific confirmation method. For example, typical content of this
	// element might be a <ds:KeyInfo> element as defined in the XML Signature Syntax
	// and Processing specification [XMLSig], which identifies a cryptographic key.
	// Particular confirmation methods MAY define a schema type to describe the elements,
	// attributes, or content that may appear in the <SubjectConfirmationData> element.
	SubjectConfirmationData *SubjectConfirmationData `xml:"SubjectConfirmationData,omitempty"`
}

// The <SubjectConfirmationData> element has the SubjectConfirmationDataType complex
// type. It specifies additional data that allows the subject to be confirmed or
// constrains the circumstances under which the act of subject confirmation can take
// place. Subject confirmation takes place when a relying party seeks to verify the
// relationship between an entity presenting the assertion (that is, the attesting
// entity) and the subject of the assertion's claims.
type SubjectConfirmationData struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`

	// A time instant before which the subject cannot be confirmed. The time value is encoded in UTC.
	NotBefore string `xml:",attr,omitempty"`

	// A time instant at which the subject can no longer be confirmed. The time value is encoded in UTC.
	NotOnOrAfter string `xml:",attr,omitempty"`

	// A URI specifying the entity or location to which an attesting entity can present the assertion.
	// For example, this attribute might indicate that the assertion must be delivered to a particular
	// network endpoint in order to prevent an intermediary from redirecting it someplace else.
	Recipient string `xml:",attr,omitempty"`

	// The ID of a SAML protocol message in response to which an attesting entity can present the
	// assertion. For example, this attribute might be used to correlate the assertion to a SAML
	// request that resulted in its presentation.
	InResponseTo string `xml:",attr,omitempty"`

	// The network address/location from which an attesting entity can present the assertion.
	// For example, this attribute might be used to bind the assertion to particular client
	// addresses to prevent an attacker from easily stealing and presenting the assertion from
	// another location. IPv4 addresses SHOULD be represented in the usual dotted-decimal format
	// (e.g., "1.2.3.4"). IPv6 addresses SHOULD be represented as defined by Section 2.2 of IETF
	// RFC 3513 [RFC 3513] (e.g., "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210").
	Address string `xml:",attr,omitempty"`

	// This complex type uses an <xs:anyAttribute> extension point to allow arbitrary namespace-
	// qualified XML attributes to be added to <SubjectConfirmationData> constructs without the need
	// for an explicit schema extension. This allows additional fields to be added as needed to supply
	// additional confirmation-related information. SAML extensions MUST NOT add local (non-namespace-
	// qualified) XML attributes or XML attributes qualified by a SAML-defined namespace to the
	// SubjectConfirmationDataType complex type or a derivation of it; such attributes are reserved for
	// future maintenance and enhancement of SAML itself.
	Attributes []xml.Attr `xml:",any,attr,omitempty"`

	// This complex type uses an <xs:any> extension point to allow arbitrary XML elements to be added to
	// <SubjectConfirmationData> constructs without the need for an explicit schema extension. This
	// allows additional elements to be added as needed to supply additional confirmation-related
	// information.
	Children []Node `xml:",any,omitempty"`
}

// The <SubjectLocality> element specifies the DNS domain name and IP address for the system
// from which the assertion subject was authenticated.
//
// This element is entirely advisory, since both of these fields are quite easily “spoofed,”
// but may be useful information in some applications.
type SubjectLocality struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectLocality"`

	// The network address of the system from which the principal identified by the subject
	// was authenticated. IPv4 addresses SHOULD be represented in dotted-decimal format
	// (e.g., "1.2.3.4"). IPv6 addresses SHOULD be represented as defined by Section 2.2 of
	// IETF RFC 3513 [RFC 3513] (e.g., "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210").
	Address string `xml:",attr,omitempty"`

	// The DNS name of the system from which the principal identified by the subject was authenticated.
	DNSName string `xml:",attr,omitempty"`
}
