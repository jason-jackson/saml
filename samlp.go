package saml

import (
	"encoding/xml"
	"net/http"
	"time"
)

// All SAML requests are of types that are derived from the abstract RequestAbstractType complex type.
//
// If a SAML responder deems a request to be invalid according to SAML syntax or processing rules, then if
// it responds, it MUST return a SAML response message with a <StatusCode> element with the value
// urn:oasis:names:tc:SAML:2.0:status:Requester. In some cases, for example during a
// suspected denial-of-service attack, not responding at all may be warranted.
type RequestAbstractType struct {
	Saml  string   `xml:"xmlns:saml,attr,omitempty"`
	SamlP Protocol `xml:"xmlns:samlp,attr,omitempty"`

	// An identifier for the request. It is of type xs:ID and MUST follow the requirements specified
	// in Section 1.3.4 for identifier uniqueness. The values of the ID attribute in a request and the
	// InResponseTo attribute in the corresponding response MUST match.
	ID string `xml:",attr"`

	// The version of this request.
	Version string `xml:",attr"`

	// The time instant of issue of the request. The time value is encoded in UTC, as described in Section 1.3.3.
	IssueInstant time.Time `xml:",attr"`

	// A URI reference indicating the address to which this request has been sent. This is useful to prevent
	// malicious forwarding of requests to unintended recipients, a protection that is required by some protocol
	// bindings. If it is present, the actual recipient MUST check that the URI reference identifies the location
	// at which the message was received. If it does not, the request MUST be discarded. Some protocol bindings
	// may require the use of this attribute (see [SAMLBind]).
	Destination string `xml:",attr,omitempty"`

	// Indicates whether or not (and under what conditions) consent has been obtained from a principal in
	// the sending of this request. See Section 8.4 for some URI references that MAY be used as the value
	// of the Consent attribute and their associated descriptions. If no Consent value is provided, the
	// identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect.
	Consent string `xml:",attr,omitempty"`

	// Identifies the entity that generated the request message. (For more information on this element, see
	// Section 2.2.5.)
	Issuer string `xml:"saml:Issuer,omitempty"`

	// An XML Signature that authenticates the requester and provides message integrity, as described
	// in Section 5.
	//
	// The SAML request MAY be signed, which provides both authentication of the requester and message
	// integrity. If such a signature is used, then the <ds:Signature> element MUST be present, and the SAML
	// responder MUST verify that the signature is valid (that is, that the message has not been tampered with)
	// in accordance with [XMLSig]. If it is invalid, then the responder MUST NOT rely on the contents of the
	// request and SHOULD respond with an error. If it is valid, then the responder SHOULD evaluate the
	// signature to determine the identity and appropriateness of the signer and may continue to process the
	// request or respond with an error (if the request is invalid for some other reason).
	//
	// If a Consent attribute is included and the value indicates that some form of principal consent has been
	// obtained, then the request SHOULD be signed.
	Signature string `xml:"ds:Signature,omitempty"`

	// This extension point contains optional protocol message extension elements that are agreed on
	// between the communicating parties. No extension schema is required in order to make use of this
	// extension point, and even if one is provided, the lax validation setting does not impose a requirement
	// for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-
	// SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`
}

// All SAML responses are of types that are derived from the StatusResponseType complex type.
type StatusResponseType struct {
	Saml  string `xml:"xmlns:saml,attr,omitempty"`
	SamlP string `xml:"xmlns:samlp,attr,omitempty"`

	// An identifier for the response. It is of type xs:ID, and MUST follow the requirements specified in
	// Section 1.3.4 for identifier uniqueness.
	ID string `xml:",attr"`

	// A reference to the identifier of the request to which the response corresponds, if any. If the response
	// is not generated in response to a request, or if the ID attribute value of a request cannot be
	// determined (for example, the request is malformed), then this attribute MUST NOT be present.
	// Otherwise, it MUST be present and its value MUST match the value of the corresponding request's
	// ID attribute.
	InResponseTo string `xml:",attr,omitempty"`

	// The version of this response. SAML versioning is discussed in Section 4.
	Version string `xml:",attr"`

	// The time instant of issue of the response. The time value is encoded in UTC, as described in Section 1.3.3.
	IssueInstant time.Time `xml:",attr"`

	// A URI reference indicating the address to which this response has been sent. This is useful to prevent
	// malicious forwarding of responses to unintended recipients, a protection that is required by some
	// protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
	// location at which the message was received. If it does not, the response MUST be discarded. Some
	// protocol bindings may require the use of this attribute (see [SAMLBind]).
	Destination string `xml:",attr,omitempty"`

	// Indicates whether or not (and under what conditions) consent has been obtained from a principal in
	// the sending of this response. See Section 8.4 for some URI references that MAY be used as the value
	// of the Consent attribute and their associated descriptions. If no Consent value is provided, the
	// identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in
	// effect.
	Consent string `xml:",attr,omitempty"`

	// Identifies the entity that generated the response message. (For more information on this element, see
	// Section 2.2.5.)
	Issuer string `xml:"saml:Issuer,omitempty"`

	// An XML Signature that authenticates the responder and provides message integrity, as described
	// below and in Section 5.
	//
	// The SAML response MAY be signed, which provides both authentication of the responder and message
	// integrity. If such a signature is used, then the <ds:Signature> element MUST be present, and the SAML
	// requester receiving the response MUST verify that the signature is valid (that is, that the message has not
	// been tampered with) in accordance with [XMLSig]. If it is invalid, then the requester MUST NOT rely on
	// the contents of the response and SHOULD treat it as an error. If it is valid, then the requester SHOULD
	// evaluate the signature to determine the identity and appropriateness of the signer and may continue to
	// process the response as it deems appropriate.
	//
	// If a Consent attribute is included and the value indicates that some form of principal consent has been
	// obtained, then the response SHOULD be signed.
	Signature string `xml:"ds:Signature,omitempty"`

	// This extension point contains optional protocol message extension elements that are agreed on
	// between the communicating parties. . No extension schema is required in order to make use of this
	// extension point, and even if one is provided, the lax validation setting does not impose a requirement
	// for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-
	// SAML-defined namespace.
	Extensions *Extensions `xml:",omitempty"`

	// A code representing the status of the corresponding request.
	Status Status
}

type Status struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// A code representing the status of the activity carried out in response to the corresponding request.
	StatusCode StatusCode

	// A message which MAY be returned to an operator.
	StatusMessage string `xml:",omitempty"`

	// Additional information concerning the status of the request.
	StatusDetail *StatusDetail `xml:",omitempty"`
}

// The <StatusCode> element specifies a code or a set of nested codes representing the status of the
// corresponding request.
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol samlp:StatusCode"`

	// The status code value. This attribute contains a URI reference. The value of the topmost
	// <StatusCode> element MUST be from the top-level list provided in this section.
	Value SamlStatus `xml:"Value,attr"`

	// A subordinate status code that provides more specific information on an error condition.
	// Note that responders MAY omit subordinate status codes in order to prevent attacks that seek to
	// probe for additional information by intentionally presenting erroneous requests.
	StatusCode []StatusCode `xml:",omitempty"`
}

// The <StatusMessage> element specifies a message that MAY be returned to an operator
type StatusMessage struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusMessage"`
	Value   string   `xml:",chardata"`
}

// The <StatusDetail> element MAY be used to specify additional information concerning the status of
// the request. The additional information consists of zero or more elements from any namespace, with no
// requirement for a schema to be present or for schema validation of the <StatusDetail> contents.
type StatusDetail struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusDetail"`
	Value    string   `xml:",chardata"`
	Children []Node   `xml:",any,omitempty"`
}

// If the requester knows the unique identifier of one or more assertions, the <AssertionIDRequest>
// message element can be used to request that they be returned in a <Response> message. The
// <saml:AssertionIDRef> element is used to specify each assertion to return. See Section 2.3.1 for
// more information on this element.
type AssertionIDRequest struct {
	XMLName xml.Name `xml:"samlp:AssertionIDRequest"`

	// The <AssertionIDRef> element makes a reference to a SAML assertion by its unique identifier. The
	// specific authority who issued the assertion or from whom the assertion can be obtained is not specified as
	// part of the reference.
	AssertionIDRefs []string `xml:"AssertionIDRef"`

	RequestAbstractType
}

// The <SubjectQuery> message element is an extension point that allows new SAML queries to be
// defined that specify a single SAML subject. Its SubjectQueryAbstractType complex type is abstract
// and is thus usable only as the base of a derived type. SubjectQueryAbstractType adds the
// <saml:Subject> element (defined in Section 2.4) to RequestAbstractType.
type SubjectQuery struct {
	Subject Subject

	RequestAbstractType
}

/*
The <AuthnQuery> message element is used to make the query “What assertions containing
authentication statements are available for this subject?” A successful <Response> will
contain one or more assertions containing authentication statements.

The <AuthnQuery> message MUST NOT be used as a request for a new authentication using
credentials provided in the request. <AuthnQuery> is a request for statements about
authentication acts that have occurred in a previous interaction between the indicated
subject and the authentication authority.

In response to an authentication query, a SAML authority returns assertions with
authentication statements as follows:
  - Rules given in Section 3.3.4 for matching against the <Subject> element of the query
    identify the assertions that may be returned.
  - If the SessionIndex attribute is present in the query, at least one <AuthnStatement>
    element in the set of returned assertions MUST contain a SessionIndex attribute that
    matches the SessionIndex attribute in the query. It is OPTIONAL for the complete set of
    all such matching assertions to be returned in the response.
  - If the <RequestedAuthnContext> element is present in the query, at least one
    <AuthnStatement> element in the set of returned assertions MUST contain an <AuthnContext>
    element that satisfies the element in the query (see Section 3.3.2.2.1). It is OPTIONAL
    for the complete set of all such matching assertions to be returned in the response.
*/
type AuthnQuery struct {
	XMLName xml.Name `xml:"samlp:AuthnQuery"`

	// If present, specifies a filter for possible responses. Such a query asks the question
	// “What assertions containing authentication statements do you have for this subject
	// within the context of the supplied session information?”
	SessionIndex string `xml:",attr,omitempty"`

	// If present, specifies a filter for possible responses. Such a query asks the question
	// "What assertions containing authentication statements do you have for this subject
	// that satisfy the authentication context requirements in this element?"
	RequestedAuthnContext *RequestedAuthnContext `xml:",omitempty"`

	SubjectQuery
}

// RequestedAuthnContext specifies the authentication context requirements
// of authentication statements returned in response to a request or query.
//
// Either a set of class references or a set of declaration references can be used. The set of supplied
// references MUST be evaluated as an ordered set, where the first element is the most preferred
// authentication context class or declaration. If none of the specified classes or declarations can be satisfied
// in accordance with the rules below, then the responder MUST return a <Response> message with a
// second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext.
type RequestedAuthnContext struct {
	XMLName xml.Name `xml:"samlp:RequestedAuthnContext"`

	// Specifies the comparison method used to evaluate the requested context classes or
	// statements, one of "exact", "minimum", "maximum", or "better". The default is "exact".
	//
	// If Comparison is set to "exact" or omitted, then the resulting authentication context in the authentication
	// statement MUST be the exact match of at least one of the authentication contexts specified.
	//
	// If Comparison is set to "minimum", then the resulting authentication context in the authentication
	// statement MUST be at least as strong (as deemed by the responder) as one of the authentication
	// contexts specified.
	//
	// If Comparison is set to "better", then the resulting authentication context in the authentication
	// statement MUST be stronger (as deemed by the responder) than any one of the authentication contexts
	// specified.
	//
	// If Comparison is set to "maximum", then the resulting authentication context in the authentication
	// statement MUST be as strong as possible (as deemed by the responder) without exceeding the strength
	// of at least one of the authentication contexts specified.
	Comparison string `xml:",attr,omitempty"`

	// Specifies one or more URI references identifying authentication context classes or declarations.
	ClassReferences       []URI `xml:"AuthnContextClassRef,omitempty"`
	DeclarationReferences []URI `xml:"AuthnContextDeclRef,omitempty"`
}

/*
The <AttributeQuery> element is used to make the query “Return the requested attributes for this
subject.” A successful response will be in the form of assertions containing attribute statements,
to the extent allowed by policy.

A single query MUST NOT contain two <saml:Attribute> elements with the same Name and
NameFormat values (that is, a given attribute MUST be named only once in a query).

In response to an attribute query, a SAML authority returns assertions with attribute statements as follows:
  - Rules given in Section 3.3.4 for matching against the <Subject> element of the query identify the
    assertions that may be returned.
  - If any <Attribute> elements are present in the query, they constrain/filter the attributes and optionally
    the values returned, as noted above.
  - The attributes and values returned MAY also be constrained by application-specific policy considerations.

The second-level status codes urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile and
urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue MAY be used to
indicate problems with the interpretation of attribute or value information in a query.
*/
type AttributeQuery struct {
	XMLName xml.Name `xml:"samlp:AttributeQuery"`

	// Each <saml:Attribute> element specifies an attribute whose value(s) are to be returned. If no
	// attributes are specified, it indicates that all attributes allowed by policy are requested.
	// If a given <saml:Attribute> element contains one or more <saml:AttributeValue> elements, then
	// if that attribute is returned in the response, it MUST NOT contain any values that are not
	// equal to the values specified in the query. In the absence of equality rules specified by
	// particular profiles or attributes, equality is defined as an identical XML representation of
	// the value. For more information on <saml:Attribute>, see Section 2.7.3.1.
	Attributes []Attribute `xml:"Attribute,omitempty"`

	SubjectQuery
}

/*
The <AuthzDecisionQuery> element is used to make the query “Should these actions on this resource be
allowed for this subject, given this evidence?” A successful response will be in the form of
assertions containing authorization decision statements.

> Note: The <AuthzDecisionQuery> feature has been frozen as of SAML V2.0, with no future enhancements
planned. Users who require additional functionality may want to consider the eXtensible Access
Control Markup Language [XACML], which offers enhanced authorization decision features.

In response to an authorization decision query, a SAML authority returns assertions with authorization
decision statements as follows:

  - Rules given in Section 3.3.4 for matching against the <Subject> element of the query identify the
    assertions that may be returned.
*/
type AuthzDecisionQuery struct {
	XMLName xml.Name `xml:"samlp:AuthzDecisionQuery"`

	// A URI reference indicating the resource for which authorization is requested.
	Resource string `xml:",attr,omitempty"`

	// The actions for which authorization is requested. For more information on this element, see
	// Section 2.7.4.2.
	Actions []Action `xml:"Action,omitempty"`

	// A set of assertions that the SAML authority MAY rely on in making its authorization decision.
	// For more information on this element, see Section 2.7.4.3.
	Evidence *Evidence `xml:",omitempty"`

	SubjectQuery
}

/*
The <Response> message element is used when a response consists of a list of zero or more
assertions that satisfy the request.

In response to a SAML-defined query message, every assertion returned by a SAML authority MUST
contain a <saml:Subject> element that strongly matches the <saml:Subject> element found in the query.

A <saml:Subject> element S1 strongly matches S2 if and only if the following two conditions both apply:
  - If S2 includes an identifier element (<BaseID>, <NameID>, or <EncryptedID>), then S1 MUST include
    an identical identifier element, but the element MAY be encrypted (or not) in either S1 or S2. In
    other words, the decrypted form of the identifier MUST be identical in S1 and S2. "Identical" means
    that the identifier element's content and attribute values MUST be the same. An encrypted identifier
    will be identical to the original according to this definition, once decrypted.
  - If S2 includes one or more <saml:SubjectConfirmation> elements, then S1 MUST include at least one
    <saml:SubjectConfirmation> element such that S1 can be confirmed in the manner described by at least
    one <saml:SubjectConfirmation> element in S2.

As an example of what is and is not permitted, S1 could contain a <saml:NameID> with a particular
Format value, and S2 could contain a <saml:EncryptedID> element that is the result of encrypting
S1's <saml:NameID> element. However, S1 and S2 cannot contain a <saml:NameID> element with
different Format values and element content, even if the two identifiers are considered to refer to the
same principal.

If the SAML authority cannot provide an assertion with any statements satisfying the constraints
expressed by a query or assertion reference, the <Response> element MUST NOT contain an
<Assertion> element and MUST include a <StatusCode> element with the value
urn:oasis:names:tc:SAML:2.0:status:Success.

All other processing rules associated with the underlying request and response messages MUST be
observed.
*/
type Response struct {
	XMLName xml.Name `xml:"samlp:Response"`

	// Specifies an assertion by value. See Section 2.3.3 for more information.
	Assertions []Assertion `xml:"Assertion"`

	// Specifies an encrypted assertion by value. See Section 2.3.3 for more information.
	EncryptedAssertions []EncryptedAssertion `xml:"EncryptedAssertion"`

	StatusResponseType
}

// To request that an identity provider issue an assertion with an authentication statement,
// a presenter authenticates to that identity provider (or relies on an existing security context)
// and sends it an <AuthnRequest> message that describes the properties that the resulting
// assertion needs to have to satisfy its purpose. Among these properties may be information that
// relates to the content of the assertion and/or information that relates to how the resulting
// <Response> message should be delivered to the requester. The process of authentication of the
// presenter may take place before, during, or after the initial delivery of the <AuthnRequest> message.
//
// The requester might not be the same as the presenter of the request if, for example, the requester
// is a relying party that intends to use the resulting assertion to authenticate or authorize the
// requested subject so that the relying party can decide whether to provide a service.
//
// The <AuthnRequest> message SHOULD be signed or otherwise authenticated and integrity protected by
// the protocol binding used to deliver the message.
type AuthnRequest struct {
	XMLName xml.Name `xml:"samlp:AuthnRequest"`

	// Specifies the requested subject of the resulting assertion(s). This may include one or more
	// <saml:SubjectConfirmation> elements to indicate how and/or by whom the resulting assertions
	// can be confirmed. For more information on this element, see Section 2.4.
	//
	// If entirely omitted or if no identifier is included, the presenter of the message is presumed
	// to be the requested subject. If no <saml:SubjectConfirmation> elements are included, then the
	// presenter is presumed to be the only attesting entity required and the method is implied by
	// the profile of use and/or the policies of the identity provider.
	Subject *Subject `xml:",omitempty"`

	// Specifies constraints on the name identifier to be used to represent the requested subject.
	// If omitted, then any type of identifier supported by the identity provider for the requested
	// subject can be used, constrained by any relevant deployment-specific policies, with respect
	// to privacy, for example.
	NameIDPolicy *NameIDPolicy `xml:",omitempty"`

	// Specifies the SAML conditions the requester expects to limit the validity and/or use of the
	// resulting assertion(s). The responder MAY modify or supplement this set as it deems
	// necessary. The information in this element is used as input to the process of constructing
	// the assertion, rather than as conditions on the use of the request itself. (For more
	// information on this element, see Section 2.5.)
	Conditions *Conditions `xml:",omitempty"`

	// Specifies the requirements, if any, that the requester places on the authentication context
	// that applies to the responding provider's authentication of the presenter. See Section
	// 3.3.2.2.1 for processing rules regarding this element.
	RequestedAuthnContext *RequestedAuthnContext `xml:",omitempty"`

	// Specifies a set of identity providers trusted by the requester to authenticate the presenter,
	// as well as limitations and context related to proxying of the <AuthnRequest> message to
	// subsequent identity providers by the responder.
	Scoping *Scoping `xml:",omitempty"`

	// A Boolean value. If "true", the identity provider MUST authenticate the presenter directly
	// rather than rely on a previous security context. If a value is not provided, the default is
	// "false". However, if both ForceAuthn and IsPassive are "true", the identity provider MUST NOT
	// freshly authenticate the presenter unless the constraints of IsPassive can be met.
	ForceAuthn bool `xml:",attr,omitempty"`

	// A Boolean value. If "true", the identity provider and the user agent itself MUST NOT visibly
	// take control of the user interface from the requester and interact with the presenter in a
	// noticeable fashion. If a value is not provided, the default is "false".
	IsPassive bool `xml:",attr,omitempty"`

	// Indirectly identifies the location to which the <Response> message should be returned to the
	// requester. It applies only to profiles in which the requester is different from the
	// presenter, such as the Web Browser SSO profile in [SAMLProf]. The identity provider MUST have
	// a trusted means to map the index value in the attribute to a location associated with the
	// requester. [SAMLMeta] provides one possible mechanism. If omitted, then the identity provider
	// MUST return the <Response> message to the default location associated with the requester for
	// the profile of use. If the index specified is invalid, then the identity provider MAY return
	// an error <Response> or it MAY use the default location. This attribute is mutually exclusive
	// with the AssertionConsumerServiceURL and ProtocolBinding attributes.
	AssertionConsumerServiceIndex *int `xml:",attr,omitempty"`

	// Specifies by value the location to which the <Response> message MUST be returned to the
	// requester. The responder MUST ensure by some means that the value specified is in fact
	// associated with the requester. [SAMLMeta] provides one possible mechanism; signing the
	// enclosing <AuthnRequest> message is another. This attribute is mutually exclusive with the
	// AssertionConsumerServiceIndex attribute and is typically accompanied by the ProtocolBinding
	// attribute.
	AssertionConsumerServiceURL string `xml:",attr,omitempty"`

	// A URI reference that identifies a SAML protocol binding to be used when returning the
	// <Response> message. See [SAMLBind] for more information about protocol bindings and URI
	// references defined for them. This attribute is mutually exclusive with the
	// AssertionConsumerServiceIndex attribute and is typically accompanied by the
	// AssertionConsumerServiceURL attribute.
	ProtocolBinding Binding `xml:",attr,omitempty"`

	// Indirectly identifies information associated with the requester describing the SAML
	// attributes the requester desires or requires to be supplied by the identity provider in the
	// <Response> message. The identity provider MUST have a trusted means to map the index value in
	// the attribute to information associated with the requester. [SAMLMeta] provides one possible
	// mechanism. The identity provider MAY use this information to populate one or more
	// <saml:AttributeStatement> elements in the assertion(s) it returns.
	AttributeConsumingServiceIndex *int `xml:",attr,omitempty"`

	// Specifies the human-readable name of the requester for use by the presenter's user agent or
	// the identity provider.
	ProviderName string `xml:",attr,omitempty"`

	RequestAbstractType
}

// The <NameIDPolicy> element tailors the name identifier in the subjects of assertions
// resulting from an <AuthnRequest>.
type NameIDPolicy struct {
	XMLName xml.Name `xml:"samlp:NameIDPolicy"`

	// Specifies the URI reference corresponding to a name identifier format defined in this or
	// another specification (see Section 8.3 for examples). The additional value of
	// urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted is defined specifically for use within
	// this attribute to indicate a request that the resulting identifier be encrypted.
	//
	// If the Format value is omitted or set to
	// urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified, then the identity provider is free to
	// return any kind of identifier, subject to any additional constraints due to the content of
	// this element or the policies of the identity provider or principal.
	//
	// The special Format value urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted indicates that
	// the resulting assertion(s) MUST contain <EncryptedID> elements instead of plaintext. The
	// underlying name identifier's unencrypted form can be of any type supported by the identity
	// provider for the requested subject.
	//
	// Regardless of the Format in the <NameIDPolicy>, the identity provider MAY return an
	// <EncryptedID> in the resulting assertion subject if the policies in effect at the identity
	// provider (possibly specific to the service provider) require that an encrypted identifier be
	// used.
	//
	// Note that if the requester wishes to permit the identity provider to establish a new
	// identifier for the principal if none exists, it MUST include this element with the
	// AllowCreate attribute set to "true". Otherwise, only a principal for whom the identity
	// provider has previously established an identifier usable by the requester can be
	// authenticated successfully. This is primarily useful in conjunction with the
	// urn:oasis:names:tc:SAML:2.0:nameid-format:persistent Format value (see Section 8.3.7).
	Format NameIdFormat `xml:",attr,omitempty"`

	// Optionally specifies that the assertion subject's identifier be returned (or created) in the
	// namespace of a service provider other than the requester, or in the namespace of an
	// affiliation group of service providers. See for example the definition of
	// urn:oasis:names:tc:SAML:2.0:nameid-format:persistent in Section 8.3.7.
	SPNameQualifier string `xml:",attr,omitempty"`

	// A Boolean value used to indicate whether the identity provider is allowed, in the course of
	// fulfilling the request, to create a new identifier to represent the principal. Defaults to
	// "false". When "false", the requester constrains the identity provider to only issue an
	// assertion to it if an acceptable identifier for the principal has already been established.
	// Note that this does not prevent the identity provider from creating such identifiers outside
	// the context of this specific request (for example, in advance for a large number of
	// principals).
	AllowCreate bool `xml:",attr,omitempty"`
}

// The <Scoping> element specifies the identity providers trusted by the requester to authenticate the
// presenter, as well as limitations and context related to proxying of the <AuthnRequest> message to
// subsequent identity providers by the responder.
//
// In profiles specifying an active intermediary, the intermediary MAY examine the list and return a
// <Response> message with an error <Status> and a second-level <StatusCode> of
// urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP or
// urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP if it cannot contact or does not support any of
// the specified identity providers.
type Scoping struct {
	XMLName xml.Name `xml:"samlp:Scoping"`

	// Specifies the number of proxying indirections permissible between the identity provider that
	// receives this <AuthnRequest> and the identity provider who ultimately authenticates the
	// principal. A count of zero permits no proxying, while omitting this attribute expresses no
	// such restriction.
	ProxyCount *int `xml:",attr,omitempty"`

	// An advisory list of identity providers and associated information that the requester deems
	// acceptable to respond to the request.
	IDPList IDPList `xml:",omitempty"`

	// Identifies the set of requesting entities on whose behalf the requester is acting. Used to
	// communicate the chain of requesters when proxying occurs, as described in Section 3.4.1.5.
	// See Section 8.3.6 for a description of entity identifiers.
	RequesterIDs []string `xml:"RequesterID,omitempty"`
}

// The <IDPList> element specifies the identity providers trusted by the requester to authenticate the presenter.
type IDPList struct {
	XMLName xml.Name `xml:"samlp:IDPList"`

	// Information about a single identity provider.
	IDPEntries []IDPEntry `xml:"samlp:IDPEntry,omitempty"`

	// If the <IDPList> is not complete, using this element specifies a URI reference that can be
	// used to retrieve the complete list. Retrieving the resource associated with the URI MUST
	// result in an XML instance whose root element is an <IDPList> that does not itself contain a
	// <GetComplete> element.
	GetCompleteUri string `xml:"samlp:GetComplete,omitempty"`
}

// GetCompleteList updates the list of items to match the
// complete list from the specified uri if it is set
func (l *IDPList) GetCompleteList() error {
	if l.GetCompleteUri == "" {
		return nil
	}

	resp, err := http.DefaultClient.Get(l.GetCompleteUri)
	if err != nil {
		return err
	}

	var body []byte
	if _, err = resp.Body.Read(body); err != nil {
		return err
	}

	// use a temporary list instead of unmarshalling to the
	// current item as we don't want to lose everything on
	// failure
	var list IDPList
	if err := xml.Unmarshal(body, &list); err != nil {
		return err
	}

	l.IDPEntries = list.IDPEntries
	return nil
}

// The <IDPEntry> element specifies a single identity provider trusted by the requester to authenticate the presenter.
type IDPEntry struct {
	XMLName xml.Name `xml:"samlp:IDPEntry"`

	// The unique identifier of the identity provider. See Section 8.3.6 for a description of such
	// identifiers.
	ProviderID string `xml:",attr"`

	// A human-readable name for the identity provider.
	Name string `xml:",attr,omitempty"`

	// A URI reference representing the location of a profile-specific endpoint supporting the
	// authentication request protocol. The binding to be used must be understood from the profile
	// of use.
	Location URI `xml:"Loc,attr,omitempty"`
}

// The <ArtifactResolve> message is used to request that a SAML protocol message be returned in an
// <ArtifactResponse> message by specifying an artifact that represents the SAML protocol message.
// The original transmission of the artifact is governed by the specific protocol binding that is being used; see
// [SAMLBind] for more information on the use of artifacts in bindings.
//
// The <ArtifactResolve> message SHOULD be signed or otherwise authenticated and integrity
// protected by the protocol binding used to deliver the message.
type ArtifactResolve struct {
	XMLName xml.Name `xml:"samlp:ArtifactResolve"`

	// The artifact value that the requester received and now wishes to translate into the protocol
	// message it represents. See [SAMLBind] for specific artifact format information.
	Artifact string

	RequestAbstractType
}

// The recipient of an <ArtifactResolve> message MUST respond with an <ArtifactResponse>
// message element. This element is of complex type ArtifactResponseType, which extends
// StatusResponseType with a single optional wildcard element corresponding to the SAML protocol
// message being returned. This wrapped message element can be a request or a response.
//
// The <ArtifactResponse> message SHOULD be signed or otherwise authenticated and integrity
// protected by the protocol binding used to deliver the message.
type ArtifactResponse struct {
	XMLName  xml.Name `xml:"samlp:ArtifactResponse"`
	Children []Node   `xml:",any,omitempty"`

	StatusResponseType
}

// A provider sends a <ManageNameIDRequest> message to inform the recipient of a changed name
// identifier or to indicate the termination of the use of a name identifier.
//
// The <ManageNameIDRequest> message SHOULD be signed or otherwise authenticated and integrity
// protected by the protocol binding used to deliver the message.
type ManageNameIDRequest struct {
	XMLName xml.Name `xml:"samlp:ManageNameIDRequest"`

	// The name identifier and associated descriptive data (in plaintext form) that specify the
	// principal as currently recognized by the identity and service providers prior to this
	// request. (For more information, see Section 2.2.)
	NameID *NameID `xml:",omitempty"`

	// The name identifier and associated descriptive data (in encrypted form) that specify the
	// principal as currently recognized by the identity and service providers prior to this
	// request. (For more information, see Section 2.2.)
	EncryptedID *EncryptedID `xml:",omitempty"`

	// The new identifier value (in plaintext form) to be used when communicating with the
	// requesting provider concerning this principal, or an indication that the use of the old
	// identifier has been terminated. In the former case, if the requester is the service provider,
	// the new identifier MUST appear in subsequent <NameID> elements in the SPProvidedID attribute.
	// If the requester is the identity provider, the new value will appear in subsequent <NameID>
	// elements as the element's content.
	NewID string `xml:",omitempty"`

	// The new identifier value (in encrypted form) to be used when communicating with the
	// requesting provider concerning this principal.
	//
	// If the requester is the service provider, the new identifier MUST appear in subsequent
	// <NameID> elements in the SPProvidedID attribute.
	//
	// If the requester is the identity provider, the new value will appear in subsequent <NameID>
	// elements as the element's content.
	NewEncryptedID *EncryptedElementType `xml:",omitempty"`

	// An indication that the use of the old identifier has been terminated.
	Terminate bool `xml:",omitempty"`

	RequestAbstractType
}

// The recipient of a <ManageNameIDRequest> message MUST respond with a <ManageNameIDResponse>
// message, which is of type StatusResponseType with no additional content.
//
// The <ManageNameIDResponse> message SHOULD be signed or otherwise authenticated and integrity
// protected by the protocol binding used to deliver the message.
type ManageNameIDResponse struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ManageNameIDResponse"`
	StatusResponseType
}

// A session participant or session authority sends a <LogoutRequest> message to indicate that a session
// has been terminated.
// The <LogoutRequest> message SHOULD be signed or otherwise authenticated and integrity protected
// by the protocol binding used to deliver the message.
type LogoutRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`

	// The time at which the request expires, after which the recipient may discard the message. The
	// time value is encoded in UTC, as described in Section 1.3.3.
	NotOnOrAfter time.Time `xml:",attr,omitempty"`

	// An indication of the reason for the logout, in the form of a URI reference.
	Reason LogoutReason `xml:",attr,omitempty"`

	// The identifier and associated attributes (in plaintext form) that specify the principal as
	// currently recognized by the identity and service providers prior to this request. (For more
	// information on this element, see Section 2.2.)
	BaseID *BaseID `xml:",omitempty"`

	// The identifier and associated attributes (in plaintext form) that specify the principal as
	// currently recognized by the identity and service providers prior to this request. (For more
	// information on this element, see Section 2.2.)
	NameID *NameID `xml:",omitempty"`

	// The identifier and associated attributes (in encrypted form) that specify the principal as
	// currently recognized by the identity and service providers prior to this request. (For more
	// information on this element, see Section 2.2.)
	EncryptedID *EncryptedID `xml:",omitempty"`

	// The identifier that indexes this session at the message recipient.
	SessionIndexes []string `xml:"SessionIndex,omitempty"`

	RequestAbstractType
}

// The recipient of a <LogoutRequest> message MUST respond with a <LogoutResponse> message, of
// type StatusResponseType, with no additional content specified.
//
// The <LogoutResponse> message SHOULD be signed or otherwise authenticated and integrity
// protected by the protocol binding used to deliver the message.
type LogoutResponse struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`

	StatusResponseType
}

// To request an alternate name identifier for a principal from an identity provider, a requester
// sends an <NameIDMappingRequest> message.
//
// The message SHOULD be signed or otherwise authenticated and integrity protected by the protocol
// binding used to deliver the message.
type NameIDMappingRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDMappingRequest"`

	// The identifier and associated descriptive data that specify the principal as currently
	// recognized by the requester and the responder. (For more information on this element, see
	// Section 2.2.)
	BaseID *BaseID `xml:",omitempty"`

	// The identifier and associated descriptive data that specify the principal as currently
	// recognized by the requester and the responder. (For more information on this element, see
	// Section 2.2.)
	NameID *NameID `xml:",omitempty"`

	// The identifier and associated descriptive data that specify the principal as currently
	// recognized by the requester and the responder. (For more information on this element, see
	// Section 2.2.)
	EncryptedID *EncryptedID `xml:",omitempty"`

	// The requirements regarding the format and optional name qualifier for the identifier to be
	// returned.
	NameIDPolicy NameIDPolicy `xml:",omitempty"`

	RequestAbstractType
}

// The recipient of a <NameIDMappingRequest> message MUST respond with a <NameIDMappingResponse> message.
//
// The message SHOULD be signed or otherwise authenticated and integrity protected by the protocol
// binding used to deliver the message.
type NameIDMappingResponse struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDMappingResponse"`

	// The identifier and associated attributes that specify the principal in the manner requested,
	// usually in encrypted form. (For more information on this element, see Section 2.2.)
	NameID *NameID `xml:",omitempty"`

	// The identifier and associated attributes that specify the principal in the manner requested,
	// usually in encrypted form. (For more information on this element, see Section 2.2.)
	EncryptedID *EncryptedID `xml:",omitempty"`

	StatusResponseType
}
