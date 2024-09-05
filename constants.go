package saml

// Prefixes
const (
	NamespaceSAMLPrefix  = "saml:"
	NamespaceSAMLPPrefix = "samlp:"

	prefixSAML    = "urn:oasis:names:tc:SAML:"
	prefixSAML1   = prefixSAML + "1.0:"
	prefixSAML1_1 = prefixSAML + "1.1:"
	prefixSAML2   = prefixSAML + "2.0:"
)

// Protocols
const (
	NamespaceSamlp = NamespaceSamlp2

	NamespaceSamlp1   Protocol = prefixSAML1 + "protocol"   // The namespace for the SAML 1.0 protocol.
	NamespaceSamlp1_1 Protocol = prefixSAML1_1 + "protocol" // The namespace for the SAML 1.1 protocol.
	NamespaceSamlp2   Protocol = prefixSAML2 + "protocol"   // The namespace for the SAML 2.0 protocol.
)

type AuthenticationContext string

const (
	// Password authentication context.
	AuthenticationContextPassword AuthenticationContext = prefixSAML2 + "ac:classes:Password"

	// PasswordProtectedTransport authentication context.
	AuthenticationContextPasswordProtectedTransport AuthenticationContext = prefixSAML2 + "ac:classes:PasswordProtectedTransport"

	// Unspecified authentication context.
	AuthenticationContextUnspecified AuthenticationContext = prefixSAML2 + "ac:classes:unspecified"
)

type AttributeIdentifier string

const (
	// Pairwise identifier attribute
	AttributeIdentifierPairwiseId AttributeIdentifier = prefixSAML + "attribute:pairwise-id"

	// Subject identifier attribute
	AttributeIdentifierSubjectId AttributeIdentifier = prefixSAML + "attribute:subject-id"
)

type Binding string

const (
	// The URN for the Holder-of-Key Web Browser SSO Profile binding
	BindingHokSso Binding = prefixSAML2 + "profiles:holder-of-key:SSO:browser"

	// The URN for the HTTP-ARTIFACT binding.
	BindingHttpArtifact Binding = prefixSAML2 + "bindings:HTTP-Artifact"

	// The URN for the HTTP-POST binding.
	BindingHttpPost Binding = prefixSAML2 + "bindings:HTTP-POST"

	// The URN for the HTTP-Redirect binding.
	BindingHttpRedirect Binding = prefixSAML2 + "bindings:HTTP-Redirect"

	// The URN for the DEFLATE url encoding
	BindingHttpRedirectDeflate Binding = prefixSAML2 + "bindings:URL-Encoding:DEFLATE"

	// The URN for the IdP Discovery Protocol binding
	BindingIdpDisc Binding = prefixSAML + "profiles:SSO:idp-discovery-protocol"

	// The URN for the PAOS binding.
	BindingPaos Binding = prefixSAML2 + "bindings:PAOS"

	// The URN for the SOAP binding.
	BindingSoap Binding = prefixSAML2 + "bindings:SOAP"

	// The URN for the URI binding.
	BindingUri Binding = prefixSAML2 + "bindings:URI"
)

type ConfirmationMethod string

const (
	// Bearer subject confirmation method.
	ConfirmationMethodBearer ConfirmationMethod = prefixSAML2 + "cm:bearer"

	// Holder-of-Key subject confirmation method.
	ConfirmationMethodHoK ConfirmationMethod = prefixSAML2 + "cm:holder-of-key"

	// Sender Vouches subject confirmation method.
	ConfirmationMethodSenderVouches ConfirmationMethod = prefixSAML2 + "cm:sender-vouches"
)

type Consent string

const (
	// Indicates that a principal’s consent has been explicitly obtained by the issuer of the message during the
	// action that initiated the message.
	ConsentExplicit Consent = prefixSAML2 + "consent:current-explicit"

	// Indicates that a principal’s consent has been implicitly obtained by the issuer of the message during the
	// action that initiated the message, as part of a broader indication of consent.
	// Implicit consent is typically more proximal to the action in time and presentation than prior consent,
	// such as part of a session of activities.
	ConsentImplicit Consent = prefixSAML2 + "consent:current-implicit"

	// Indicates that the issuer of the message does not believe that they need to obtain or report consent.
	ConsentInapplicable Consent = prefixSAML2 + "consent:inapplicable"

	// Indicates that a principal’s consent has been obtained by the issuer of the message.
	ConsentObtained Consent = prefixSAML2 + "consent:obtained"

	// Indicates that a principal’s consent has been obtained by the issuer of the message at some point prior to
	// the action that initiated the message.
	ConsentPrior Consent = prefixSAML2 + "consent:prior"

	// Indicates that the issuer of the message did not obtain consent.
	ConsentUnavailable Consent = prefixSAML2 + "consent:unavailable"

	// No claim as to principal consent is being made.
	ConsentUnspecified Consent = prefixSAML2 + "consent:unspecified"
)

const (
	EptiUrnMace = "urn:mace:dir:attribute-def:eduPersonTargetedID"

	EptiUrnOid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
)

type LogoutReason string

const (
	// LogoutRequest Reason - admin wishes to terminate the session
	LogoutReasonAdmin LogoutReason = prefixSAML2 + "logout:admin"

	// LogoutRequest Reason - user wishes to terminate the session
	LogoutReasonUser LogoutReason = prefixSAML2 + "logout:user"

	// LogoutRequest Reason - global session timeout exceeded
	LogoutReasonGlobalTimeout LogoutReason = prefixSAML2 + "logout:global-timeout"

	// LogoutRequest Reason - mutually agreed upon session timeout exceeded
	LogoutReasonSpTimeout LogoutReason = prefixSAML2 + "logout:sp-timeout"
)

type AttributeNameFormat string

const (
	// The class of strings acceptable as the attribute name MUST be drawn from the set of values belonging to
	// the primitive type xs:Name as defined in [Schema2] Section 3.3.6. See [SAMLProf] for attribute profiles
	// that make use of this identifier.
	AttributeNameFormatBasic AttributeNameFormat = prefixSAML2 + "attrname-format:basic"

	// The interpretation of the attribute name is left to individual implementations.
	AttributeNameFormatUnspecified AttributeNameFormat = prefixSAML2 + "attrname-format:unspecified"

	// The attribute name follows the convention for URI references [RFC 2396], for example as used in XACML
	// [XACML] attribute identifiers. The interpretation of the URI content or naming scheme is application-
	// specific. See [SAMLProf] for attribute profiles that make use of this identifier.
	AttributeNameFormatUri AttributeNameFormat = prefixSAML2 + "attrname-format:uri"
)

type NameIdFormat string

const (
	// Email address NameID format.
	NameIdFormatEmailAddress NameIdFormat = prefixSAML1_1 + "nameid-format:emailAddress"

	// Encrypted NameID format.
	NameIdFormatEncrypted NameIdFormat = prefixSAML2 + "nameid-format:encrypted"

	// Entity NameID format.
	NameIdFormatEntity NameIdFormat = prefixSAML2 + "nameid-format:entity"

	// Kerberos Principal Name NameID format.
	NameIdFormatKerberos NameIdFormat = prefixSAML2 + "nameid-format:kerberos"

	// Persistent NameID format.
	NameIdFormatPersistent NameIdFormat = prefixSAML2 + "nameid-format:persistent"

	// Transient NameID format.
	NameIdFormatTransient NameIdFormat = prefixSAML2 + "nameid-format:transient"

	// Unspecified NameID format.
	NameIdFormatUnspecified NameIdFormat = prefixSAML1_1 + "nameid-format:unspecified"

	// Windows Domain Qualifier Name NameID format.
	NameIdFormatWindowsDomainQualifiedName NameIdFormat = prefixSAML1_1 + "nameid-format:WindowsDomainQualifiedName"

	// X509 Subject Name NameID format.
	NameIdFormatX509SubjectName NameIdFormat = prefixSAML1_1 + "nameid-format:X509SubjectName"
)

// Namespaces
const (
	// The namespace for the SAML 2 metadata Algorithm Support profile
	NamespaceAlgSupport = prefixSAML + "metadata:algsupport"

	// The namespace for the ECP protocol.
	NamespaceEcp = prefixSAML2 + "profiles:SSO:ecp"

	// The namespace for the EduID metadata protocol.
	NamespaceEMetadata = "http://eduid.cz/schema/metadata/1.0"

	// The namespace for the SAML 2 HoK Web Browser SSO Profile.
	NamespaceHok = prefixSAML2 + "profiles:holder-of-key:SSO:browser"

	// The namespace for the SAML 2 metadata.
	NamespaceMetadata = prefixSAML2 + "metadata"

	// The namespace for the SAML 2 Metadata Extensions for Registration and Publication Information.
	NamespaceMetadataRpi = prefixSAML + "metadata:rpi"

	// The namespace for the SAML 2 Metadata Extensions for Login and Discovery User Interface Version.
	NamespaceMetadataUi = prefixSAML + "metadata:ui"

	// The namespace for the SAML 2 metadata attributes.
	NamespaceMetadataAttr = prefixSAML + "metadata:attribute"

	// The namespace for the Shibboleth Metadata profile.
	NamespaceShibbolethMetadata = "urn:mace:shibboleth:metadata:1.0"

	// The namespace for the SAML 2 assertions.
	NamespaceSaml = prefixSAML2 + "assertion"

	// The namespace for the SOAP protocol.
	NamespaceSoap = "http://schemas.xmlsoap.org/soap/envelope/"

	// The namespace for the IDP Discovery protocol
	NamespaceIdpDisc = prefixSAML + "profiles:SSO:idp-discovery-protocol"
)

type SamlStatus string

const (
	// The status namespace
	StatusPrefix = prefixSAML2 + "status:"

	// The request could not be performed due to an error on the part of the requester.
	//
	// Top-level status code.
	StatusRequester SamlStatus = StatusPrefix + "Requester"

	// The request could not be performed due to an error on the part of the SAML responder or SAML authority.
	//
	// Top-level status code.
	StatusResponder SamlStatus = StatusPrefix + "Responder"

	// The request succeeded. Additional information MAY be returned in the <StatusMessage>
	// and/or <StatusDetail> elements.
	//
	// Top-level status code.
	StatusSuccess SamlStatus = StatusPrefix + "Success"

	// The SAML responder could not process the request because the version of the request message was incorrect.
	//
	// Top-level status code.
	StatusVersionMismatch SamlStatus = StatusPrefix + "VersionMismatch"

	// The responding provider was unable to successfully authenticate the principal.
	//
	// Second-level status code.
	StatusAuthnFailed SamlStatus = StatusPrefix + "AuthnFailed"

	// Unexpected or invalid content was encountered within a <saml:Attribute> or <saml:AttributeValue> element.
	//
	// Second-level status code.
	StatusInvalidAttr SamlStatus = StatusPrefix + "InvalidAttrNameOrValue"

	// The responding provider cannot or will not support the requested name identifier policy.
	//
	// Second-level status code.
	StatusInvalidNameidPolicy SamlStatus = StatusPrefix + "InvalidNameIDPolicy"

	// The specified authentication context requirements cannot be met by the responder.
	//
	// Second-level status code.
	StatusNoAuthnContext SamlStatus = StatusPrefix + "NoAuthnContext"

	// Used by an intermediary to indicate that none of the supported identity provider <Loc> elements in an
	// <IDPList> can be resolved or that none of the supported identity providers are available.
	//
	// Second-level status code.
	StatusNoAvailableIdp SamlStatus = StatusPrefix + "NoAvailableIDP"

	// Indicates the responding provider cannot authenticate the principal passively, as has been requested.
	//
	// Second-level status code.
	StatusNoPassive SamlStatus = StatusPrefix + "NoPassive"

	// Used by an intermediary to indicate that none of the identity providers in an <IDPList> are
	// supported by the intermediary.
	//
	// Second-level status code.
	StatusNoSupportedIdp SamlStatus = StatusPrefix + "NoSupportedIDP"

	// Used by a session authority to indicate to a session participant that it was not able to propagate logout
	// to all other session participants.
	//
	// Second-level status code.
	StatusPartialLogout SamlStatus = StatusPrefix + "PartialLogout"

	// Indicates that a responding provider cannot authenticate the principal directly and is not permitted
	// to proxy the request further.
	//
	// Second-level status code.
	StatusProxyCountExceeded SamlStatus = StatusPrefix + "ProxyCountExceeded"

	// The SAML responder or SAML authority is able to process the request but has chosen not to respond.
	// This status code MAY be used when there is concern about the security context of the request message or
	// the sequence of request messages received from a particular requester.
	//
	// Second-level status code.
	StatusRequestDenied SamlStatus = StatusPrefix + "RequestDenied"

	// The SAML responder or SAML authority does not support the request.
	//
	// Second-level status code.
	StatusRequestUnsupported SamlStatus = StatusPrefix + "RequestUnsupported"

	// The SAML responder cannot process any requests with the protocol version specified in the request.
	//
	// Second-level status code.
	StatusRequestVersionDeprecated SamlStatus = StatusPrefix + "RequestVersionDeprecated"

	// The SAML responder cannot process the request because the protocol version specified in the request message
	// is a major upgrade from the highest protocol version supported by the responder.
	//
	// Second-level status code.
	StatusRequestVersionTooHigh SamlStatus = StatusPrefix + "RequestVersionTooHigh"

	// The SAML responder cannot process the request because the protocol version specified in the request message
	// is too low.
	//
	// Second-level status code.
	StatusRequestVersionTooLow SamlStatus = StatusPrefix + "RequestVersionTooLow"

	// The resource value provided in the request message is invalid or unrecognized.
	//
	// Second-level status code.
	StatusResourceNotRecognized SamlStatus = StatusPrefix + "ResourceNotRecognized"

	// The response message would contain more elements than the SAML responder is able to return.
	//
	// Second-level status code.
	StatusTooManyResponses SamlStatus = StatusPrefix + "TooManyResponses"

	// An entity that has no knowledge of a particular attribute profile has been presented with an attribute
	// drawn from that profile.
	//
	// Second-level status code.
	StatusUnknownAttrProfile SamlStatus = StatusPrefix + "UnknownAttrProfile"

	// The responding provider does not recognize the principal specified or implied by the request.
	//
	// Second-level status code.
	StatusUnknownPrincipal SamlStatus = StatusPrefix + "UnknownPrincipal"

	// The SAML responder cannot properly fulfill the request using the protocol binding specified in the request.
	//
	// Second-level status code.
	StatusUnsupportedBinding SamlStatus = StatusPrefix + "UnsupportedBinding"
)

const (
	// The maximum size for any entity id as per specification
	EntityIdMaxLength = 1024

	// The maximum size for any entity id as per SAML2INT-specification
	Saml2intEntityIdMaxLength = 256

	// The format to express a timestamp in SAML2
	DatetimeFormat = "2006-01-02T15:04:05Z" // TODO Check me "Y-m-d\\TH:i:sp"
)

type AssertionValidity int

const (
	AssertionValid AssertionValidity = iota
	AssertionIndeterminate
	AssertionInvalid
)

type DecisionType string

const (
	DecisionTypePermit        DecisionType = "Permit"
	DecisionTypeDeny          DecisionType = "Deny"
	DecisionTypeIndeterminate DecisionType = "Indeterminate"
)

type ContactType string

const (
	ContactTypeTechnical      ContactType = "technical"
	ContactTypeSupport        ContactType = "support"
	ContactTypeAdministrative ContactType = "administrative"
	ContactTypeBilling        ContactType = "billing"
	ContactTypeOther          ContactType = "other"
)

type KeyType string

const (
	KeyTypeEncryption KeyType = "encryption"
	KeyTypeSigning    KeyType = "signing"
)
