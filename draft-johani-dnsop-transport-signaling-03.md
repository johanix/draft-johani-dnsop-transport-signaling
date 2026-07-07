---
title: "Opportunistic Operator based SVCB transport signaling (OOTS)"
abbrev: "DNS Transport Signaling"
docname: draft-johani-dnsop-transport-signaling-03
date: {DATE}
category: std
stream: IETF

ipr: trust200902
area: Internet
workgroup: DNSOP Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - ins: J. Stenstam
    name: Johan Stenstam
    organization: The Swedish Internet Foundation
    country: Sweden
    email: johan.stenstam@internetstiftelsen.se
  - ins: L. Fernandez
    name: Leon Fernandez
    organization: The Swedish Internet Foundation
    country: Sweden
    email: leon.fernandez@internetstiftelsen.se
  - ins: E. Bergström
    name: Erik Bergström
    organization: The Swedish Internet Foundation
    country: Sweden
    email: erik.bergstrom@internetstiftelsen.se
  - ins: P. Homberg
    name: Philip Homberg
    organization: NLnet Labs
    country: Netherlands
    email: philip@nlnetlabs.nl
  - ins: S. Dickinson
    name: Sara Dickinson
    organization: Sinodun IT
    country: United Kingdom
    email: sara@sinodun.com

normative:

informative:

--- abstract

This document proposes an Opportunistic Operator Transport Signaling mechanism
(OOTS) based on SVCB records, to enable operators of authoritative DNS servers
to signal their support for alternative transport protocols (e.g., DNS over TLS
(DoT) and DNS over QUIC (DoQ)). These SVCB records can contain a new
(experimental) SVCB "oots" key which contains fine grained information about
the support for specific transports. This signaling may either be provided
within the Additional section of authoritative DNS responses (Passive mode) or
be the result of direct DNS queries (Probe mode).

Acquiring such SVBC records enables recursive resolvers to then
Opportunistically upgrade connections to the authoritative to encrypted
transports, thereby improving privacy, security, and performance for subsequent
interactions.

--- middle

# Introduction

The Domain Name System (DNS) primarily relies on UDP and TCP for communication
between resolvers and authoritative servers. While these protocols are
well-established, there is a growing interest in leveraging modern encrypted
transport protocols like DNS over TLS (DoT) {{!RFC7858}} and DNS over QUIC
(DoQ) {{!RFC9250}} to enhance privacy, security, and performance.

'Unilateral Opportunistic Deployment of Encrypted Recursive-to-Authoritative
DNS' {{!RFC9539}} describes a mechanism for how recursive resolvers can probe
authoritative servers to discover if port 853 is open in order to
Opportunistically upgrade to an encrypted transport. However that mechanism has
not gained widespread deployment due to a number of limitations and a
reluctance of authoritative operators to open port 853 with no signaling
mechanisms available. 

Here we propose an alternative mechanism that enables a more controlled
deployment of Opportunistic encrypted transports: Opportunistic Operator
Transport Signaling mechanism (OOTS). This improves on the Opportunistic (but
blind) testing of alternative transports suggested in {{RFC9539}} by providing
a mechanism by which a responding authoritative server may signal what
alternative transports it supports, along with additional information about
each transport.

This signaling is based on SVCB records {{!RFC9460}} which can contain a new
(experimental) SVCB "oots" key that contains fine grained information about the
support for specific transports. These may either be provided within the
Additional section of authoritative DNS responses (Passive mode) or be the
result of direct DNS queries (Probe mode). 

The former, "Passive mode", is enabled by use of a new EDNS(0) option and allows
resolvers to discover alternative transports efficiently with no additional queries.

The latter, "Probe mode", enables recursive resolvers willing to expend
additional overhead to obtain SVCB records via direct queries, and to
(optionally) directly discover if DNSSEC signed SVCB records exist.

Neither mode requires changes to the parent zone. Passive mode may require
additional SVCB alias mode records for certain delegation patterns. 

On obtaining such SVBC records recursive resolvers can then
Opportunistically upgrade connections to the authoritative to and encrypted
transport contained within the signaled information.

This specification is expected to evolve over time based on interoperability
testing and experimental deployments. Early work is expected to include
comparing the two modes to see if one or the other is preferable or if both
should be part of the long term solution. Other work will investigate if the
structure of, and the information in, the SVCB "oots" key is useful in practice.

## Structure of the document

{{the-oots-mechanism}} gives an overview of the OOTS mechanism.

{{oots-passive-mode}} describes Passive mode to obtain OOTS SVCB records

{{oots-probe-mode}} describes Probe mode to obtain OOTS SVCB records

{{discovery-of-oots-records}} and {{using-oots-records}} describe how recursive
resolvers may then process and use those records (however they were obtained)
including caching considerations, upgrading to encrypted connections and
optional attempts to authenticate the authoritative server.

The final sections provide a brief comparison with {{?DELEG=I-D.draft-ietf-deleg}} along with Security, Operational
and Privacy considerations.

# Github repo

TO BE REMOVED: This document is being collaborated on in Github at:
[https://github.com/johanix/draft-johani-dnsop-transport-signaling](https://github.com/johanix/draft-johani-dnsop-transport-signaling).
The most recent working version of the document, open issues, etc, should all be
available there.  The authors (gratefully) accept pull requests.


# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals.

General DNS terminology used here follows that defined in {{!RFC9499}}. A short description of a number of relevant terms described there are listed below for context along with new terms used in this document.

* **Authoritative Nameserver (Auth Server):** A DNS server that holds
the authoritative zone data for a specific domain.

* **Recursive Nameserver (Resolver):** A DNS server that processes
user queries, performing iterative lookups to authoritative servers to
resolve domain names.

* **OOTS Passive mode:** Recursive resolvers set the EDNS(0) OOTS Option in a query and authoritative servers supply EDNS(0) OOTS Responses in the Additional section if appropriate.

* **OOTS Probe mode:** Recursive resolvers directly query for SVCB records of authoritative servers and process any "oots" keys in those records

* **SVCB Record:** Service Binding record, as defined in {{!RFC9460}}.

* **SCVB "oots" key:** New experimental Service Parameter Key (SvcParamKey)  key defined in {{!I-D.draft-johani-dnsop-svcb-oots}} which allows an operator to advertise a requested query load for each advertised transport.

* **EDNS(0) OOTS Option:** New EDNS(0) flag that indicates a resolver wishes to receive OOTS SVCB records in the Additional section of the response.

* **EDNS(0) OOTS Response:** An SVCB record included  in the
Additional section of an authoritative DNS response, intended to
signal the responding authoritative nameserver's transport
capabilities.

* **Server Identity:**   **TODO** 

* **Strict and Opportunistic connection modes:** These connection modes are entirely analogous to those defined for stub to recursive connections in
  {{!RFC8310}}. 
   * **Strict** requires both an encrypted and authenticated connection
  to the server based on authentication credentials that were obtained via a
  secure mechanism. Clients MUST hard-fail the connection if this is not possible.
   * **Opportunistic** uses cleartext as the baseline connection,
  with encryption and authentication negotiated and applied to the connection
  when available.


# The OOTS mechanism

The basis of the Opportunistic operator transport signaling (OOTS)
mechanism is the existence of Service Binding records (SVCB RRs) for
authoritative nameservers that offer encrypted transports. The mechanism is
expected to be experimental in nature in the early stages as various details of
the discovery heuristics and signaling mechanism are explored and developed.

## Authoritative Operator SVCB records

Operators publish SVCB records to signal which transports they support on the
nameservers they operate. Using an experimental code point for a new "oots"
SVCB key {{!I-D.draft-johani-dnsop-svcb-oots}}, additional attributes of those transports can be expressed e.g. requested % traffic levels.

Operators can optionally return any relevant SVCB records in the Additional
section of queries that have the OOTS EDNS(0) option set where
they are authoritative for the served zone. This EDNS(0) option indicates that
the recursive resolver is actively requesting the information be returned.

## Recursive Resolvers

Recursive resolvers can discover SVCB records one of two ways:

* **Passive mode**: A recursive resolvers sets the OOTS EDNS(0) option to
  indicate they want to receive SVCB records in the Additional section if they
  are available. A nameservers that is authoritative for the zone in question
  (i.e. managed by the zone operator) returns any SVCB records available for
  the authoritative nameservers when responding to a query with the OOTS EDNS(0)
  option set.

* **Probe mode**: A recursive resolver actively probes for SVCB records for some or
  all of the authoritative nameservers they query.

A recursive resolver can then use the SVCB records to upgrade connections to
encrypted transports, but should honor any attributes of the transports
described in the SVCB records e.g. requested % traffic levels.

## Discovery and Transport Selection

_Discovery heuristics_: The heuristics for doing SVCB discovery are an
implementation decision since they should align with the local resolution logic
in the software implementation. For example, resolvers may perform SVCB
discovery at any time e.g. before sending any queries to an authoritative, in
parallel to sending cleartext queries to the authoritative or at a later time.
In another approach, a resolver may start in Passive mode and subsequently
probe directly for a SVCB binding record in an attempt to obtain a DNSSEC
signed record (if the one obtained via the OOTS Option was not signed).

_Transport selection heuristics_: Similarly, resolvers may attempt connections
over encrypted transports at any time i.e. before sending any queries to the
resolver, in parallel to sending cleartext queries to the resolver or at a
later time after having obtained a SVCB record.

Clearly, from a privacy perspective, is is preferable to use an encrypted
transport as early as possible in the resolution process. But for an
Opportunistic policy, this can and should be balanced with efficient and
reliable query resolution. Capturing data on and developing the details of one
or more strategies for these activities is expected to evolve over time.

## Authenticating connections

Strict and Opportunistic connection policies for stub to recursive connections are described in {{!RFC8310}} and the terms are used analogously here.

The information conveyed by the SVCB records alone (even when DNSSEC signed)
signals only the capabilities of the authoritative nameserver serving the zone.
It does not, therefore, establish a full chain of trust directly to the zone
itself and MUST be considered as insecure. It should not be used as a basis of
a Strict connection policy, only to enable an Opportunistic connection policy.

Since resolvers acquiring a OOTS signal are limited to using an Opportunistic
connection policy, both the discovery and transport selection heuristics
specifics are left as implementation and/or policy decisions for the resolver
operator. However, acquiring such a signal enables resolvers to immediately
apply the local Opportunistically connection policy for the nameserver in
question.

Resolvers may, of course, still validate the certificate presented by the
nameserver and log the result.

## Transport Signaling Attributes

Desirable attributes to signal for each supported protocol include (but are not
limited to):

* Requested % of traffic a resolver should attempt to send over that transport 
* If the service is considered experimental
* ...

**FOR DISCUSSION** What other attributes might be useful?


# OOTS Passive mode 

The core of this mechanism is for an authoritative nameserver to include an
SVCB record containing an "oots" key in the Additional section of its responses
under specific conditions.

This signaling mechanism consists of two steps:

* The first is that a resolver MAY include the new EDNS(0) option that defines
  an OOTS request in a query to an authoritative nameserver.
* The second is the behavior of the authoritative nameserver receiving that
  query which SHOULD include SVCB records in the response if the required
  conditions are met.

##  Design decisions

See {{rationale-for-using-the-additional-section}} for the rationale for using the Additional section for the transport signaling EDNS(0) OOTS Response.

## The EDNS(0) OOTS Option

To provide a mechanism for resolvers to explicitly request to
receive transport signals, this document defines a new EDNS(0)
option called "OOTS". When included in a query, this
option signals to the authoritative server that the resolver
wants to receive transport signals in the response.

The typical use case is to set the EDNS(0) OOTS option when the resolver has no
cached transport signaling information (i.e. the resolver is contacting the
authoritative for the first time or any existing record has expired from the
cache).

The EDNS(0) OOTS option is structured as follows:

~~~
                                              1   1   1   1   1   1
      0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 0: |                            OPTION-CODE                        |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 2: |                           OPTION-LENGTH                       |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
~~~

Field definition details:

OPTION-CODE:
    2 octets / 16 bits (defined in {{!RFC6891}}) contains the value TBD
    for OOTS.

OPTION-LENGTH:
    2 octets / 16 bits (defined in {{!RFC6891}}) contains
    the length of the payload in octets. For the OOTS option,
    this value MUST be 0 as there is no payload.

The OOTS option is designed to be a simple, lightweight
mechanism that can be used to enable transport signaling without
affecting the normal operation of DNS resolution.


## Authoritative Nameserver Behavior

### Trigger Conditions for Including the OOTS SVCB records

An authoritative nameserver SHOULD NOT include OOTS SVCB records in a response
if the EDNS(0) OOTS option was not present in the query.

**NOTE** - During development and prototyping of this specification a valid reason that an experimental deployment might decide to include OOTS SVCB records in all responses is for testing purposes.

#### Condition 1

An authoritative nameserver SHOULD include OOTS SVBC records in the Additional
section and *all* of the following conditions are met:

1. **Presence of the OOTS Option:** The query includes an EDNS(0) OOTS option from the resolver.

1. **NS RRset Presence:** An NS Resource Record Set (RRset) for the
queried zone is present in either the Answer section or the Authority
section of the DNS response.

2. **Self-Identification:** The responding authoritative nameserver's
own Fully Qualified Domain Name (FQDN) (or one of its configured
aliases/identities) is found within the NS RRset mentioned in
condition 1\.

3. **Transport Capability:** The responding authoritative nameserver
supports one or more alternative transport protocols (e.g., DoT, DoH,
DoQ) and is configured to advertise these capabilities.

5. **Availability of RRSIG SVCB:** If the zone in which the nameserver
name is located is signed, only include the SVCB record if it is
possible to also include the corresponding RRSIG SVCB. If the zone with
the nameserver name is unsigned, then include the SVCB even without the
RRSIG.

**TODO**: Discuss - the requirement for the SVCB record to be included only if
it is DNSSEC-signed has the consequence that the DTS transport signal cannot be
present for an unsigned zone using vanity names in the zone for its nameservers.

#### Condition 2

**TODO** 


### Multiple Server Identities

An authoritative nameserver may be known by multiple FQDNs (e.g.,
ns1.example.com, dns.customer.org, ns.cdnprovider.net). To facilitate
condition 2 ("Self-Identification"), authoritative server
implementations MAY include a configuration mechanism (e.g., an
identities list) where operators can list all FQDNs by which the
server is known. This allows the server to correctly identify itself
regardless of the specific name used in the NS RRset.

###  Format of the OOTS SVCB records

The OOTS SVCB records are ones with the following characteristics:

* **OWNER:** The owner name of the SVCB record MUST be the label
  "_dns" followed by the FQDN of the authoritative nameserver itself,
  as identified in the NS RRset that triggered its inclusion (e.g.,
  _dns.ns.dnsprovider.com.).

* **CLASS:** IN (Internet).

* **TYPE:** SVCB.

* **TTL:** The TTL of the SVCB record SHOULD be chosen by the
   authoritative server operator. Choice of TTL is a local configuration
   decision, but unless the supported transports are subject to frequent
   change a value on the order of 24h or more is suggested.

* **SVCB\_PRIORITY:** 1\. The specific priority value is not critical
   for this mechanism, but 1 indicates the highest priority for the
   service.

* **SVCB\_TARGET:** . (root). This indicates that the DNS transport
   capabilities described by the SVCB record refer to the owner name of
   the record.

* **SVCB\_PARAMS:** A set of Service Parameters indicating the
   supported transport protocols. In this document only the "oots"
   parameter is defined, as relevant for signaling transports e.g. 
   DoT (oots=dot:100), DoQ (oots=doq:100) or cleartext DNS (oots=do53:100)

   If any other parameter, including "ipv4hint" and "ipv6hint", is present in the
   SVCB parameter list then it SHOULD be ignored.

**Example 1:**

If ns.dnsprovider.net. responds to a query for www.example.com. and
ns.dnsprovider.net is listed in the NS RRset, it may respond with a
DNS message that contains:

~~~
Header: ...

Answer:
www.example.com.   IN A 1.2.3.4

Authority:
example.com.       IN NS ns1.example.com.
example.com.       IN NS ns.dnsprovider.net.

Additional:
ns.dnsprovider.net. IN A 5.6.7.8
ns.dnsprovider.net. IN RRSIG A ...
_dns.ns.dnsprovider.net. IN SVCB 1 . "oots=doq:100,dot:100,do53:100"
_dns.ns.dnsprovider.net. IN RRSIG SVCB ...
~~~

**TODO**: More examples

<!-- [**TODO**: Short paragraph on needing alias mode SVCB records, or take this discussion out of this description completely?] -->


<!--
### johani: broken example, to be fixed
**Example 2:**

If the signed zone example.com has two nameservers, ns1.example.com and
ns2.example.com, then a possible response from ns2.example.com may be:
~~~
Header: ...

Answer:
www.example.com.   IN A 1.2.3.4

Authority:

Additional:
ns2.example.com. IN A 5.6.7.8
ns2.example.com. IN SVCB 1 . "alpn=doq,dot,do53"
ns2.example.com. IN RRSIG SVCB ... 
ns1.example.com. IN SVCB 1 . "alpn=dot"
ns1.example.com. IN RRSIG SVCB ... 
~~~
This requires that "ns2.example.com." is a name that this
authoritative nameserver is aware of as one of its identities.
Furthermore, as the zone example.com is signed it is possible to
include the SVCB.-->

## Recursive Nameserver Behavior

Recursive nameservers adopting this mechanism SHOULD implement the
following logic:

### When Sending Queries

1. **EDNS(0) OOTS Option:** If the resolver does not 
   know the transport capabilities of the authoritative nameserver
   it is about to send a query to it MAY request transport
   signaling by including an EDNS(0) "OOTS" option in the query.
   
   
**FOR DISCUSSION**: Further advice on frequency of re-querying.

### When Receiving Responses

1. **Parsing:** When receiving an authoritative DNS response with the EDNS(0)
   OOTS option present the resolver SHOULD parse the Additional section for SVCB
   records.

2. **Owner Check:** If an SVCB record is found whose owner name
   matches an authoritative nameserver identified in the Authority or
   Answer sections of the *current* response, the resolver MAY consider
   this a valid OOTS SVCB record.

# OOTS Probe mode 

Recursive resolvers may also probe directly for SVCB records for any
authoritative nameserver they need to connect to perform recursion.

## Timing of probing queries

The specific details of the exact timing of probe queries is left as an
implementation/policy for the recursive resolver. For example, a nameserver
that implements OOTS and does not know the transport capabilities of the
authoritative nameserver it is about to send a query to MAY

* perform cleartext queries and in parallel probe for OOTS records
* perform cleartext queries and in lazily probe for OOTS records (i.e. probe at some point in the future)
* delay cleartext queries until the result of a probe for OOTS records is known
* perform priming probes for an list of well known authoritative servers on start up and apply one of the above policies for all other authoritatives.

**FOR DISCUSSION**: Further advice on frequency of re-querying.

## 4.2 OOTS Probe queries

**Example 1:**
The resolver explicitly asks for the DNS transport signal for the
authoritative nameserver ns.dnsprovider.net. by querying
for "_dns.ns.dnsprovider.net. SVCB":

~~~
Header: ...

Answer:
_dns.ns.dnsprovider.net.  IN SVCB 1 . "oots=doq:100,dot:100,do53:100"
_dns.ns.dnsprovider.net.  IN RRSIG SVCB ...

Additional:
~~~


# Discovery of OOTS records

_Discovery heuristics_: The heuristics for doing SVCB discovery are an
implementation decision since they should align with the local resolution logic
in the software implementation. For example, resolvers may perform SVCB
discovery at any time e.g. before sending any queries to an authoritative, in
parallel to sending cleartext queries to the authoritative or at a later time.
In another approach, a resolver may start in Passive mode and subsequently
probe directly for a SVCB binding record in an attempt to obtain a DNSSEC
signed record (if the one obtained via the OOTS Option was not signed).

**TODO**: More discussion of mixing the two modes.

# Using OOTS records

The OOTS SVCB records are a mechanism to *discover* capabilities
of nameservers, not to override trusted delegation or service
configuration.

## DNSSEC validation

**Prioritization:**
Any DNSSEC-validated OOTS SVCB record found via an explicit probe query MUST
take precedence over any unvalidated OOTS SVCB record

* **DNSSEC Validation (Optional but Recommended):**
* The resolver SHOULD attempt to DNSSEC validate the OOTS SVCB record. This
involves validating the SVCB record itself and its corresponding RRSIG
(if present) against the DNSSEC chain of trust for the zone that owns
the SVCB record (e.g., dnsprovider.com for ns.dnsprovider.com).

* **DNSSEC Validation Failure:** If DNSSEC validation fails the resolver SHOULD ignore the record and proceed
  as if no record had been received. The result of a failed the DNSSEC
  validation can be logged for further investigation.

**QUESTION**: Should the above DNSSEC restriction still apply?


## Upgrading connections

_Transport selection heuristics_: Similarly, resolvers may attempt connections over
encrypted transports at any time i.e. before sending any queries to the
resolver, in parallel to sending cleartext queries to the resolver or at a
later time after having obtained a SVCB record.

Resolver MAY attempt connections over any transport with a weight greater than
one in the "oots" key.

Resolvers SHOULD honor any transport weight value found in the "oots" key for
any transport they attempt to connect over.

Resolvers MUST always be prepared to fall back to
traditional UDP/TCP transport if an attempt to use an alternative
transport based on an OOTS SVCB record (especially an unvalidated one) fails
or times out.

Resolvers MAY also cache information about the result of a connection attempt
based on an OOTS record, for example when a particular transport is indicated
as being supported but connection attempts fail. Resolvers MAY choose to
implement a back-off for retrying connection attempts in this scenario.

## Authentication of the Authoritative Nameserver

Authentication of the authoritative nameserver is not an explicit goal.
The reason is that as an Opportunistic mechanism it will not always be
possible to do such authentication.

While the certificate presented by the nameserver can be validated in a manner
analogous to that described in {{!RFC8310}} this only validates that the
capability of the nameserver is as advertised. This does not validate that the
nameserver is authoritative for the zone in question (see
{{security-considerations}} for more security considerations).

Even without strong authentication of the authoritative server
the proposed mechanism still provides benefits (increased privacy, potential
performance improvements) and for that reason cryptographic verification
of the server identity is not a requirement.

However, the result of an authentication attempt may of use to evaluate various information, e.g. :

* the presence/absence of any certificate for the server
* the status of any certificate (e.g. validity, expiration)

Such information might be logged and/or reported to the operators of the servers in question.

## Resolver Caching Strategies

Resolvers implementing the OOTS SVCB record mechanism have several options
for caching the transport signals received.

A suggested primary strategy is to set the EDNS(0) ODTS option when
transport signaling information is not currently cached.

The primary caching strategy SHOULD be "Standard DNS Cache", i.e.
treat the SVCB record like any other DNS record, caching it according
to its TTL. This is the simplest approach and will simply cause the
resolver to fall back to UDP for one query if the transport signal
data has expired.

For a more detailed analysis of possible caching logic, see
{{!RFC9539}}, section 4.

Note that the resolver always has the option of using the EDNS(0)
ODTS option whenever the cache entry is getting close to expiry.

Given the variety of deployment scenarios and operational
requirements, this document does not mandate a specific caching
strategy. Implementers SHOULD choose a strategy that best fits their
operational needs, considering factors such as:

* The importance of minimizing connection attempts
* The impact of failed connection attempts
* The computational cost of different caching strategies
* The memory requirements of maintaining cache state

The chosen strategy SHOULD be documented in the implementation's
configuration options to allow operators to make informed decisions
about its use.

# Comparison with DELEG

The idea to use an SVCB "oots" parameter for transport signaling
originated with the work on {{?DELEG=I-D.draft-ietf-deleg}}.  The
current document uses a new SVCB key rather than as integral part of a
changed delegation mechanism.

Both mechanisms have distinct use cases, and pros and cons. The major advantage
of the DELEG mechanism is that when DNSSEC signed it cannot be spoofed or
filtered, as it is an integral part of an upcoming protocol change.

The Opportunistic mechanism described here has the major advantage of
being available immediately without any changes to the DNS
protocol. Furthermore, as it is a signal directly from an
authoritative nameserver, a single OOTS SVCB record may allow the recipient
recursive nameserver to upgrade the transport used for all the zones
served by that authoritative nameserver (which may be millions)
without the need to make any changes to the zones, nor to the parent
zones.

Given the current DNS landscape with a limited number of very large
providers of authoritative DNS service and a limited number of large
providers of recursive DNS service the Opportunistic model described
here has the potential of enabling upgrading the transport for a
significant fraction of the DNS traffic with a limited amount of
effort.

# Security Considerations

* **Spoofing of Unvalidated OOTS SVCB records:** An OOTS SVCB record that cannot be DNSSEC
validated (e.g., for ns.example.com where example.com is unsigned)
is susceptible to spoofing by an on-path attacker. Such an attacker
could insert a fake SVCB record advertising a non-existing transport,
thereby denying connection over that transport. However, since the
resolver connection policy is Opportunistic and not required for DNS resolution, the
worst-case scenario is that the resolver attempts a connection that
fails and then falls back to traditional transports.  Security for the
actual DNS data remains unaffected. The cryptographic validation of
TLS/QUIC (via X.509 certificates) for DoT/DoQ would still protect the
integrity and privacy of the connection itself.

* **No New Attack Vectors:** This mechanism does not introduce new
attack vectors for DNS data itself, as it primarily concerns transport
discovery. It relies on the existing security properties of DoT, DoH
and DoQ for actual session security.

* **Safe Rollout:**  Only recursive resolvers that implement OOTS will 
request or probe for OOTS SVCB records and only authoritatives that publish
such records will respond with them.

# Operational Considerations

* **Response Size:** Including an SVCB record in the Additional
section will increase the size of UDP responses. Authoritative server
operators should consider the potential for UDP fragmentation or TCP
fallback if responses become excessively large, though a single SVCB
record is typically small. Recursive nameservers should usually only set
the EDNS(0) OOTS when they do not already have the transport signaling
information.

* **Server Configuration:** Authoritative server implementations will
need configuration options to enable this feature and manage the
identities list.

* **Rollout Strategy:** This mechanism supports a gradual rollout.
Authoritative servers can begin sending OOTS records to just those resolver requesting
them , and resolvers can begin requesting OOTS records without requiring all
authoritative servers to implement the feature.

* **Monitoring:** As there is extremely limited data on effects of
alternative DNS transports for communication resolver to authoritative
nameserver it is strongly suggested that monitoring (of use,
resource consumption, etc) is considered.

# Privacy Considerations

* **Opportunistic provides no security guarantees:** The above text discusses
  discovery of transport signals and authentication information in queries made
  by the recursive resolver. Those queries may or may not occur over encrypted
  or authenticated connections. Only when all the connections are authenticated
  are all the queries protected from active surveillance. If all the
  connections are Opportunistically encrypted then the queries are protected
  from passive surveillance. Otherwise they may occur in cleartext, or a
  combination of circumstances may exist.

* **Leakage in queries to parents:** Such queries leak the name of the zone
  that the resolver wishes to ultimately query which in itself can be
  sensitive. During the early stages of the incremental rollout of technologies
  such as recursive to authoritative encrypted connections it is unlikely that
  fully confidential discovery will be possible due to the nature of the DNS
  hierarchy. However, if large TLDs and/or those hosted by large CDNs support
  encrypted transports a significant number of queries from busy resolvers to
  discovery information on TLD child zones (and below) could be performed
  confidentially thereby greatly improving the privacy over the current
  situation.

# IANA Considerations

## OOTS EDNS(0) Option

This document defines a new EDNS(0) option, entitled "OOTS",
assigned a value of TBD in the "DNS EDNS(0) Option Codes (OPT)" registry.

~~~
   +-------+----------------------+----------+----------------------+
   | Value | Name                 | Status   | Reference            |
   +-------+----------------------+----------+----------------------+
   | TBD   | OOTS                 | Standard | ( This document )    |
   +-------+----------------------+----------+----------------------+
~~~

**Note to the RFC Editor**: In this section, please replace
occurrences of "(This document)" with a proper reference.

# Implementation Status

**Note to the RFC Editor**: Please remove this entire section before publication.

* The TDNS Framework of experimental DNS servers developed and maintained by the
  Swedish Internet Foundation implements this draft (see [https://github.com/johanix/tdns](https://github.com/johanix/tdns)). 
  TDNS has support for both the authoritative nameserver and
  recursive nameserver parts of the draft.
* There is a work-in-progress implementation in NSD **TODO: Reference needed**

# Acknowledgments

Many people have commented and contributed to this document in different ways.
In no particular order and with a significant risk of forgetting someone: The
participants of the DELEG Working Group, Peter Thomassen, Christian Elmerot,
John Todd, Peter Koch, Willem Toorop, Peter van Dijk.

--- back

# Change History (to be removed before publication)

* -03 version
   * Re-structure draft and introduce Passive and Probe mode

# Rationale for Using the Additional Section

**Note to the RFC Editor**: Please remove this entire section before
publication.

Only DNS nameservers (authoritative or recursive) that are aware of
the proposed mechanism will use it. It requires no changes to the existing
protocol in order to convey more RR sets in the Additional section. 

A downside is that it is not possible to strictly rely on anything
specific being present in the Additional section, as it may be
stripped off by a middlebox or even by the sending nameserver
(eg. due to packet size constraints). For this reason it is not
possible to guarantee the presence of the OOTS records even when
the signal is explicitly queried for.

This is usually a major issue and the primary reason that data in the
Additional section is actively ignored by resolvers. In this
particular case, though, even an untrusted transport signal is better
than no signal at all. Furthermore, the only effect of a forged or
otherwise incorrect transport signal is a, typically failed,
connection attempt to an authoritative nameserver that does not
support the advertised transport. This will cause immediate fallback
to "Do53", i.e. traditional DNS over UDP/TCP and the non-availability
of the advertised transport will be remembered by the resolver (for
some suitable time).
 
Hence, using the Additional section for request mode of OOTS has vastly more
benefits than drawbacks.
