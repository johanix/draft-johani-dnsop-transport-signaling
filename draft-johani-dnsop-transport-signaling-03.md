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
the support for specific transports. 

Recursive resolvers can obtain these records either by requesting they be
included in the Additional section of authoritative DNS responses (Passive
mode) or by direct DNS queries (Probe mode). Resolvers can then
Opportunistically upgrade connections to the authoritative to encrypted
transports according to local policy, thereby improving privacy, security, and
performance for subsequent interactions.

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
Transport Signaling mechanism (OOTS). This signaling is based on SVCB records
{{!RFC9460}}, {{!RFC9461}} which can contain a new (experimental) SVCB "oots"
key that specifies per-transport query load parameters. This improves on the
Opportunistic (but blind) testing of alternative transports suggested in
{{RFC9539}} by providing a mechanism by which a responding authoritative server
may signal which alternative transports it supports, along with more detailed
information about each transport.

Recursive resolvers can obtain these records either by requesting they be
included in the Additional section of authoritative DNS responses (Passive
mode), and/or by performing direct DNS queries for SVCB records (Probe mode),
depending on the local _discovery_ policy.

* The former, "Passive mode", is enabled by use of a new EDNS(0) option and
  allows resolvers to discover alternative transports efficiently with no
  additional queries. The records returned here are to be taken by the resolver as a hint of the transport capabilities of the authoritative server.

* The latter, "Probe mode", enables recursive resolvers willing to expend
  additional overhead to obtain SVCB records via direct queries, and to
  (optionally) directly discover if DNSSEC signed SVCB records exist.

This dual approach has some similarities to NS re-validation
{{?I-D.draft-ietf-dnsop-ns-revalidation}} whereby a resolver may choose to
actively probe the child zone for NS records after receiving a referral.
However, OOTS is more flexible in that resolvers may choose to operate in one
 mode or a combined mode approach.

Neither mode requires changes to the parent zone. Passive mode may require
additional SVCB alias mode records for certain delegation patterns. 

On obtaining such SVCB records recursive resolvers can then apply a local
_connection_ policy to Opportunistically upgrade connections to the
authoritative to an encrypted transport contained within the signaled
information.

The Opportunistic mechanism described here has a major advantage of
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

This specification is expected to evolve over time based on interoperability
testing and experimental deployments. Early work is expected to include
comparing the two modes to see if one or the other is preferable or if both
should be part of the long term solution. Other work will investigate if the
structure of, and the information in, the SVCB "oots" key is useful in practice.

*NOTE: * While DNS over HTTP (DoH) {{!RFC8484}} is also an option as a recursive to authoritative encrypted transport many of the advantages of the use of DoH stub to resolver do not apply in the recursive to authoritative context. Hence, there appears to be little current appetite to deploy DoH for this use. So while DoH is covered by this specification and included in the SVCB "oots" key definition, the examples and discussion here reference only DoT and DoQ for brevity.

## Structure of the document

{{overview-of-the-oots-mechanism}} gives a general overview of the OOTS mechanism.

{{recommendations-for-recursive-resolvers}} provides recommendations for recursive resolvers on how to discover OOTS records using both Passive and Probe mode.

{{recommendations-for-authoritative-servers}} provides recommendations for authoritative servers, in particular when to include records requested in Passive mode.

{{using-oots-records}} describes how to use the parameters from the "oots" SvcParam (however they were obtained).

The final sections provide Security, Operational and Privacy considerations.

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

General DNS terminology used here follows that defined in {{!RFC9499}}.

* **OOTS Passive mode:** Recursive resolvers set the EDNS(0) OOTS Option in a query and authoritative servers supply EDNS(0) OOTS Responses in the Additional section if appropriate.

* **OOTS Probe mode:** Recursive resolvers directly query for SVCB records of authoritative servers and process any "oots" keys in those records

* **SVCB Record:** Service Binding record, as defined in {{!RFC9460}}.

* **SCVB "oots" key:** New experimental Service Parameter Key (SvcParamKey)  key defined in {{!I-D.draft-johani-dnsop-svcb-oots}} which allows an operator to advertise a requested query load for each advertised transport.

* **OOTS Record:** Service Binding record, as defined in {{!RFC9460}} that contains the SVCB "oots" key.

* **EDNS(0) OOTS Option:** New EDNS(0) flag that indicates a resolver wishes to receive OOTS SVCB records in the Additional section of the response.

* **EDNS(0) OOTS Response:** An SVCB record included  in the
Additional section of an authoritative DNS response, intended to
signal the responding authoritative nameserver's transport
capabilities.

* **Strict and Opportunistic connection modes:** These connection modes are entirely analogous to those defined for stub to recursive connections in
  {{!RFC8310}}. 
   * **Strict** requires both an encrypted and authenticated connection
  to the server based on authentication credentials that were obtained via a
  secure mechanism. Clients MUST hard-fail the connection if this is not possible.
   * **Opportunistic** uses cleartext as the baseline connection,
  with encryption and authentication negotiated and applied to the connection
  when available.


# Overview of the OOTS mechanism

The basis of the Opportunistic operator transport signaling (OOTS) mechanism is
the discovery of and usage by recursive resolvers of Service Binding records
(SVCB RRs) for authoritative nameservers that offer encrypted transports. 

An new, experimental SCVB "oots" parameter is defined in {{!I-D.draft-johani-dnsop-svcb-oots}} for the OOTS mechanism. It allows the operator of an authoritative DNS nameserver to advertise, per DNS transport protocol (such as DNS over UDP/TCP, DNS over TLS, DNS over HTTPS, and DNS over QUIC), the operator's own assessment of the share of the nameserver's total query load that it is confident it can serve over that transport. The per-transport values are independent capability estimates rather than a distribution of queries across transports; they are opportunistic hints that a resolver MAY use to inform transport selection and MAY ignore entirely.

Recursive resolvers can discover and use OOTS SVCB records that contain the
"oots" parameter. However, it is important to note that the information
conveyed by the SVCB records alone (even when DNSSEC signed) signals only the
capabilities of the authoritative nameserver serving the zone. It does not,
therefore, establish a full chain of trust directly to the zone itself and MUST
be considered as insecure. It should not be used as a basis of a Strict
connection policy, only to enable an Opportunistic connection policy.

However, acquiring such a signal enables resolvers to immediately apply the
local Opportunistically connection policy for the nameserver in question.
Resolvers may, of course, still validate the certificate presented by the
nameserver and log the result.

The mechanism is expected to be experimental in nature in the early stages as
various details of the discovery heuristics and signaling mechanism are
explored and developed.


## Discovery policy for OOTS records

Recursive resolvers can discover SVCB records one of two ways:

* **Passive mode**: A recursive resolvers sets the OOTS EDNS(0) option to
  indicate they want to receive SVCB records in the Additional section if they
  are available. A nameservers that is authoritative for the zone in question
  (i.e. managed by the zone operator) returns any SVCB records available for
  the authoritative nameservers when responding to a query with the OOTS
  EDNS(0) option set. This is the most efficient mode as it requires no
  additional queries to obtain the signal.

* **Probe mode**: A recursive resolver actively probes for SVCB records for
  some or all of the authoritative nameservers they query. This mode incurs more overhead but is useful, for example, for resolvers that have a local policy that includes attempting DNSSEC validation of the SVCB records.

_Discovery policy heuristics_: The heuristics for doing SVCB discovery are an
implementation decision since they should align with the local resolution logic
in the software implementation. A typical use case might be to attempt to
discover OOTS records when the resolver has no cached transport signaling
information (i.e. the resolver is contacting the authoritative for the first
time or any existing record has expired from the cache). However, a resolver
might:

* perform cleartext queries and discover OOTS records in parallel.
* perform cleartext queries and in lazily discover for OOTS records (i.e. at some point in the future)
* delay cleartext queries until the result of a direct probe for OOTS records is known
* perform priming probes for an list of well known authoritative servers on start up and apply one of the above policies for all other authoritatives.

In another approach, a resolver may start in Passive mode and subsequently
probe directly for a SVCB binding record in an attempt to obtain a DNSSEC
signed record (if the one obtained via the OOTS Option was not signed).

## Connection policy for OOTS records

Strict and Opportunistic connection policies for stub to recursive connections are described in {{!RFC8310}} and the terms are used analogously here.

A recursive resolver can use OOTS SVCB records to Opportunistically upgrade
connections to encrypted transports, but SHOULD honor the total query load shares specified in the OOTS SVCB records.

_Connection policy heuristics_: Similarly to discovery policy heuristics, the
details of the local connection policy are an implementation detail. Resolvers
may attempt connections over encrypted transports at any time i.e. before
sending any queries to the resolver, in parallel to sending cleartext queries
to the resolver or at a later time after having obtained a SVCB record.

Clearly, from a privacy perspective, is is preferable to use an encrypted
transport as early as possible in the resolution process. But for an
Opportunistic policy, this can and should be balanced with efficient and
reliable query resolution. Capturing data on and developing the details of one
or more strategies for these activities is expected to evolve over time.


# Recommendations for recursive resolvers

This section describes how recursive resolvers can discovery OOTS records.

## OOTS Passive mode 

This mode consists of two steps:

* A resolver MAY include the new EDNS(0) option that defines
  an OOTS request in a query to an authoritative nameserver.
* A authoritative nameserver receiving that query SHOULD include SVCB records
  in the response if the required conditions are met, see {{recommendations-for-authoritative-servers}}.

###  Design decisions

See {{rationale-for-using-the-additional-section}} for the rationale for using the Additional section for the transport signaling EDNS(0) OOTS Response.

### The EDNS(0) OOTS Option

To provide a mechanism for resolvers to explicitly request to
receive transport signals, this document defines a new EDNS(0)
option called "OOTS". When included in a query, this
option signals to the authoritative server that the resolver
wants to receive transport signals in the response.

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


###  Sending Queries

Recursive resolvers MAY include the EDNS(0) OOTS Option in a query to an authoritative to request transport signaling be included in the response.

###  Receiving Responses

#### Parsing responses

When receiving an authoritative DNS response to a query where the EDNS(0) OOTS
option was set the resolver SHOULD parse the Additional section for SVCB
records.

When receiving a DNS response to a query where the EDNS(0) OOTS option was not
set the resolver SHOULD ignore any SVCB records in the Additional section for the purposes of transport signaling.

If the EDNS(0) OOTS option was set in a query but no OOTS SVCB record was received in the response, the resolver should proceed as if there are no OOTS records for the zone that resolution is being performed on.

#### Valid OOTS records

If an SVCB record is found whose owner name matches an authoritative nameserver
identified in the Authority or Answer sections of the *current* response and
the SVCB contains an "oots" SvcParam , the resolver MAY consider this a valid
OOTS SVCB record. If it does not, the resolver MUST ignore the SCVB record. If
any other parameter, including "ipv4hint" and "ipv6hint", is present in the
SVCB parameter list then that parameter SHOULD be ignored.

**QUESTION:** Should we explicitly say something here about the possible presence of the "alpn" parameter?

**QUESTION:** Should we specify that authoritatives that implement this specification set the EDNS(0) OOTS option in a response to make it clearer that there is no signal? Since both the option and the records can be tampered with if they are sent over cleartext this may not be useful. But if the response it sent over an encrypted transport this may form a useful signal for measuring deployment. 

**TODO:** We do not yet discuss multiple SVCB records in a response. 


### OOTS Passive mode queries

**Example 1:**

If the resolver queries ns.dnsprovider.net for www.example.com. and
ns.dnsprovider.net is authoritative for www.example.com, the respond might be:

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


### Forwarders

Forwarders SHOULD NOT modify any EDNS(0) OOTS option in any query.

Forwarders SHOULD NOT modify OOTS SVCB records in the Additional section of any response.

### Stub resolvers

Stub resolvers SHOULD NOT set the EDNS(0) OOTS option in any query.

Stub resolvers SHOULD ignore any OOTS SVCB records in the Additional section of any response.


## OOTS Probe mode 

### Sending queries

Recursive resolvers MAY also probe directly for SVCB records for any
authoritative nameserver they need to connect to perform recursion.

### Receiving responses

If the SVCB record contains a "oots" SvcParam the resolver MAY consider this a
valid OOTS SVCB record. If it does not, the resolver MUST ignore the SCVB
record for the purposes of transport signaling.

If any other parameter, including "ipv4hint" and "ipv6hint", is present in
the SVCB parameter list then it SHOULD be ignored.

### OOTS Probe mode queries

**Example:**
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


# Recommendations for Authoritative servers

## OOTS Probe mode

### Sending responses

An authoritative nameserver SHOULD NOT include OOTS SVCB records in a response
if the EDNS(0) OOTS option was not present in the query. This is to avoid increasing the size of responses to resolvers that do not implement this specification.

**NOTE** - During development and prototyping of this specification a valid reason that an experimental deployment might decide to include OOTS SVCB records in all responses is for testing purposes.

Authoritative servers that implement this specification should provide a configuration option to control whether or not OOTS records are included in responses if the nameserver is configured to serve minimal responses.

Authoritative nameserver implementations differ significantly in how they generate the content of responses. Some have a concept of a server identity, others do not. Some can synthesize records and DNSSEC sign on-the-fly, others cannot. As a result, attempting to specify a general algorithm for how nameservers should determine which responses to include OOTS records in is out of scope for this document. Instead it is stated that the nameserver SHOULD include an OOTS record in a response if the EDNS(0) OOTS option was set in the query and:

* the nameserver is authoritative for the zone containing the QNAME in the query
* the nameserver has access to, or can generate an SVCB record that matches the format defined below

**QUESTION:** Is this correct??

Details of some known implementation methodologies are presented for context in {{authoritative-probe-mode-methodologies}}.

###  Format of the OOTS SVCB records

The OOTS SVCB records are ones with the following characteristics:

* **OWNER:** The owner name of the SVCB record MUST be the label
  "_dns" followed by the FQDN of an authoritative nameserver for the zone,
  as identified in the child NS RRset for the zone.

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
   SvcParam is defined, as relevant for signaling transports e.g. 
   DoT (oots=dot:100), DoQ (oots=doq:100) or cleartext DNS (oots=do53:100)


**QUESTION:** Have changed the text in the owner name bullet here to say 'child NS set' - is that correct or can we be more flexible 'parent or child'?

# Using OOTS records

The OOTS SVCB records are a mechanism to *discover* capabilities of
nameservers, not to override trusted delegation or service configuration.

{{!I-D.draft-johani-dnsop-svcb-oots}} specifies the syntax and semantics of the
"oots" SvcParam. To summarise, it conveys, per DNS transport protocol available
at a nameserver, the operator's assessment of the share of the nameserver's 
total query load that it is confident it can serve over that transport,
expressed as a percentage. Weight values are unsigned integers in the range 
\[0, 100\]. The weights are NOT a distribution that partitions queries across
transports and are NOT an instruction to a resolver on how to split its
queries; each weight is an independent capability assessment against the same
total load. Consequently, a nameserver MAY advertise a weight of 100 for more
than one transport (full confidence on each), and the sum of the weights in a
single "oots" SvcParam value will typically exceed 100. A weight of 0 indicates
that the transport is not available at this nameserver. An example OOTS SVCB record containing this parameter is:

~~~
ns.example.net. 300 IN SVCB 1 . oots="do53:100,dot:5,doq:5"
~~~

Resolver MAY attempt connections over any transport with a weight greater than
1 in the "oots" SvcParam.

A resolver MUST interpret a value of more than 100 as 100.

If resolvers choose to use encrypted transports, they SHOULD honor any transport weight value found in the "oots" SvcParam
for any transport they attempt to connect over. Resolvers MAY choose to use lower transport weights for encrypted transports due to local resource constraints. Resolvers SHOULD NOT use higher transport weight value found in the unless there is a compelling reason, e.g. no other transport is available.

Resolvers MUST always be prepared to fall back to traditional UDP/TCP transport
if an attempt to use an alternative transport based on an OOTS SVCB record
(especially an unvalidated one) fails or times out.

**QUESTION:** Did we decide to say anything about possible implementations of this in the appendix??

Resolvers MAY also cache information about the result of a connection attempt
based on an OOTS record, for example when a particular transport is indicated
as being supported but connection attempts fail. Resolvers MAY choose to
implement a back-off for retrying connection attempts in this scenario. For a
more detailed analysis of this possible caching logic, see {{!RFC9539}},
section 4.


# Security Considerations

* **DNSSEC Validation (Optional but Recommended):** The resolver SHOULD attempt to DNSSEC validate the OOTS SVCB record. This involves validating the SVCB
record itself and its corresponding RRSIG (if present) against the DNSSEC chain
of trust for the zone that owns the SVCB record (e.g., dnsprovider.com for
ns.dnsprovider.com).

* **DNSSEC Validation Failure:** If DNSSEC validation fails the resolver SHOULD 
  ignore the record and proceed as if no record had been received. The result of
   a failed the DNSSEC validation can be logged for further investigation.

**QUESTION**: Should the above DNSSEC restriction still apply? If so, we should explain when the two SHOULDs above might not be followed.

* **Prioritisation of signals:** Similarly to NS re-validation {{?I-D.draft-ietf-dnsop-ns-revalidation}}, any DNSSEC-validated OOTS SVCB record found via an explicit probe query MUST take precedence over any unvalidated OOTS SVCB record. OOTS signals are one of a number of methods that resolvers can use to determine transport capabilities of servers and they should be prioritized appropriately. For example, and OOTS signal may be deemed higher priority then the results of probing port 853 but MUST not take precedence over a DNSSEC signed transport signal obtained via a DELEG record.

* **Spoofing of Unvalidated OOTS SVCB records:** An OOTS SVCB record that
  cannot be DNSSEC validated (e.g., for ns.example.com where example.com is
  unsigned) is susceptible to spoofing by an on-path attacker. Such an attacker
  could insert a fake SVCB record advertising a non-existing transport, thereby
  denying connection over that transport. However, since the resolver
  connection policy is Opportunistic and not required for DNS resolution, the
  worst-case scenario is that the resolver attempts a connection that fails and
  then falls back to traditional transports. Security for the actual DNS data
  remains unaffected. The cryptographic validation of TLS/QUIC (via X.509
  certificates) for DoT/DoQ would still protect the integrity and privacy of
  the connection itself.

* **Certificate validation**: While the certificate presented by the nameserver
  can be validated in a manner analogous to that described in {{!RFC8310}} this
  only validates that the capability of the nameserver is as advertised. This
  does not validate that the nameserver is authoritative for the zone in
  question. If validation fails for any reason that information might be logged and/or reported to the operators of the servers in question.

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
  Authoritative servers can begin sending OOTS records to just those resolver
  requesting them, and resolvers can begin requesting OOTS records without
  requiring all authoritative servers to implement the feature.

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

The idea to use an SVCB "oots" SvcParam for transport signaling
originated with the work on {{?DELEG=I-D.draft-ietf-deleg}}. 

Many people have commented and contributed to this document in different ways.
In no particular order and with a significant risk of forgetting someone: The
participants of the DELEG Working Group, Peter Thomassen, Christian Elmerot,
John Todd, Peter Koch, Willem Toorop, Peter van Dijk.

--- back

# Change History (to be removed before publication)

* -03 version
   * Re-structure draft and introduce Passive and Probe mode

# Rationale for Using the Additional Section

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

# Implementation considerations

## Authoritative Probe mode methodologies

### Multiple Server Identities

An authoritative nameserver may be known by multiple FQDNs (e.g.,
ns1.example.com, dns.customer.org, ns.cdnprovider.net). To facilitate
methodology 1 ("Self-Identification"), authoritative server
implementations can include a configuration mechanism (e.g., an
identities list) where operators can list all FQDNs by which the
server is known. This allows the server to correctly identify itself
regardless of the specific name used in the NS RRset.

### Methodology  1

An authoritative nameserver SHOULD include OOTS SVCB records in the Additional
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

### Methodology 2

**TODO:** Refine the NSD example to be included here.

<!-- The NSD prototype supports two types of queries. The first is a query for the A or AAAA record of a nameserver:

~~~
Query: ns1.p.axfr.net. AAAA
Response:

;; ANSWER SECTION:
ns1.p.axfr.net. 300     IN      AAAA    2a01:3f0:1:2::63

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:
_dns.ns1.p.axfr.net.    10800   IN      SVCB    1 . (alpn="doq,dot,doh,do53")
~~~

A/AAAA replies tend to be small. So there is no problem adding an SVCB. These queries are also relatively rare because the resolver will only query for this specific name. And all information is contained in a single zone.

The second type of query is any query where NSD is configured to return the apex NS records:

~~~
Query: www.foo.com. A
Response:

;; ANSWER SECTION:
www.foo.com.    7200    IN    A    1.2.3.4

;; AUTHORITY SECTION:
foo.com.    300    IN    NS    ns.foo.com.

;; ADDITIONAL SECTION:
_dns.ns.foo.com. 10800 IN SVCB 0 _dns.ns1.p.axfr.net.
ns.foo.com.      300    IN    A    77.72.230.63
~~~

Assuming the SVCB is added to the zone. This is still in a single zone.  -->



