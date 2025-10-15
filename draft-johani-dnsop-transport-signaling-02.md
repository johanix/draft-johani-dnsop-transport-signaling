---
title: "Authoritative DNS Transport Signaling"
abbrev: "DNS Transport Signaling"
docname: draft-johani-dnsop-transport-signaling-02
date: {DATE}
category: std

ipr: trust200902
area: Internet
workgroup: DNSOP Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
  ins: J. Stenstam
  name: Johan Stenstam
  organization: The Swedish Internet Foundation
  country: Sweden
  email: johan.stenstam@internetstiftelsen.se
 -
  ins: L. Fernandez
  name: Leon Fernandez
  organization: The Swedish Internet Foundation
  country: Sweden
  email: leon.fernandez@internetstiftelsen.se
 -
  ins: E. Bergström
  name: Erik Bergström
  organization: The Swedish Internet Foundation
  country: Sweden
  email: erik.bergstrom@internetstiftelsen.se

normative:
  RFC2119:
  RFC8174:
  RFC7858:
  RFC9460:
  RFC9461:
  RFC9250:
  RFC6891:

informative:
  RFC9539:
  I-D.draft-ietf-deleg:
--- abstract

This document proposes a mechanism for authoritative DNS servers to
signal their support for alternative transport protocols (e.g., DNS
over TLS (DoT), DNS over HTTPS (DoH) and DNS over QUIC (DoQ)) directly
within the Additional section of authoritative DNS responses. This
"hint-based" approach aims to enable resolvers to discover and upgrade
transport connections more efficiently, thereby improving privacy,
security, and performance for subsequent interactions.

The mechanism is designed to not require any protocol change. It is
safe, backward-compatible, and effective even when DNSSEC validation
of the hint is not possible or desired.

This document proposes an improvement to the opportunistic (but blind)
testing of alternative transports suggested in RFC9539 by providing a
mechanism by which a responding authoritative server may signal what
alternative transports it supports.

TO BE REMOVED: This document is being collaborated on in Github at:
[https://github.com/johanix/draft-johani-dnsop-transport-signaling](https://github.com/johanix/draft-johani-dnsop-transport-signaling).
The most recent working version of the document, open issues, etc, should all be
available there.  The authors (gratefully) accept pull requests.

--- middle

# 1. Introduction

The Domain Name System (DNS) primarily relies on UDP and TCP for
communication between resolvers and authoritative servers.  While
these protocols are well-established, there is a growing interest in
leveraging modern transport protocols like DNS over TLS (DoT)
{{!RFC7858}}, DNS over HTTPS (DoH) {{!RFC9461}} and DNS over QUIC
(DoQ) {{!RFC9250}} to enhance privacy, security, and performance.

Existing efforts to signal service connection information, such as the
SVCB and HTTPS DNS records {{!RFC9460}} {{!RFC9461}}, primarily focus
on service discovery mechanisms where a client explicitly queries for
these records, often from a parent zone. While robust, this approach
can introduce additional latency and requires explicit configuration
at the parent zone level.

This document proposes a "DNS Opportunistic Transport Signaling" (DNS
OTS) mechanism. DNS OTS, aka an "OTS Hint" allows an authoritative DNS
nameserver to directly convey its transport capabilities as a hint
within the Additional section of responses to queries where it
identifies itself as an authoritative nameserver for the requested
zone. This direct, in-band signaling provides a low-latency discovery
path, even when a formal, validated signal is not available.
Furthermore, this is achieved without any changes to the DNS Protocol.

## 1.1. Prior Art

An attempt at utilizing more modern, and in particular, more private
transports between resolvers and authoritative nameservers was introduced
in {{!RFC9539}}. The idea there was to opportunistically try to send the
query to the authoritative nameserver over multiple transports with no
prior knowledge of whether a transport was supported in the receiving end
or not.

The drawback with that approach is that without any significant deployment
of authoritative support the resolver end will mostly spend cycles and
traffic on a wasted effort. For this reason their deployment has been limited.

Furthermore, in Appendix B of {{!RFC9539}} requirements for improving
the defense against an active attacker are listed. The first requirement is:

* A signaling mechanism that tells the recursive resolver that the
  authoritative server intends to offer authenticated encryption.

This document aims to provide exactly such a mechanism while staying within
the current DNS protocol. Therefore the transport signaling provided will
be opportunistic, and as such fit well as an improvement to {{!RFC9539}}.

## Rationale for Using the Additional Section (moved)

See Appendix A for the rationale for using the Additional section.

# 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals.

* **Authoritative Nameserver (Auth Server):** A DNS server that holds
 the authoritative zone data for a specific domain.

* **Recursive Nameserver (Resolver):** A DNS server that processes
 user queries, performing iterative lookups to authoritative servers to
 resolve domain names.

* **OTS Hint:** A DNSSEC-signed SVCB record included opportunistically
 in the Additional section of an authoritative DNS response, intended
 to signal the responding authoritative nameserver's transport
 capabilities.

* **SVCB Record:** Service Binding record, as defined in {{!RFC9460}}.

# 3. Modes of Operation

[new text, needs to be integrated]

This document provides two modes, opportunistic mode and strict mode.

In opportunistic mode, the autoritative server and the recursive resolver
make a best effort attempt to set up an encrypted DNS transport connection.
This provides enhanced privacy against a passive attacker. However an
active attracker may be able to force a downgrade to unencrypted DNS.

In strict mode, the authoritative server and the recursive resolver try to
ensure an active attack results in at most a denial of surface, but does not
leak any data or allow untrusted data to accepted.

# 3. Problem space

[new text, needs to be integrated]

This section looks at the various configurations that need to be supported.

In opportunistic mode, the authoritative needs to provide the recursive 
resolver with the transport signaling record even when the recursive resolver
does not explicitly ask for it. For example by adding it to the result of an
A or AAAA query for a name server. The recursive resolver accepts such an
additional record
This section looks at the various configurations that need to be supported.

In opportunistic mode, the authoritative needs to provide the recursive 
resolver with the transport signaling record even when the recursive resolver
does not explicitly ask for it. For example by adding it to the result of an
A or AAAA query for a name server. The recursive resolver accepts such a
record an uses it to set up a secure transport.

For strict mode, it is important to realize that security can only increase:
if one name server support script mode then that may be enough to access a
zone in a secure way even if other name server only offer unencrypted 
transports or support only opportunistic mode. 
For this reason, the following analysis assumes that a zone is served by
exactly one name server.

There are three zones that matter in this analysis: the parent zone, the
child zone, and the zone that contains the name server addresses and transport
signalling records.
Note that the name server addresses may be located in the child zone. 
And some of the three zones may be served by the same name server.

The parent zone contains delegation NS records which are not DNSSEC signed.
So it does not matter if the parent zone is DNSSEC signed or not.
What does matter is whether the parent zone support a strict mode secure
connection.
This gives a total of two possibilities for the parent zone.

For the child zone there are also two possibilities, the child zone is DNSSEC
secure or not.

Then for the name server transport signalling there are three possibilities:
the zone that hold the name server information supports a strict mode secure
connection, the zone does not support a strict mode secure connection but it
is DNSSEC secure, and the zone is neither DNSSEC secure nor does it support a
strict mode secure connection.

[ the following may need a table, only text for now ]

There are two special cases where strict transport signalling is unavailable.
The first is when the zone that holds the name server records is neither
avaiable using strict mode secure connection nor DNSSEC secure. In that
case obtaining transport signalling in a secure way is not possible.

The second case is where the parent zone is no using strict mode
transport signalling and the child zone is not DNSSEC secure. 
In that case obtain a list of the child's name servers in a secure way is 
impossible.

The remaining cases can be analysed as followes.
If the parent supports a strict mode secure transport then the resolver
can receive a trust (delegation) NS RR set from the parent. 
Otherwise, the resolver has to obtain the apex NS RRset at client (using
an untrusted or potentially optimistic secure connection) and verify that
the apex NS RRset is DNSSEC secure.

If the zone that hold the name server records is available using 
a strict mode secure connection then it is sufficient if the name server add
transport mode signalling with an A or AAAA query.

If no strict mode secure connection is available then the authoritative
server should include transport signalling records with an A or AAAA query
including signatures.
However, if the resolver does not receive those records it has to generate
an expliciy query for the transport signnaling record to obtain a secure
denial of existance.

# 3. Modes of Operation

This document defines two modes for consuming and acting on transport signaling: 
Opportunistic and Strict. These modes define when and how data from an SVCB record
associated with an authoritative nameserver may be used by a resolver.

## 3.1. Opportunistic Mode

Opportunistic mode applies when the SVCB record for the authoritative nameserver is
received opportunistically in the Additional section (an OTS Hint). The hint may or
may not be DNSSEC-signed and may or may not be successfully validated by the resolver.

Behavior:
- If the opportunistic SVCB and its signatures are DNSSEC-validated, the resolver MAY
  treat it equivalently to Strict mode for the corresponding data.
- If the opportunistic SVCB is not validated (e.g., unsigned, or validation fails), then:
  - The resolver MAY use only positive "alpn" entries to attempt an upgrade (e.g., dot, doq).
  - The resolver MUST ignore any negative transport signals (e.g., "-do53").
  - The resolver MUST ignore ipv4hint, ipv6hint, tlsa, and any other parameters that
    affect addressing or authentication.
  - The resolver MUST be prepared to immediately fall back to traditional UDP/TCP (Do53)
    upon failure or timeout.

Rationale:
- Opportunistic mode enables low-latency discovery without requiring changes at
  parent zones or prior configuration, while containing risk by limiting use of
  unvalidated data to only positive upgrade attempts.

## 3.2. Strict Mode

Strict mode applies when the resolver explicitly queries for the SVCB RRset at the
authoritative nameserver’s owner name (the nameserver FQDN) and obtains a DNSSEC-signed
response that is successfully validated to the appropriate trust anchor.

Requirements and behavior:
- The resolver MUST issue a direct query for the SVCB RRset at the nameserver’s FQDN.
- The resolver MUST successfully DNSSEC-validate the SVCB RRset and its RRSIGs.
- When validated, the resolver MAY use all fields of the SVCB RDATA for connection
  establishment and policy decisions, including:
  - alpn: positive transport signals (e.g., dot, doq) and any explicitly negative
    transport signals (see below).
  - ipv4hint / ipv6hint: address hints for the authoritative nameserver.
  - tlsa: a new SVCB parameter defined by this document that conveys the TLSA record
    to authenticate TLS/QUIC connections to the authoritative nameserver.
- If a validated SVCB contains an explicit negative transport signal (e.g., "-do53"),
  the resolver SHOULD honor it. For example, "-do53" indicates that legacy UDP/TCP is
  not supported by this authoritative nameserver and the resolver SHOULD attempt only
  the positively advertised alternatives. If all alternatives fail and the negative signal
  is validated, the resolver SHOULD treat that server as unreachable and prefer other 
  authoritative servers for the zone.

Notes:
- This document introduces an extension to the SVCB "alpn" parameter: a leading "-"
  indicates an explicit negative transport signal (e.g., "-do53"). IANA and specification
  updates are required (see IANA Considerations).
- This document also introduces a new SVCB parameter "tlsa" that carries TLSA RDATA for
  the nameserver endpoint. The exact encoding is defined in IANA Considerations. Use of
  "tlsa" is only appropriate when the SVCB is DNSSEC-validated.

## 3.3. Precedence and Interaction

- When both Relaxed and Strict information are available, Strict mode information MUST
  take precedence.
- An Opportunistic-mode SVCB that is DNSSEC-validated is equivalent to Strict for policy
  and usage purposes.
- In the absence of validated information, an Opportunistic signal MUST NOT be used to
  enforce negative policy, alter addressing, or bootstrap authentication material.

## 3.4. Caching and No-OTS

- Resolvers MAY cache Strict-mode SVCB information according to its TTL and MAY use the
  EDNS(0) No-OTS option to avoid redundant hints when sufficient information is cached.
- In Opportunistic mode, resolvers MAY cache positive "alpn" results subject to local
  policy (see Resolver Caching Strategies). When a resolver has sufficient cached
  information, it SHOULD set No-OTS to reduce response size and limit unnecessary hints.

## 3.5. Summary of Permitted Use by Mode

- Opportunistic (unvalidated):
  - MAY use: alpn (positive) only.
  - MUST NOT use: alpn (negative), ipv4hint, ipv6hint, tlsa, or any parameter that
    affects addressing or authentication.
  - MUST support fallback to Do53.
- Strict (validated):
  - MAY use: alpn (positive), alpn (negative with "-" prefix), ipv4hint, ipv6hint,
    tlsa, and other defined parameters.
- Opportunistic (validated):
  - Equivalent to Strict for the validated SVCB.

Implementation note:
- Existing SVCB clients that do not understand negative alpn tokens or the new "tlsa"
  parameter will ignore them and remain interoperable. Clients implementing this
  specification MUST follow the above mode-dependent processing and precedence rules.

# 4. The Opportunistic Signaling Mechanism

The core of this proposal is for an authoritative nameserver to
include an SVCB record in the Additional section of its responses
under specific conditions.

This consists of three parts. The first two are the behaviour of the
authoritative nameserver receiving the query and the behaviour of the
recursive nameserver receiving the response. The final part is a new
EDNS(0) option that defines an OPT-OUT capability.

# 5. Authoritative Nameserver Behaviour

## 5.1. Trigger Conditions for Including the OTS Hint

An authoritative nameserver SHOULD include an OTS Hint when *all* of
the following conditions are met:

1. **Self-Identification:** The responding authoritative own Fully
   Qualified Domain Name (FQDN) (or one of its configured
   aliases/identities) is found within the NS RRset for the queried
   zone.

2. **Transport Capability:** The responding authoritative nameserver
   supports one or more alternative transport protocols (e.g., DoT,
   DoH, DoQ) and is configured to advertise these capabilities.

3. **Presence of the OTS Option:** The query does include an EDNS(0)
   OTS option from the resolver.

4. **Availability of RRSIG SVCB:** The zone in which the nameserver
   name is located is signed, including the SVCB record.

5. **SVCB not present in Answer:** If the SVCB record is present in
   the Answer section (because it was explicitly queried for), then it
   does not have to be included again in the Additional section,
   regardless of whether the resolver has set the OTS Option or not.

## 5.2. Multiple Server Identities

An authoritative nameserver may be known by multiple FQDNs (e.g.,
ns1.example.com, dns.customer.org, ns.cdnprovider.net). To facilitate
condition 1 ("Self-Identification"), authoritative server
implementations MAY include a configuration mechanism (e.g., an
identities list) where operators can list all FQDNs by which the
server is known. This allows the server to correctly identify itself
regardless of the specific name used in the NS RRset.

## 5.3. Format of the DNS Transport Signal SVCB Record

The OTS Hint MUST be an SVCB record with the following
characteristics:

* **OWNER:** The owner name of the SVCB record MUST be the label "_dns" followed by
  the FQDN of the authoritative nameserver itself, as identified in the NS RRset that
 triggered its inclusion (e.g., _dns.ns.dnsprovider.com.).

* **CLASS:** IN (Internet).

* **TYPE:** SVCB.

* **TTL:** The TTL of the SVCB record SHOULD be chosen by the
   authoritative server operator. Choice of TTL is a local configuration
   decision, but unless the supported transports are subject to frequent
   change a value on the order of 24h or more is suggested.

* **SVCB_PRIORITY:** 1. The specific priority value is not critical
   for this hint mechanism, but 1 indicates the highest priority for the
   service.

* **SVCB_TARGET:** . (root). This indicates that the DNS transport
   capabilities described by the SVCB record refer to the owner name of
   the record.

* **SVCB_PARAMS:** A set of Service Parameters indicating the
   supported transport protocols. This document defines the "alpn"
   parameter {{!RFC9460}}, as relevant for signaling DoT
   (alpn=dot), DoH (alpn=doh), DoQ (alpn=doq) and Do53 (alpn=do53).

   This document further defines the SVCB parameters "ipv4hint" and "ipv6hint"
   as allowed to be included in the SVCB record. These keys MUST NOT
   be used by the resolver unless the SVCB record has been successfully
   validated.
   
   Finally a "tlsa" parameter containing the corresponding TLSA record 
   for the certificate used to secure a DoQ or DoT transport. This 
   parameter MUST NOT be used by the resolver unless the SVCB record
   has been successfully validated.

   If any other parameter is present in the SVCB parameter list it
   must be ignored by the resolver.

**Example 1:**

If ns.dnsprovider.net. responds to a query for www.example.com. (in
the unsigned zone example.com.) and ns.dnsprovider.net is listed in
the NS RRset for example.com., it may respond with a DNS message
that contains:
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
_dns.ns.dnsprovider.net. IN SVCB 1 . "alpn=doq,dot,do53"
_dns.ns.dnsprovider.net. IN RRSIG SVCB ...
~~~
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
include the SVCB.

Note: the requirement for the SVCB record to be included only if it is
DNSSEC-signed has the consequence that the OTS transport signal cannot
be present for an unsigned zone using vanity names in the zone for its
nameservers.

**Example 3:**
The resolver explicitly asks for the DNS transport signal for the
authoritative nameserver ns.dnsprovider.net. by querying
for "_dns.ns.dnsprovider.net. SVCB":
~~~
Header: ...

Answer:
_dns.ns.dnsprovider.net.  IN SVCB 1 . (alpn="doq,dot,-do53", tlsa="...")
_dns.ns.dnsprovider.net.  IN RRSIG SVCB ...

Additional:
~~~
Because the resolver uses strict mode (by querying for the SVCB record and
validating the response) all data in the record may be used. In this case that
includes the negative transport for "do53" which will effectively turn off
UDP/TCP use by the resolver for communicating with this particular authoritative
nameserver.

# 6. Recursive Nameserver Behavior

Recursive nameservers adopting this mechanism SHOULD implement the
following logic:

## 6.1. When Sending Queries

1. **OPT-OUT Possibility:** If the resolver already thinks that it
   knows the transport capabilities of the authoritative nameserver
   it is about to send a query to it may opt out from DNS transport
   signaling by including an EDNS(0) "No-OTS" option in the query.

   It is important to be aware that using the No-OTS option consistently
   will make the resolver blind to any changes in the transport
   signals, which is clearly not acceptable. Hence any use of "No-OTS"
   should be restricted to only be used within the TTL of an already
   received and parsed OTS Hint.

## 6.2. When Receiving Responses

1. **Opportunistic Parsing:** When receiving an authoritative DNS
   response, the resolver SHOULD parse the Additional section for SVCB
   records.

2. **Owner Check:** If an SVCB record is found whose owner name
   matches the "_dns" label followed by an authoritative nameserver
   name for the zone to which the query belongs, the resolver MAY
   consider this an OTS Hint.

3. **DNSSEC Validation (Optional but Recommended):** 
   * The resolver SHOULD attempt to DNSSEC validate the OTS Hint. This
   involves validating the SVCB record itself and its corresponding RRSIG
   (if present) against the DNSSEC chain of trust for the zone that owns
   the SVCB record (e.g., dnsprovider.com for _dns.ns.dnsprovider.com).

   * If validation succeeds: The OTS Hint is considered a **trusted
   signal**. The resolver MAY then use all the transport signals provided in
   the SVCB record when deciding on alternative transport choices for
   subsequent queries to that specific authoritative nameserver.

   * If validation fails, or no RRSIG is present: The OTS Hint MUST
   be treated as an **unvalidated hint**. The resolver MAY still
   opportunistically attempt to use the signaled alternative transports,
   but MUST be prepared for immediate fallback to traditional transports
   (UDP/TCP) if the connection fails. This is particularly relevant for
   scenarios like vanity names (e.g., ns.customer.com where customer.com
   is an unsigned zone, but the underlying server ns.dnsprovider.com is
   capable).

4. **Prioritization:**
* Any DNSSEC-validated SVCB record found via explicit query (e.g.,
ns.example.com for a queried domain) MUST take precedence over any
unvalidated OTS Hint.

* The OTS Hint is a mechanism to *discover* capabilities
opportunistically, not to override trusted delegation or service
configuration.

5. Fallback: Resolvers MUST always be prepared to fall back to
traditional UDP/TCP transport if an attempt to use an alternative
transport based on an OTS Hint (especially an unvalidated one) fails
or times out.

## 6.3. Upgrading the DNS Transport Signal

If an unvalidated opportunistic transport signal has been received the
resolver may chose to upgrade that signal, either immediately or when
the transport signal is close to expiration from the resolver cache. An
upgraded transport signal allows the resolver to operate in Strict Mode,
and then use all the information in the SVCB record.

## 6.3. Authentication of the Authoritative Nameserver

Authentication of the authoritative nameserver is not an explicit goal.
The reason is that as an opportunistic mechanism it will not always be
possible to do such authentication. Some of the options that do exist
are listed below.

Authentication of the authoritative nameserver may be done either by
validation of a DNSSEC RRSIG over the SVCB record containing the OTS
Hint or by verification of the server certificate presented in the
set up of the communication (be it over DoT, DoQ or DoH).

As there will not always be a DNSSEC signature to validate that option
is opportunistic at best. Likewise, while it may sometimes be possible
to validate the server cert against a DNSSEC-signed TLSA record, it will
not always be an option.

Finally, validating the server cert against a list of well-known public
Certificate Authorities is possible, but there is no standardized way
to determine which CAs are appropriate for DNS server certificates.

However, even without strong authentication of the authoritative server
the proposed mechanism still provides benefits (privacy, potential
performance improvements) and for that reason cryptographic verification
of the server identity is not a requirement.

## 6.4. Resolver Caching Strategies

Resolvers implementing the DNS OTS Hint mechanism have several options
for caching the transport signals received via OTS Hints. 

A suggested primary strategy is to set the EDNS(0) No-OTS option
when no transport signaling information is needed. This may be because
the resolver already knows the authoritative nameserver's transport
capabilities from a previous response (with a TTL that has not expired)
or for some other reason.

The primary caching strategy SHOULD be "Standard DNS Cache", i.e.
treat the SVCB record like any other DNS record, caching it according to
its TTL. This is the simplest approach and will simply cause the resolver
to fall back to UDP for one query if the transport signal data has expired.

For a more detailed analysis of possible caching logic, see {{!RFC9539}},
section 4.

Note that the resolver always has the option of not using the EDNS(0)
No-OTS option whenever the cache entry is getting close to expiry.

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

# 7. Strict Recursive Nameserver Behavior

This section contains two options for resolver behavior. The first one
is easier for the resolver but places more strict requirements on
the authoritative servers that serve a zone. The second one is the other
way around.

# 7.1 First option.

In this option, there is a requirement that for a zone to support
strict mode, all nameservers for the zone have to support strict mode.
In addition the OTS hint for nameservers that support strict mode has
to include a Strict Mode DNS Transport (SMDT) parameter to signal that
this nameserver support strict mode.
Without an additional flag, a resolver may something find a nameserver
that supports opportunistic mode and assume strict mode and the next time
find a different nameserver and switch back to an unencrypted transport.

[ for SMDT, we should consider putting the SVCB in the authority section. 
That guarantees that it ends up add the resolver (doesn't accidentally get
truncated) and gets validated ]

If the resolver has a strict mode secure connection to the parent of
the zone that the resolver tries to access then it can (for the
purpose of setting up a strict mode secure connection) trust the delegation
NS records it receives from the parent.

Otherwise the resolver MUST lookup the NS RRset at the apex of the child
zone and MUST DNSSEC validate the reply. If the DNSSEC validation status
is insecure or indeterminate then a strict mode secure connection is not
possible and the resolver can access the child zone using unencrypted DNS
or using opportunistic mode.

If the DNSSEC validation status is bogus then the resolver MUST treat the zone
as unreachable. Otherwise, if the DNSSEC validation status is secure, then
the resolver proceeeds with the next step.

To support strict mode, all nameservers have to support strict mode. 
So a resolver can just pick a random nameserver as a starting point.
- if the nameserver is in a zone with a strict mode secure connection then
  it trusts the result of a A or AAAA query for the nameserver. If
  the reply includes an OTS hint with the SMDT flag then a strict mode
  secure connection can be established and this step terminates.
  If an OTS hint is received without the SMDT flag then the resolver may
  switch to opportunistic mode.
  Otherwise, strict mode is not available and the resolver fall backs to 
  unencrypted DNS.
- if the nameserver is in a DNSSEC secure zone then the resolver needs proof
  that either the OTS hint exists or that it doesn't exist. If the OTS hint
  exists and has the SMDT flag then a strict mode secure connection can be
  established and this step terminates.
  Note that nameservers that support strict mode include the OTS hint plus
  signatures in a reply to an A or AAAA query.
  The resolver does have to send a separate query to get a negative result.
  If an OTS hint is received without the SMDT flag then the resolver may
  switch to opportunistic mode.
  Otherwise, strict mode is not available and the resolver falls back to 
  unencrypted DNS.
  If there is a failure to prove either presence or absence of the OTS hints
  then the resolver MAY either consider the zone unreachable or try another
  nameserver. The resolver MUST NOT use this nameserver to query the child
  zone.
- if the nameserver is in a DNSSEC insecure zone, then no strict mode 
  secure connection is possible to this nameserver.
  If there is a failure to determine whether the zone is insecure then
  the resolver MUST NOT use this nameserver to query the child zone.
  The resolver MAY either consider the zone unreachable or try another
  nameserver.

To handle inconsistencies, if a resolver finds a strict mode nameserver for
a zone and later finds a nameserver that does not support strict mode, then
the resolver MUST set the status of the zone to not support strict mode.

# 7.2 Second option.

For this option, the resolver does all the work. No SMDT flag is needed.

If the resolver has a strict mode secure connection to the parent of
the zone that the resolver tries to access then it can (for the
purpose of setting up a strict mode secure connection) trust the delegation
NS records it receives from the parent.

Otherwise the resolver MUST lookup the NS RRset at the apex of the child
zone and MUST DNSSEC validate the reply. If the DNSSEC validation status
is insecure or indeterminate then a strict mode secure connection is not
possible and the resolver can access the child zone using unencrypted DNS
or using opportunistic mode.

If the DNSSEC validation status is bogus then the resolver MUST treat the zone
as unreachable. Otherwise, if the DNSSEC validation status is secure, then
the resolver proceeeds with the next step.

In the next step, the resolver has to find at least one nameserver that
offers a strict mode secure connection or it has to prove that none of the
nameservers offer a strict mode secure connection.

The resolver iterates over the list of nameservers for the child zone and
for each nameserver:
- if the nameserver is in a zone with a strict mode secure connection then
  the resolver trusts the result of a A or AAAA query for the nameserver. If
  the reply includes an OTS hint then a strict mode secure connection 
  can be established and this step terminates.
  The resolver MAY check the
  remaining nameservers to see if they offer strict mode as well.
- if the nameserver is in a DNSSEC secure zone then the resolver needs proof
  that either the OTS hint exists or that it doesn't exist. If the OTS hint
  exists then a strict mode secure connection can be established and this
  step terminates.
  The resolver MAY check the
  remaining nameservers to see if they offer strict mode as well.
  If there is a failure to prove either presence or absence of the OTS hints
  the the resolver MUST note this (to be used at the end of this algorithm).
- if the nameserver is in a DNSSEC insecure zone, then no strict mode 
  secure connection is possible to this nameserver.
  The resolver continues with the next nameserver.

The final step is to determine whether the resolver can accept that a
strict mode connection was not available. If there was any failure, with
looking up a nameserver in a zone that has strict mode secure connection,
in a secure zone if the DNSSEC validation status is bogus, or if there was an
error determining the DNSSEC status of OTS hint, then the resolver MUST
consider the child zone unreachable.

# 7. The EDNS(0) No-OTS Option

To provide a mechanism for resolvers to explicitly opt out of
receiving transport signals, this document defines a new EDNS(0)
option called "No-OTS" (NOTS). When included in a query, this
option signals to the authoritative server that the resolver does not
want to receive any transport signals in the response.

The typical use case is to set the EDNS(0) No-OTS option when
the resolver already has the transport information it needs.

The EDNS(0) No-OTS option is structured as follows:

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
    for No-OTS.

OPTION-LENGTH:
    2 octets / 16 bits (defined in {{!RFC6891}}) contains
    the length of the payload in octets. For the No-OTS option,
    this value MUST be 0 as there is no payload.

When an authoritative server receives a query containing the EDNS(0)
No-OTS option, it SHOULD NOT include any OTS Hints in the
response, regardless of whether it would normally do so based on the
conditions described in Section 5.1.

This option provides a clean way for resolvers to opt out of receiving
transport signals, which may be useful in scenarios where:

* The resolver has recently established transport preferences for a
  particular authoritative server and that transport signal has not
  expired.
* The resolver does not support or does not want to use alternative
  transports
* The resolver wants to minimize response sizes
* The resolver is operating in an environment where transport signals
  are not needed or desired

The No-OTS option is designed to be a simple, lightweight
mechanism that can be used to disable transport signaling without
affecting the normal operation of DNS resolution.

# 8. Comparison with DELEG

The idea to use an SVCB alpn parameter for transport signaling
originated with the work on DELEG {{?I-D.draft-ietf-deleg}}.  The
current document uses the same data format, but as an opportunistic
addition to the Additional section rather than as integral part of a
changed delegation mechanism.

Both mechanisms have distinct use cases, and pros and cons. The major
advantage of the DELEG mechanism is that it cannot be spoofed or
filtered, as it is an integral part of an upcoming protocol change.

The opportunistic mechanism described here has the major advantage of
being available immediately without any changes to the DNS
protocol. Furthermore, as it is a signal directly from an
authoritative nameserver, a single OTS Hint may allow the recipient
recursive nameserver to upgrade the transport used for all the zones
served by that authoritative nameserver (which may be millions)
without the need to make any changes to the zones, nor to the parent
zones.

Given the current DNS landscape with a limited number of very large
providers of authoritative DNS service and a limited number of large
providers of recursive DNS service the opportunistic model described
here has the potential of enabling upgrading the transport for a
significant fraction of the DNS traffic with a limited amount of
effort.

# 9. Security Considerations

* **Spoofing of Unvalidated Hints:** An OTS Hint that cannot be DNSSEC
validated (e.g., for ns.example.com where example.com is unsigned)
is susceptible to spoofing by an on-path attacker. Such an attacker
could insert a fake SVCB record advertising a non-existing transport,
thereby denying connection over that transport. However, since the
hint is opportunistic and not required for DNS resolution, the
worst-case scenario is that the resolver attempts a connection that
fails and then falls back to traditional transports.  Security for the
actual DNS data remains unaffected. The cryptographic validation of
TLS/QUIC (via X.509 certificates) for DoT/DoQ would still protect the
integrity and privacy of the connection itself.

* **DNSSEC Validation:** When a OTS Hint is signed by DNSSEC (e.g.,
the ns.dnsprovider.net SVCB record from a signed dnsprovider.net zone),
it provides a trusted signal. Resolvers SHOULD leverage DNSSEC validation
to distinguish between trusted and unvalidated hints.

* **No New Attack Vectors:** This mechanism does not introduce new
attack vectors for DNS data itself, as it primarily concerns transport
discovery. It relies on the existing security properties of DoT, DoH
and DoQ for actual session security.

* **Safe Rollout:** As existing recursive nameservers carefully avoid
data in the Additional section that they do not need, the OTS Hint
will be ignored by everyone except recursive nameservers that
understand the OTS Hint.

* **No-OTS enables a downgrade attack:** If an attacker is able to
inject a No-OTS option to an outbound query then no transport signal
will be provided. However, this is a consequence of the opportunistic
nature of the OTS Hint and not worse than not being able to do
transport signaling at all.

# 10. Operational Considerations

* **Response Size:** Including an SVCB record in the Additional
section will increase the size of UDP responses. Authoritative server
operators should consider the potential for UDP fragmentation or TCP
fallback if responses become excessively large, though a single SVCB
record is typically small. Recursive nameservers should usually set
the EDNS(0) No-OTS when they already have the transport signaling
information.

* **Server Configuration:** Authoritative server implementations will
need configuration options to enable this feature and manage the
identities list.

* **Rollout Strategy:** This mechanism supports a gradual rollout.
Authoritative servers can begin sending hints without requiring
changes from resolvers, and resolvers can begin processing hints
without requiring all authoritative servers to implement the feature.

* **Monitoring:** As there is extremely limited data on effects of
alternative DNS transports for communication resolver to authoritative
nameserver it is strongly suggested that monitoring (of use,
resource consumption, etc) is considered.

# 11. IANA Considerations

## 11.1. No-OTS EDNS(0) Option

This document defines a new EDNS(0) option, entitled "No-OTS",
assigned a value of TBD in the "DNS EDNS0 Option Codes (OPT)" registry.

~~~
   +-------+--------------------------+----------+----------------------+
   | Value | Name                     | Status   | Reference            |
   +-------+--------------------------+----------+----------------------+
   | TBD   | No-OTS                   | Standard | ( This document )    |
   +-------+--------------------------+----------+----------------------+
~~~

**Note to the RFC Editor**: In this section, please replace
occurrences of "(This document)" with a proper reference.

## 11.2. SVCB/HTTPS Parameter: tlsa

This document requests registration of a new SVCB/HTTPS parameter in the
"SVCB and HTTPS Parameters" registry:

~~~
   +-------+--------+--------------------+----------------------+
   | Key   | Name   | Meaning            | Reference            |
   +-------+--------+--------------------+----------------------+
   | TBD   | tlsa   | Carries TLSA data  | ( This document )    |
   +-------+--------+--------------------+----------------------+
~~~

Presentation and wire format: The value carries one or more TLSA RRs
associated with the nameserver endpoint. Exact encoding and size limits
are defined by this document (TBD). Use of this parameter is appropriate
only when the containing SVCB RRset is DNSSEC-validated (see Section 3).

## 11.3. SVCB alpn Negative Tokens

This document updates the "alpn" SVCB parameter syntax to permit negative
transport tokens by prefixing with a hyphen ("-") (e.g., "-do53"). The
semantics of a negative token are to indicate explicit non-support of the
named transport by the authoritative nameserver.

IANA is requested to note this extension in the "SVCB and HTTPS Parameters"
registry entry for "alpn" and reference this document. No new ALPN IDs are
registered by this change; negative tokens reuse existing ALPN identifiers
with a leading hyphen as a presentation-only convention.

# 12. Acknowledgements

* The participants of the DELEG Working Group, Peter Thomassen and Christian Elmerot.

# Appendix A. Rationale for Using the Additional Section

**Note to the RFC Editor**: Please remove this entire section before publication.

When designing a mechanism that rely on sending new information in DNS
responses without changing the current DNS protocol, the Additional section
has the major advantage of being ignored by legacy software. This property
makes it possible to essentially deploy the proposed mechanism immediately,
as it will not cause problems with existing DNS infrastructure.

* Existing authoritative nameservers will not provide any OTS Hint in the
  Additional section.

* Existing resolvers will actively ignore any OTS Hint in the Additional section.

Only DNS nameservers (authoritative or recursive) that are aware of the
proposed mechanism will use it.

The downside is that it is not possible to strictly rely on anything
specific being present in the Additional section, as it may be stripped off by
a middle man or even by the sending nameserver (eg. due to packet size
constraints). For this reason it is not possible to provide more than an
opportunistic transport signal.

Another issue is whether the data provided may be trusted or not. A
spoofed positive signal (eg. claiming DoQ support when this is false)
would not be catastrophic. However, a spoofed negative signal
(eg. claiming no Do53 support while such support is present) would be
dangerous. For this reason (ability to provide both positive and
negative signals) the OTS hint MUST be secure and hence DNSSEC signed.

// This is
// usually a major issue and the primary reason that data in the Additional
// section is actively ignored by resolvers. In this particular case, though,
// even an untrusted transport signal is better than no signal at all. Furthermore,
// the only effect of a forged or otherwise incorrect transport signal is a,
// typically failed, connection attempt to an authoritative nameserver that
// does not support the advertised transport. This will cause immediate fallback
// to "Do53", i.e. traditional DNS over UDP/TCP and the non-availability of the
// advertised transport will be remembered by the resolver (for some suitable time).

Hence, using the Additional section for opportunistic transport signaling has
vastly more benefits than drawbacks.

# Appendix B. SVCB ALPN Negative Tokens

This appendix defines a presentation-time extension to the SVCB "alpn" parameter
that allows an authoritative nameserver to signal explicit non-support of a
transport by prefixing an existing ALPN token with a hyphen ("-"). For example,
"-do53" indicates that legacy UDP/TCP transport is not supported.

Processing rules:
- Negative tokens are only actionable when the SVCB RRset is DNSSEC-validated
  (i.e., Strict mode, or Relaxed mode with successful validation). In these
  cases, resolvers SHOULD honor negative tokens when selecting transports.
- In unvalidated Relaxed mode, resolvers MUST ignore negative tokens.
- Negative tokens do not define new ALPN identifiers; they reuse existing
  identifiers in presentation form with a leading hyphen.

Examples:
- alpn="dot,doq"           -> Indicates support for DoT and DoQ.
- alpn="-do53,dot"         -> Indicates no Do53; use DoT (validated modes only).
- alpn="-do53,doq,dot"     -> Indicates no Do53; prefer DoQ/DoT (validated modes only).

Interoperability considerations:
- Implementations that do not understand negative tokens will ignore them
  per SVCB parameter processing and remain interoperable.
- This extension does not alter on-the-wire encoding for ALPN; it is a
  presentation-layer convention. IANA considerations for documentation
  of this convention are provided in Section 11.3.

--- back

# Change History (to be removed before publication)

> Initial public draft
