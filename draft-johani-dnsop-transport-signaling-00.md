---
title: "Authoritative DNS Transport Signaling"
abbrev: "Authoritative DNS Transport Signaling"
docname: draft-johani-dnsop-transport-signaling-00
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

informative:

--- abstract

This document proposes a mechanism for authoritative DNS servers to
opportunistically signal their support for alternative transport
protocols (e.g., DNS over TLS (DoT), DNS over HTTPS (DoH) and DNS over
QUIC (DoQ)) directly within the additional section of authoritative
DNS responses. This "hint-based" approach aims to enable recursive
resolvers to discover and upgrade transport connections more
efficiently, thereby improving privacy, security, and performance for
subsequent interactions. The mechanism is designed to be safe,
backward-compatible, and effective even when DNSSEC validation of the
hint is not possible or desired.

--- middle

# **1\. Introduction**

The Domain Name System (DNS) primarily relies on UDP and TCP for
communication between recursive resolvers and authoritative servers.
While these protocols are well-established, there is a growing
interest in leveraging modern transport protocols like DNS over TLS
(DoT) {{!RFC7858}}, DNS over HTTPS (DoH) {{!RFC9461}} and DNS over
QUIC (DoQ) {{!RFC9250}} to enhance privacy, security, and performance.

Existing efforts to signal service connection information, such as the
SVCB and HTTPS DNS records {{!RFC9460}} {{!RFC9461}}, primarily focus
on service discovery mechanisms where a client explicitly queries for
these records, often from a parent zone. While robust, this approach
can introduce additional latency and requires explicit configuration
at the parent zone level.

This document proposes an "DNS Opportunistic Transport
Signaling" (DNS OTS) mechanism. DNS OTS, aka an "OTS Hint" allows 
an authoritative DNS nameserver to directly convey its transport
capabilities as a hint within the additional section of responses
to queries where it identifies itself as an authoritative nameserver
for the requested zone. This direct, in-band signaling provides a
low-latency discovery path, even when a formal, validated signal is
not available.

# **2\. Terminology**

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals.

* **Authoritative Nameserver (Auth Server):** A DNS server that holds
the authoritative zone data for a specific domain.

* **Recursive Nameserver (Recursor):** A DNS server that processes user
queries, performing iterative lookups to authoritative servers to
resolve domain names.

* **OTS Hint:** An SVCB record included opportunistically in the
additional section of an authoritative DNS response, intended to
signal the responding authoritative nameserver's transport capabilities.

* **SVCB Record:** Service Binding record, as defined in {{!RFC9460}}.

# **3\. The Opportunistic Signaling Mechanism**

The core of this proposal is for an authoritative nameserver to
include an SVCB record in the additional section of its responses
under specific conditions.

## **3.1\. Trigger Conditions for Including the OTS Hint**

An authoritative nameserver SHOULD include an OTS Hint when *all* of
the following conditions are met:

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

### **3.1.1\. Multiple Server Identities**

An authoritative nameserver may be known by multiple FQDNs (e.g.,
ns1.example.com, dns.customer.org, ns.cdnprovider.net). To facilitate
condition 2 ("Self-Identification"), authoritative server
implementations MAY include a configuration mechanism (e.g., an
identities list) where operators can list all FQDNs by which the
server is known. This allows the server to correctly identify itself
regardless of the specific name used in the NS RRset.

## **3.2\. Format of the OTS Hint**

The OTS Hint MUST be an SVCB record with the following
characteristics:

* **OWNER:** The owner name of the SVCB record MUST be the FQDN of the
authoritative nameserver itself, as identified in the NS RRset that
triggered its inclusion (e.g., ns.dnsprovider.com.).

* **CLASS:** IN (Internet).  

* **TYPE:** SVCB.  

* **TTL:** The TTL of the SVCB record SHOULD be chosen by the
authoritative server operator. A TTL similar to that of the NS record
is RECOMMENDED.

* **SVCB\_PRIORITY:** 1\. The specific priority value is not critical
for this hint mechanism, but 1 indicates the highest priority for the
service.

* **SVCB\_TARGET:** . (root). This indicates that the DNS transport
capabilities described by the SVCB record refer to the owner name of
the record.

* **SVCB\_PARAMS:** A set of Service Parameters indicating the
supported transport protocols. In this document only the alpn parameter
{{!RFC9460}} is described, as relevant for signaling DoT (alpn=dot),
DoH (alpn=doh) and DoQ (alpn=doq).

**Example:**  

If ns.dnsprovider.com responds to a query for www.customer.com and
ns.dnsprovider.com is listed in the NS RRset, the additional section
may contain: `ns.dnsprovider.com. IN SVCB 1 . "alpn=doq,dot"`

## **4\. Recursive Resolver Behavior**

Recursive nameservers adopting this mechanism SHOULD implement the
following logic:

1. **Opportunistic Parsing:** When receiving an authoritative DNS
response, the resolver SHOULD parse the additional section for SVCB
records.

2. **Owner Check:** If an SVCB record is found whose owner name
matches an authoritative nameserver identified in the Authority or
Answer sections of the *current* response, the resolver MAY consider
this an OTS Hint.

3. **DNSSEC Validation (Optional but Recommended):**  

* The recursive resolver SHOULD attempt to DNSSEC validate the
OTS Hint. This involves validating the SVCB record itself and its
corresponding RRSIG (if present) against the DNSSEC chain of trust for
the zone that owns the SVCB record (e.g., dnsprovider.com for
ns.dnsprovider.com).

* **If validation succeeds:** The OTS Hint is considered a **trusted
signal**. The resolver MAY then prefer the signaled alternative
transports for subsequent queries to that specific authoritative
nameserver.

* **If validation fails, or no RRSIG is present:** The OTS Hint MUST
be treated as an **unvalidated hint**. The resolver MAY still
opportunistically attempt to use the signaled alternative transports,
but MUST be prepared for immediate fallback to traditional transports
(UDP/TCP) if the connection fails. This is particularly relevant for
scenarios like vanity names (e.g., ns.customer.com where customer.com
is an unsigned zone, but the underlying server ns.dnsprovider.com is
capable).

4. **Caching:** Validated and unvalidated hints MAY be cached by the
recursive resolver for a duration determined by their TTL or a local
policy. Caching unvalidated hints SHOULD be done with care, and they
SHOULD be invalidated quickly if a connection attempt based on them
fails.

5. **Prioritization:**  

* Any DNSSEC-validated SVCB record found via explicit query
(e.g., ns.example.com for a queried domain MUST take precedence
over any unvalidated OTS Hint.

* The OTS Hint is a mechanism to *discover* capabilities
opportunistically, not to override trusted delegation or service
configuration.

6. **Fallback:** Recursive resolvers MUST always be prepared to fall
back to traditional UDP/TCP transport if an attempt to use an
alternative transport based on an OTS Hint (especially an
unvalidated one) fails or times out.

# **5\. Comparison with DELEG**

The idea to use an SVCB alpn parameter for transport signaling
originated with the work on DELEG {{?draft-wesplaap-dnsop-deleg}}.
The current document uses the same data format, but as an
opportunistic addition to the Additional Section rather than as
mandatory part of a changed delegation mechanism.

Both mechanisms have distinct use cases, and pros and cons. The major
advantage of the DELEG mechanism is that is cannot be spoofed or
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

# **5\. Security Considerations**

* **Spoofing of Unvalidated Hints:** A OTS Hint that cannot be
DNSSEC validated (e.g., for ns.customer.com where customer.com is
unsigned) is susceptible to spoofing by an on-path attacker. Such an
attacker could insert a fake SVCB record advertising a non-existing
transport, thereby denying connection over that transport. However,
since the hint is opportunistic and not required for DNS resolution,
the worst-case scenario is that the recursive resolver attempts a
connection that fails or falls back to traditional transports.
Security for the actual DNS data remains unaffected. The cryptographic
validation of TLS/QUIC (via X.509 certificates) for DoT/DoQ would
still protect the integrity and privacy of the connection itself.

* **DNSSEC Validation:** When a OTS Hint is signed by DNSSEC (e.g.,
ns.dnsprovider.com SVCB record from a signed dnsprovider.com zone), it
provides a trusted signal. Recursive resolvers SHOULD leverage DNSSEC
validation to distinguish between trusted and unvalidated hints.

* **No New Attack Vectors:** This mechanism does not introduce new
attack vectors for DNS data itself, as it primarily concerns transport
discovery. It relies on the existing security properties of DoT, DoH and
DoQ for actual session security.

* **Safe Rollout:** As existing recursive servers carefully avoid data
in the Additional Section that they do not need, the OTS Hint will
be ignored by everyone except recursive servers that understand the Hint.

# **6\. Operational Considerations**

* **Response Size:** Including an SVCB record in the additional
section will increase the size of UDP responses. Authoritative server
operators should consider the potential for UDP fragmentation or TCP
fallback if responses become excessively large, though a single SVCB
record is typically small.

* **Server Configuration:** Authoritative server implementations will
need configuration options to enable this feature and manage the
identities list.

* **Rollout Strategy:** This mechanism supports a gradual rollout.
Authoritative servers can begin sending hints without requiring
changes from recursive resolvers, and recursive resolvers can begin
processing hints without requiring all authoritative servers to
implement the feature.

# **7\. IANA Considerations**

This document requires no IANA actions.

# **8\. Acknowledgments**

...

# **9\. References**

## **9.1. Normative References**

* \[RFC2119\] Bradner, S., "Key words for use in RFCs to Indicate
Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March
1997,
[https://www.rfc-editor.org/info/rfc2119](https://www.rfc-editor.org/info/rfc2119).

* \[RFC7858\] Hu, Z., et al., "DNS over TLS", RFC 7858, DOI
10.17487/RFC7858, May 2016,
[https://www.rfc-editor.org/info/rfc7858](https://www.rfc-editor.org/info/rfc7858).

* \[RFC8174\] Leiba, B., "Ambiguity of Ought to and Should in RFCs",
BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
[https://www.rfc-editor.org/info/rfc8174](https://www.rfc-editor.org/info/rfc8174).

* \[RFC9250\] Hu, Z., et al., "DNS over QUIC", RFC 9250, DOI
10.17487/RFC9250, May 2022,
[https://www.rfc-editor.org/info/rfc9250](https://www.rfc-editor.org/info/rfc9250).

* \[RFC9460\] Schinazi, D., "SVCB and HTTPS DNS Resource Records", RFC
9460, DOI 10.17487/RFC9460, November 2023,
[https://www.rfc-editor.org/info/RFC9460](https://www.google.com/search?q=https://www.rfc-editor.org/info/RFC9460).

* \[RFC9461\] Schinazi, D., "The HTTPS DNS Resource Record", RFC 9461,
DOI 10.17487/RFC9461, November 2023,
[https://www.rfc-editor.org/info/RFC9461](https://www.google.com/search?q=https://www.rfc-editor.org/info/RFC9461).

