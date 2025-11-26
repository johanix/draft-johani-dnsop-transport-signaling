---
title: "DNS Transport Signaling: P-mode and PA-mode"
abbrev: "DTS"
docname: draft-dts-00
date: {DATE}
category: std

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
    country: The Netherlands
    email: philip@nlnetlabs.nl
  - ins: S. Dickinson
    name: Sara Dickinson
    organization: Sinodun IT
    country: United Kingdom
    email: sara@sinodun.com

normative:

informative:

--- abstract

This document defines a unified model and terminology for signaling and
establishing encrypted transports between recursive resolvers and
authoritative nameservers. It introduces two resolver-to-authoritative
connection modes:

  - P-mode (Private): opportunistic encryption that provides privacy
    against passive observers without authenticating the authoritative
    endpoint or its authority for a specific child zone.

  - PA-mode (Private and Authenticated): encryption with endpoint
    authentication and proof that the connected server is authoritative
    for the target child zone, resisting active impersonation and
    downgrade (modulo denial-of-service).

The mechanisms build on DNS Transport Signaling (DTS) carried in SVCB
records, obtained either opportunistically in the Additional section or
via explicit queries, combined with DNSSEC validation and, when needed,
TLSA-based authentication. The goal is to accelerate the transition of
DNS from cleartext to encrypted transport without requiring content
changes in parent or child zones.

--- middle

# 1. Introduction

The DNS widely uses cleartext UDP and TCP (Do53) between resolvers and
authoritative nameservers. While DNSSEC provides origin authentication
and integrity for signed records, it does not protect metadata or
queries from observation. Modern transports such as DoT, DoH, and DoQ
offer confidentiality and, with appropriate authentication, endpoint
integrity.

This document describes how resolvers and authoritative nameservers can
rapidly and incrementally deploy encrypted transports using DNS
Transport Signaling (DTS) in SVCB records, without requiring changes to
zone content. Two connection modes are defined:

  - P-mode: opportunistic encryption providing privacy against passive
    observers.
  - PA-mode: encryption plus authentication of the authoritative
    endpoint and its authority for the child zone, resisting active
    attackers.

The central design objective is to enable deployable privacy now, and
authenticated encrypted service where feasible, with minimal
coordination and no changes to parent or child zone data.

## 1.1. Prior Art and Context

Opportunistic multi-transport probing was introduced in RFC9539. This
document improves on that by defining an explicit signaling mechanism
using SVCB carried in the Additional section (opportunistic) or via
direct queries (validated), and by defining PA-mode that composes
validated transport signaling with authoritative confirmation of the
child’s NS RRset.

# 2. Threat Model

We consider:

  - Passive attacker: observes traffic on-path but cannot modify it.
  - Active attacker: on-path and capable of modifying, injecting, or
    dropping packets (including DNS response rewriting, Additional
    section stripping, and downgrade attempts).
  - Off-path attacker: attempts spoofing without path visibility (out of
    scope for transport-layer protections beyond standard DNS defenses).

Risks:
  - Confidentiality: query/metadata exposure on cleartext links.
  - Downgrade: preventing or stripping signals to force cleartext.
  - Impersonation: redirecting resolver connections to an attacker
    endpoint (e.g., via forged NS RRsets or unvalidated SVCB).
  - Fragmentation/size-based issues: truncation or loss of Additional
    data.
  - Denial-of-service: preventing establishment of encrypted or
    authenticated connections (cannot be fully prevented).

Security goals:
  - P-mode: mitigate passive observation; tolerate downgrade with
    fallback; avoid reliance on unvalidated negative signals.
  - PA-mode: authenticate the authoritative endpoint and its authority
    for the child zone, detect active interference, and avoid fallback
    to unauthenticated transport for that server.

# 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" are to be interpreted as described in BCP 14 when, and only
when, they appear in all capitals.

  - Authoritative Nameserver (Authoritative, Auth server): DNS server
    serving authoritative data for a zone.
  - Recursive Nameserver (Resolver): DNS server performing iterative
    resolution on behalf of clients.
  - DTS (DNS Transport Signaling): information conveyed via SVCB about a
    nameserver’s transport capabilities.
  - DTS Hint: an SVCB record at owner name "_dns.<nsname>" included in
    the Additional section of a response, indicating supported
    transports for that nameserver.
  - Insecure Transport Signal: a transport signal (e.g., SVCB content)
    that is not DNSSEC-validated; suitable only for positive upgrade
    hints in P-mode.
  - Secure Transport Signal: a DNSSEC-validated transport signal
    (SVCB/HTTPS RRset validated to a trust anchor).
  - Strict NS revalidation:
    - Insecure: resolver obtains NS and A/AAAA (Infrastructure records)
      without DNSSEC validation.
    - Secure: resolver obtains DNSSEC-validated NS and A/AAAA for the
      child zone or receives them via a protected referral path.
  - Secure Signaling Chain: Secure Transport Signal + Secure Strict NS
    revalidation. This chain enables PA-mode by providing both an
    authenticated transport advertisement and proof of authoritativeness
    for the child zone.
  - P-mode (Private): opportunistic encrypted connection; privacy
    against passive attackers; no proof that the endpoint is
    authoritative for the specific child zone.
  - PA-mode (Private and Authenticated): encrypted connection where the
    resolver authenticates the endpoint and confirms it is authoritative
    for the child zone. Active impersonation is detected; only DoS
    remains feasible.
  - No-DTS: an EDNS(0) option allowing resolvers to request that
    authoritative servers omit DTS hints in responses when not needed.
  - SVCB alpn negative token "-do53": presentation-time token indicating
    explicit lack of legacy UDP/TCP support. Deprecated by this document
    in favor of the "transport" parameter (do53:0). If encountered,
    actionable only when the SVCB RRset is DNSSEC-validated.
  - SVCB parameter "tlsa": conveys TLSA RDATA associated with the
    nameserver endpoint; actionable only when DNSSEC-validated.
  - SVCB parameter "transport": a private-use parameter that expresses
    per-transport traffic fraction caps requested by the authoritative
    server. The value is a comma-separated list of items of the form
    "<name>:<percent>", e.g., "doq:10,dot:100,do53:0". Semantics:
    - Each "<percent>" is an integer from 0 to 100 and represents a
      maximum fraction of resolver traffic the server requests to receive
      over that transport.
    - If both "transport" and "alpn" are present, "transport" takes
      precedence for transport selection and shaping; "alpn" is a
      compatibility fallback.
    - If only "alpn" is present, the resolver SHOULD interpret it as
      "transport" where all listed transports are mapped to 100 (e.g.,
      alpn="dot,doq" => transport="dot:100,doq:100").
    - The directive do53:0 is equivalent to the deprecated alpn token
      "-do53".

# 4. Achieving P-mode (Private)

P-mode provides confidentiality against passive observers and attempts
opportunistic upgrades to encrypted transports. It does not prove the
endpoint is authoritative for the target child zone.

## 4.1. Authoritative Server Behavior

An authoritative server SHOULD include a DTS Hint in the Additional
section when all are true:
  1. Self-identification: the server’s own FQDN (or configured identity)
     appears in the NS RRset for the queried zone.
  2. Transport capability: the server supports one or more encrypted
     transports (e.g., DoT, DoQ, DoH) and is configured to advertise
     them; optionally it can advertise lack of Do53 via "-do53" (only
     effective for validated consumers).
  3. Not redundant: if the SVCB RRset was explicitly queried and is in
     the Answer, it need not be duplicated in Additional.

 The SVCB owner name MUST be "_dns.<nsname>". The target SHOULD be ".".
 The "transport" parameter SHOULD be used to express per-transport caps
 (e.g., transport="doq:10,dot:100,do53:0"). If "alpn" is present, it is
 a compatibility fallback; when both are present, "transport" takes
 precedence and "alpn" MAY be ignored for selection and shaping. The
 "ipv4hint"/"ipv6hint" and "tlsa" parameters, if included, are only
 actionable by resolvers when the SVCB RRset is DNSSEC-validated.

## 4.2. Resolver Behavior

Upon receiving a response:
  - Parse Additional for SVCB with owner "_dns.<nsname>" matching a
    nameserver for the relevant zone.
  - If the SVCB RRset and RRSIG validate, the resolver MAY treat it as a
    Secure Transport Signal and use all parameters consistent with local
    policy.
  - If unvalidated: the resolver MAY attempt only positive upgrades
    indicated by "transport" or "alpn". When "transport" is present but
    unvalidated, the resolver MAY treat per-transport percentages as
    advisory caps only for encrypted transports (e.g., "doq:10" may be
    used to throttle attempts), MUST NOT enforce negative policy for
    legacy transports (i.e., MUST ignore do53:0), MUST ignore "ipv4hint",
    "ipv6hint", and "tlsa", and MUST be ready to fall back to Do53
    immediately on failure/timeouts.

## 4.3. Caching and No-DTS

Resolvers MAY cache validated SVCB information per TTL. When sufficient
information is cached, a resolver SHOULD set No-DTS to reduce response
size and hint churn. Use of No-DTS MUST be constrained to within the
TTL of known-good information to avoid blindness to changes.

## 4.4. Example: Opportunistic Additional SVCB (P-mode)

The authoritative server ns.dnsprovider.net. responds to a query for a
name under example.com. (unsigned child), where ns.dnsprovider.net. is
in the NS RRset for example.com. The server includes an opportunistic DTS
Hint in Additional:

~~~
Header: ...

Answer:
www.example.com.          IN A          1.2.3.4

Authority:
example.com.              IN NS         ns1.example.com.
example.com.              IN NS         ns.dnsprovider.net.

Additional:
ns.dnsprovider.net.       IN A          5.6.7.8
_dns.ns.dnsprovider.net.  IN SVCB 1 .   (
                                  transport="doq:10,dot:100,do53:0"
                                  )
~~~

Processing (P-mode):
  - If the SVCB RRset is unvalidated, the resolver MAY attempt encrypted
    transports doq/dot. It MUST ignore the negative do53:0 directive and
    be ready to fall back to Do53.
  - If the SVCB RRset is validated, the resolver MAY apply the transport
    caps including do53:0 per local policy.

# 5. Achieving PA-mode (Private and Authenticated)

PA-mode requires both an authenticated transport advertisement and proof
that the endpoint is authoritative for the child zone. Two deployment
paths are defined.

Inputs required:
  - Secure Transport Signal: a DNSSEC-validated SVCB RRset at
    "_dns.<nsname>" indicating supported encrypted transports and (if
    used) "tlsa".
  - Secure Strict NS revalidation: DNSSEC-validated NS (+A/AAAA) for the
    child zone, or an equivalent proof obtained over a protected parent
    referral path.
  - Server authentication material: TLSA RRs for the endpoint, either
    obtained directly (and DNSSEC-validated) or via the "tlsa" SVCB
    parameter (DNSSEC-validated).

## 5.1. Path A: Signed Child Zone

  1. Obtain and DNSSEC-validate the child’s apex NS RRset (and glue as
     needed).
  2. Query "_dns.<nsname> IN SVCB" for each nameserver; DNSSEC-validate
     the SVCB RRset.
  3. Obtain and DNSSEC-validate TLSA for the endpoint (directly or via
     the validated "tlsa" SVCB parameter).
  4. Establish the encrypted transport (e.g., DoT/DoQ). Authenticate the
     server using TLSA as per DANE/TLS. Client authentication (mTLS) is
     optional and out of scope.
  5. If "-do53" is present in the validated SVCB, the resolver SHOULD
     honor it and avoid Do53 fallback for that server. If encrypted
     alternatives fail, treat the server as unreachable and prefer other
     authoritative servers for the zone.

## 5.2. Path B: Unsigned Child, Protected Parent Referral

  1. Establish a PA-mode connection to at least one parent authoritative
     server for the delegation point (e.g., the TLD or enclosing zone).
  2. Over that protected connection, obtain the child’s NS RRset. This
     provides a protected referral path equivalent to Secure Strict NS
     revalidation for PA-mode establishment.
  3. Proceed as in Path A steps 2–5 for each nameserver.

## 5.3. Resolver Policy in PA-mode

  - Any single PA-mode-capable nameserver for the zone is sufficient for
    secure access to the zone. Resolvers SHOULD prefer PA-mode servers
    when available.
  - If a server previously used in PA-mode later lacks the necessary
    validated signals or authentication material, treat it as
    unreachable for PA-mode; do not silently downgrade to P-mode for the
    same server.
  - Resolvers SHOULD NOT use "transport=do53:nn", "ipv4hint/ipv6hint", or
    "tlsa" unless the corresponding SVCB RRset is DNSSEC-validated.

## 5.4. Example Workflow: PA-mode (Explicit Queries)

Scenario A (signed child):
  1. Validate child NS:
     - Q: example.com. IN NS
     - A: example.com. IN NS ns1.example.com., ns.dnsprovider.net.
     - A: RRSIG(NS) ... (valid)
  2. Get and validate transport signal:
     - Q: _dns.ns.dnsprovider.net. IN SVCB
     - A: _dns.ns.dnsprovider.net. IN SVCB 1 . (
              transport="doq:10,dot:100,do53:0"
              tlsa="..." )
       RRSIG(SVCB) ... (valid)
  3. Obtain TLSA if not carried in SVCB:
     - Q: _443._tcp.ns.dnsprovider.net. IN TLSA
     - A: TLSA ...  RRSIG(TLSA) ... (valid)
  4. Establish DoT/DoQ to ns.dnsprovider.net., authenticate via TLSA,
     apply transport caps (doq at most 10%, dot up to 100%, do53 disabled).

Scenario B (unsigned child, protected parent referral):
  1. Establish PA-mode to a parent authoritative for the delegation.
  2. Over that protected connection:
     - Q: example.com. IN NS
     - A: example.com. IN NS ns1.example.com., ns.dnsprovider.net. (trusted via protected path)
  3. Proceed with steps 2–4 from Scenario A for each nameserver.

# 6. Resolver Requirements and State

Resolvers MUST maintain:

  - Per-authoritative server transport state:
    - The set of available transports and, when validated, any "transport"
      per-transport fraction caps. This state is scoped by the SVCB RRset
      TTL and SHOULD be refreshed on expiry.
    - Accounting sufficient to implement fraction caps over a rolling
      window. Implementations MAY interpret "<percent>" as a maximum share
      of queries over time, or as weights bounded by the specified caps.
      Exact windowing and scheduling are implementation-defined.
    - When "transport" is unvalidated, caps MUST be treated as advisory
      only for encrypted transports; negative directives (e.g., do53:0)
      MUST be ignored.

  - Per-(server, zone) connection mode state:
    - For each tuple <authoritative server FQDN, child zone>, the resolver
      MUST track the established connection mode: None, P-mode, or PA-mode.
    - Mode selection is tuple-specific; a server may be PA-mode for one
      zone while only P-mode (or neither) for another.
    - Transitions:
      - P-mode -> PA-mode is permitted when PA-mode preconditions are met.
      - PA-mode -> P-mode or None MUST occur if the resolver can no longer
        validate the Secure Signaling Chain (e.g., TLSA invalid, SVCB or
        child NS validation fails). Silent downgrade for the same tuple MUST
        NOT occur without recording the loss of authentication.
    - Resolvers SHOULD prefer PA-mode tuples for selection and caching.

Implementations SHOULD document storage lifetimes, TTL interactions, and
revalidation triggers for both state dimensions.

# 7. Comparison and Analysis

  - Legacy DNS (Do53, unsigned data): no confidentiality; vulnerable to
    passive observation and active manipulation; NS referrals unsigned.
  - DNSSEC over Do53: data origin authentication and integrity where
    signed; still cleartext; metadata observable; NS referrals often
    unsigned.
  - P-mode (this document): confidentiality against passive attackers;
    subject to downgrade and active impersonation; only positive "alpn"
    hints from unvalidated signals are actionable.
  - PA-mode (this document): confidentiality plus endpoint and
    authority authentication; resists active impersonation and
    downgrade; only DoS remains. Does not require content changes in
    parent or child zones; relies on deployable signaling and validation.

Operationally, authoritative servers can enable hints immediately; large
operators and resolvers can achieve high impact with limited changes.

# 8. Security Considerations

  - Unvalidated Additional data can be spoofed or stripped; P-mode
    confines use of such data to positive upgrades and requires
    fallback.
  - Negative policy MUST be honored only when the SVCB RRset
    validates; in P-mode it MUST be ignored.
  - No-DTS can be abused as a downgrade signal if injected; its use
    should be bounded by TTL and implementation safeguards.
  - TLSA misuse: resolvers MUST DNSSEC-validate TLSA prior to use;
    certificate validation semantics follow DANE/TLS guidance.
  - Fragmentation and MTU: adding SVCB increases response size; operators
    should consider EDNS(0) and TCP/DoT/DoQ fallback behavior.
  - Denial-of-service remains possible by blocking or disrupting
    encrypted/authenticated handshakes.

# 9. IANA Considerations

  - EDNS(0) Option: No-DTS (TBD code).
  - SVCB/HTTPS parameter: "tlsa" (TBD key).
  - SVCB/HTTPS parameter: "transport" (TBD key; private-use until assigned).

# 10. Acknowledgements

Thanks to contributors and reviewers of related drafts and discussions in
DNSOP and DELEG for ideas and feedback.

--- back

# Change History (to be removed before publication)

> Initial draft of unified P-mode / PA-mode model


