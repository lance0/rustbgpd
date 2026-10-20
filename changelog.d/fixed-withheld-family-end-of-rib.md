### Fixed

- A session that negotiates a family but withholds it from export, such as
  eBGP IPv6 unicast with no IPv6 next hop, now sends that family an empty
  End-of-RIB after the initial table. Previously no End-of-RIB was sent for
  the family, so a graceful-restart peer that was restarting waited out its
  full selection deferral timer for it (RFC 4724 §4.1). The marker follows
  the same holds as a sendable family's End-of-RIB, and no route is exported
  in the family.
