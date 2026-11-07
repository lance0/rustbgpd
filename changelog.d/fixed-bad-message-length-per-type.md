### Fixed

- A received OPEN, UPDATE or NOTIFICATION shorter than its RFC 4271 §6.1
  minimum, or a KEEPALIVE that is not exactly 19 octets, now gets
  NOTIFICATION Message Header Error / Bad Message Length (1/2) carrying the
  erroneous length. Before, a short OPEN or NOTIFICATION got OPEN Message
  Error 2/0 with empty data, a short UPDATE got 3/1, and a bad KEEPALIVE
  length got 1/2 without the length.
