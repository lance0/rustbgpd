### Fixed

- A SIGHUP reload on the default generation route no longer holds the peer
  manager for one 500 ms command deadline per removed neighbor whose session
  has stopped reading commands, as a session waiting on a full RIB mailbox
  does. The removed neighbors' sessions now stop together, 64 peers at a
  time, so stuck sessions cost one delete deadline per 64 of them. If one
  removal fails, the neighbors already removed are still re-added when the
  reload rolls back. Replaced neighbors are still reshaped one at a time, so
  a failed replacement leaves every later neighbor untouched.
