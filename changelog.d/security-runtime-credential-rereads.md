### Security

- Neighbor, policy, peer-group, and FIB-table mutations no longer reopen
  unchanged gRPC credential files on the peer-manager actor. Startup, checks,
  reloads, and full configuration candidates retain credential validation.
