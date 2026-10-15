### Fixed

- Use exact flat key storage for full unicast and VPN recovery captures,
  avoiding shared-universe capture work. Concurrent full captures retain more
  memory per peer; existing recovery memory budgets and conservative withdrawal
  fallback remain in force.
