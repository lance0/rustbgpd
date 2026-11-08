### Security

- Keep outbound writer admission within its byte budget even when a route
  requires a large UPDATE. Paused peers retain their delivery cursor and resume
  in order when space becomes available, including shared update-group frames.
