### Security

- Route listings sort and deduplicate their community and large-community
  filter terms once per request and match each route with a binary search.
  Previously the RIB compared every term against every scanned route, so one
  listing carrying a very long community filter could hold the RIB for the
  whole table scan. Matching results are unchanged.
