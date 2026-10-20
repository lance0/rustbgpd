### Fixed

- `rbgp policy check` no longer keeps a full copy of the file's set and
  regex tables for every member of a test `expect chain [...]`. Each member
  now retains only the entries its policy references, so a test that
  repeats a small policy over a file with many sets, or calls a
  parameterized `route.as-path contains` policy with many distinct
  arguments, no longer grows memory with members × tables. Test verdicts,
  failure messages and coverage output are unchanged.
