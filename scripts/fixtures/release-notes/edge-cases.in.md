
### Added

- **Top-level wrapped bullet.** This bullet wraps across several source
  lines and should collapse into one flowing line on the release page,
  keeping inline code like `vlan_filtering=1` intact.
  - A nested bullet under the parent. It also wraps across lines and
    must keep its two-space indentation while its own continuation
    lines collapse.
  - A second nested bullet on a single source line.
- **Second top-level bullet.** Single source line, left as is.

A standalone prose paragraph that is hard-wrapped across two source
lines and should join into one flowing line.

### Notes

A configuration example that must stay byte-for-byte verbatim inside the
fence, even though some lines are short:

```toml
[security.grpc]
enforcement = "tier"
roles = { admin = "spki-sha256:..." }
```

> A hard-wrapped blockquote paragraph whose continuation lines must
> join into one line with a single leading marker, not literal `>`
> characters mid-sentence.
>
> A second blockquote paragraph, separated by the blank `>` line above,
> that stays its own paragraph.

> A blockquote immediately before a heading.

### After the quote

- A bullet right after a blockquote section, unaffected by it.

A small table whose rows must stay verbatim (never joined):

| Field | Meaning |
|-------|---------|
| afi   | address family |
| safi  | subsequent address family |
