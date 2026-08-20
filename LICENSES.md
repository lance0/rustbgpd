# License map

Unless a file says otherwise, rustbgpd is available under either the Apache
License 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)) or the MIT license
([`LICENSE-MIT`](LICENSE-MIT)), at your option.

The original IXP Manager Foil integration under
`integrations/ixp-manager/gpl-2.0-only/` is GPL-2.0-only. Its complete license
is included beside the source. That subtree is source-only: Cargo does not
embed it, and rustbgpd release archives, binary packages, and final container
images do not include it.

The two parts communicate only through the documented versioned JSON/process
boundary. Generated JSON and candidate configuration are data, not embedded
integration source.
