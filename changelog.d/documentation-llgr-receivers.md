### Documentation

- Correct the RFC 9494 export reference and describe what receivers without
  LLGR see after promotion. The reflector withdraws stale routes over eBGP.
  Over iBGP it retains `LLGR_STALE`, adds `NO_EXPORT` and sets `LOCAL_PREF`
  to zero.
