### Fixed

- A gNMI `CommitSetRollbackDuration` after a failed automatic rollback now
  reports the transaction as pending at the new deadline. Status previously
  kept reporting `AUTO_REVERT_FAILED` and asking for manual action while the
  reset had already re-armed the automatic retry. A retry that fails again
  reports the failure again, and a restart before the retry still notes the
  earlier failed rollback in the boot-revert banner.
