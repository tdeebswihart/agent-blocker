# jj edit & abandon
Add special `JJEditEmpty` and `JJAbandonEmpty` matchers that allow for
 - JJEdit: matches `jj edit:*`, `jj e:*` where the revision specified by REVSET (see `jj edit --help`) is empty
 - JJAbandon: matches `jj abandon:*` (usage: `jj abandon [REVSETS]...`) when the specified revisions are empty (all of them!). If no REVSET is specified it implies revision `@`.
 
 For both matchers:
 - If all of the specified REVSETS are empty: Allow
 - If any of the specified REVSETS are not empty: Deny
