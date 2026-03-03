# jj edit & abandon
 Add special `JJEditEmpty` and `JJAbandonEmpty` matchers that allow for
  - JJEditEmpty: matches `jj edit:*`, `jj e:*` where the revision specified by REVSET (see `jj edit --help`) is empty
  - JJAbandonEmpty: matches `jj abandon:*` (usage: `jj abandon [REVSETS]...`) when the specified revisions are empty (all of them!). If no REVSET is specified it implies revision `@`.
