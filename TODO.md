# jj edit & abandon
Add special `JJEditEmpty` and `JJAbandonEmpty` matchers that allow for
- JJEdit: matches `jj edit:*`, `jj e:*` where the revision specified by REVSET (see `jj edit --help`) is empty
- JJAbandon: matches `jj abandon:*` (usage: `jj abandon [REVSETS]...`) when the specified revisions are empty (all of them!). If no REVSET is specified it implies revision `@`.

For both matchers:
- If all of the specified REVSETS are empty: Allow
- If any of the specified REVSETS are not empty: Deny

To identify whether the revisions are empty use `jj log -r <REVSET>...`:
Example:
```shell
$ jj log --no-graph  -r ut -r nz
ut (empty) (no description set)
nz prompt
py (no description set)
```

In the above example `ut` is empty (second space-separated string is `(empty)`) while neither `nz` nor `py` are
