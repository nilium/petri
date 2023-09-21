petri
=====

Petri is a small tool for viewing tmux windows, panes, processes, and their open files at a glance.
It was originally written just to find out where a particular vim instance had a file open, hence the ability to also list files.
In practice this tends not to be too useful for most people, but for someone as disorganized as myself, it's helped me.

Installing
----------

Currently it is only possible to install Petri from source.
With Go 1.21 or later installed:

```
go install go.spiff.io/petri@latest
```

This will fetch, compile, and install Petri to `$GOBIN` (usually `$HOME/go/bin`).

License
-------

Petri is licensed under the Unlicense.
A copy of the license can be found in LICENSE.txt.
