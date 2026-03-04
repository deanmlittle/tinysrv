# tinysrv

A tiny `no_std` http server. ~50KB binary. zero heap allocations.

```
tinysrv [root] [port]
```

- serves files from `root` (default: `.`)
- listens on `port` (default: `8080`)
- serves `index.html` when present
- returns json directory listing otherwise
- guards against parent path traversal (`..`)