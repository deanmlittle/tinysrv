# tinysrv

a fast, tiny `no_std` http server/library. ~50KB binary size. zero heap allocations.

### usage

```
tinysrv [root] [port]
```

- serves files from `root` (default: `.`)
- listens on `port` (default: `8080`)
- serves `index.html` if present
- returns json directory listing otherwise
- prevents parent path traversal (`..`)

### library

to consume as a library, simply add `tinysrv` to your project:
```
cargo add tinysrv
```

### license
mit