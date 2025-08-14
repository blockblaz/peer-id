# peer-id

Zig implementation of [libp2p peer-id](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md).

## Prerequisites

- Zig 0.14.1

## Building

To build the project, run the following command in the root directory of the project:

```bash
zig build -Doptimize=ReleaseSafe
```

## Running Tests

To run the tests, run the following command in the root directory of the project:

```bash
zig build test --summary all
```

## Docs

To generate documentation for the project, run the following command in the root directory of the project:

```bash
zig build docs
```

# Usage

Update `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/blockblaz/peer-id
```

In your `build.zig`:

```zig
const peer_id_dep = b.dependency("peer_id", .{
    .target = target,
    .optimize = optimize,
});
const peer_id_module = peer_id_dep.module("peer_id");
root_module.addImport("peer_id", peer_id_module);
```
