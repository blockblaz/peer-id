const std = @import("std");
const peer_id_lib = @import("peer_id_lib");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("Peer ID Library Test\n", .{});

    // Test creating a peer ID
    const test_pubkey = "test_public_key_data";
    var peer_id = try peer_id_lib.createPeerId(allocator, test_pubkey);
    defer peer_id.deinit();

    const peer_id_string = try peer_id_lib.toString(allocator, peer_id);
    defer allocator.free(peer_id_string);

    std.debug.print("Created peer ID: {s}\n", .{peer_id_string});
}
