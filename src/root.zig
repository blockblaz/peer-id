//! Peer ID library for libp2p-style peer identifiers
//! Based on multiformats specification for encoding and decoding peer IDs

const std = @import("std");
const testing = std.testing;
const multiformats = @import("zmultiformats");

const Multicodec = multiformats.multicodec.Multicodec;
const Multihash = multiformats.multihash.Multihash;
const MultiBaseCodec = multiformats.multibase.MultiBaseCodec;
const CID = multiformats.cid.CID;

pub const PeerIdError = error{
    InvalidPeerId,
    InvalidPeerIdString,
    UnsupportedHashType,
    InvalidMultibase,
};

/// Represents a peer ID (a multihash of a public key)
pub const PeerId = struct {
    data: []u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const cloned_data = try allocator.dupe(u8, self.data);
        return Self{
            .data = cloned_data,
            .allocator = allocator,
        };
    }
};

/// A string representation of a peer ID (multibase-encoded CID or base58 multihash)
pub const PeerIdString = []const u8;

/// Create a peer ID from a public key 
pub fn createPeerId(allocator: std.mem.Allocator, pubkey_bytes: []const u8) !PeerId {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(pubkey_bytes);
    var hash_output: [32]u8 = undefined;
    hasher.final(&hash_output);

    const multihash_result = try Multihash(64).wrap(Multicodec.SHA2_256, &hash_output);

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const writer = buffer.writer();
    _ = try multihash_result.write(writer);

    const peer_id_data = try buffer.toOwnedSlice();
    return PeerId{
        .data = peer_id_data,
        .allocator = allocator,
    };
}

/// Validate a peer ID 
pub fn validatePeerId(peer_id: []const u8) !void {
    const parsed_multihash = Multihash(64).readBytes(peer_id) catch {
        return PeerIdError.InvalidPeerId;
    };

    const code_value = parsed_multihash.getCode();
    if (code_value != Multicodec.SHA2_256) {
        return PeerIdError.UnsupportedHashType;
    }
}

/// Convert a peer ID to a multibase-encoded CID string 
pub fn toStringCID(allocator: std.mem.Allocator, peer_id: PeerId) ![]u8 {
    const parsed_multihash = try Multihash(64).readBytes(peer_id.data);

    const cid_result = try CID(64).newV1(Multicodec.LIBP2P_KEY, parsed_multihash);

    const cid_bytes = try allocator.alloc(u8, cid_result.encodedLen());
    defer allocator.free(cid_bytes);

    const cid_slice = try cid_result.toBytes(cid_bytes);

    // Encode as base32 multibase
    const encoded_len = MultiBaseCodec.Base32Lower.encodedLen(cid_slice);
    const result = try allocator.alloc(u8, encoded_len);
    _ = MultiBaseCodec.Base32Lower.encode(result, cid_slice);
    
    return result;
}

/// Convert a peer ID to a base58 multihash string 
pub fn toStringLegacy(allocator: std.mem.Allocator, peer_id: PeerId) ![]u8 {
    // Encode the multihash directly as base58
    const encoded_len = MultiBaseCodec.Base58Btc.encodedLen(peer_id.data);
    const encoded = try allocator.alloc(u8, encoded_len);
    const result = MultiBaseCodec.Base58Btc.encode(encoded, peer_id.data);

    const final_result = try allocator.dupe(u8, result);
    allocator.free(encoded);
    return final_result;
}

/// Convert a stringified peer ID to a peer ID
pub fn fromString(allocator: std.mem.Allocator, peer_id_str: []const u8) !PeerId {
    if (peer_id_str.len >= 2 and
        ((peer_id_str[0] == 'Q' and peer_id_str[1] == 'm') or peer_id_str[0] == '1'))
    {
        return fromStringLegacy(allocator, peer_id_str);
    } else {
        return fromStringCID(allocator, peer_id_str);
    }
}

/// Convert a multibase-encoded CID string to a peer ID
pub fn fromStringCID(allocator: std.mem.Allocator, peer_id_str: []const u8) !PeerId {
    const codec = MultiBaseCodec.fromCode(peer_id_str) catch {
        return PeerIdError.InvalidMultibase;
    };

    const decoded_len = codec.decodedLen(peer_id_str[codec.codeLength()..]);
    const decoded_buf = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded_buf);

    const decoded = codec.decode(decoded_buf, peer_id_str[codec.codeLength()..]) catch {
        return PeerIdError.InvalidMultibase;
    };

    const parsed_cid = CID(64).fromBytes(decoded) catch {
        return PeerIdError.InvalidPeerIdString;
    };

    if (parsed_cid.codec != Multicodec.LIBP2P_KEY) {
        return PeerIdError.InvalidPeerIdString;
    }

    const peer_id_data = try allocator.alloc(u8, parsed_cid.hash.encodedLen());
    const multihash_slice = try parsed_cid.hash.toBytes(peer_id_data);
    errdefer allocator.free(peer_id_data);

    try validatePeerId(multihash_slice);

    const final_peer_id_data = try allocator.dupe(u8, multihash_slice);
    allocator.free(peer_id_data);

    return PeerId{
        .data = final_peer_id_data,
        .allocator = allocator,
    };
}

/// Convert a base58 multihash string to a peer ID
pub fn fromStringLegacy(allocator: std.mem.Allocator, peer_id_str: []const u8) !PeerId {
    const decoded_len = MultiBaseCodec.Base58Btc.decodedLen(peer_id_str);
    const decoded_buf = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded_buf);

    const decoded = MultiBaseCodec.Base58Btc.decode(decoded_buf, peer_id_str) catch {
        return PeerIdError.InvalidMultibase;
    };

    try validatePeerId(decoded);

    const peer_id_data = try allocator.dupe(u8, decoded);
    
    return PeerId{
        .data = peer_id_data,
        .allocator = allocator,
    };
}

/// Convert a peer ID to a string (defaults to CID format)
pub fn toString(allocator: std.mem.Allocator, peer_id: PeerId) ![]u8 {
    return toStringCID(allocator, peer_id);
}

/// Validate a stringified peer ID
pub fn validateString(peer_id_str: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    var peer_id = fromString(temp_allocator, peer_id_str) catch {
        return PeerIdError.InvalidPeerIdString;
    };
    defer peer_id.deinit();
}


// Test fixtures
const TestFixtures = struct {
    // Sample test ID and keys from https://github.com/ChainSafe/ts-peer-id/tree/master/test/fixtures
    const id = "122019318b6e5e0cf93a2314bf01269a2cc23cd3dcd452d742cdb9379d8646f6e4a9";
    const privkey = "CAASpgkwggSiAgEAAoIBAQC2SKo/HMFZeBml1AF3XijzrxrfQXdJzjePBZAbdxqKR1Mc6juRHXij6HXYPjlAk01BhF1S3Ll4Lwi0cAHhggf457sMg55UWyeGKeUv0ucgvCpBwlR5cQ020i0MgzjPWOLWq1rtvSbNcAi2ZEVn6+Q2EcHo3wUvWRtLeKz+DZSZfw2PEDC+DGPJPl7f8g7zl56YymmmzH9liZLNrzg/qidokUv5u1pdGrcpLuPNeTODk0cqKB+OUbuKj9GShYECCEjaybJDl9276oalL9ghBtSeEv20kugatTvYy590wFlJkkvyl+nPxIH0EEYMKK9XRWlu9XYnoSfboiwcv8M3SlsjAgMBAAECggEAZtju/bcKvKFPz0mkHiaJcpycy9STKphorpCT83srBVQi59CdFU6Mj+aL/xt0kCPMVigJw8P3/YCEJ9J+rS8BsoWE+xWUEsJvtXoT7vzPHaAtM3ci1HZd302Mz1+GgS8Epdx+7F5p80XAFLDUnELzOzKftvWGZmWfSeDnslwVONkL/1VAzwKy7Ce6hk4SxRE7l2NE2OklSHOzCGU1f78ZzVYKSnS5Ag9YrGjOAmTOXDbKNKN/qIorAQ1bovzGoCwx3iGIatQKFOxyVCyO1PsJYT7JO+kZbhBWRRE+L7l+ppPER9bdLFxs1t5CrKc078h+wuUr05S1P1JjXk68pk3+kQKBgQDeK8AR11373Mzib6uzpjGzgNRMzdYNuExWjxyxAzz53NAR7zrPHvXvfIqjDScLJ4NcRO2TddhXAfZoOPVH5k4PJHKLBPKuXZpWlookCAyENY7+Pd55S8r+a+MusrMagYNljb5WbVTgN8cgdpim9lbbIFlpN6SZaVjLQL3J8TWH6wKBgQDSChzItkqWX11CNstJ9zJyUE20I7LrpyBJNgG1gtvz3ZMUQCn3PxxHtQzN9n1P0mSSYs+jBKPuoSyYLt1wwe10/lpgL4rkKWU3/m1Myt0tveJ9WcqHh6tzcAbb/fXpUFT/o4SWDimWkPkuCb+8j//2yiXk0a/T2f36zKMuZvujqQKBgC6B7BAQDG2H2B/ijofp12ejJU36nL98gAZyqOfpLJ+FeMz4TlBDQ+phIMhnHXA5UkdDapQ+zA3SrFk+6yGk9Vw4Hf46B+82SvOrSbmnMa+PYqKYIvUzR4gg34rL/7AhwnbEyD5hXq4dHwMNsIDq+l2elPjwm/U9V0gdAl2+r50HAoGALtsKqMvhv8HucAMBPrLikhXP/8um8mMKFMrzfqZ+otxfHzlhI0L08Bo3jQrb0Z7ByNY6M8epOmbCKADsbWcVre/AAY0ZkuSZK/CaOXNX/AhMKmKJh8qAOPRY02LIJRBCpfS4czEdnfUhYV/TYiFNnKRj57PPYZdTzUsxa/yVTmECgYBr7slQEjb5Onn5mZnGDh+72BxLNdgwBkhO0OCdpdISqk0F0Pxby22DFOKXZEpiyI9XYP1C8wPiJsShGm2yEwBPWXnrrZNWczaVuCbXHrZkWQogBDG3HGXNdU4MAWCyiYlyinIBpPpoAJZSzpGLmWbMWh28+RJS6AQX6KHrK1o2uw==";
    const pubkey = "CAASpgIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2SKo/HMFZeBml1AF3XijzrxrfQXdJzjePBZAbdxqKR1Mc6juRHXij6HXYPjlAk01BhF1S3Ll4Lwi0cAHhggf457sMg55UWyeGKeUv0ucgvCpBwlR5cQ020i0MgzjPWOLWq1rtvSbNcAi2ZEVn6+Q2EcHo3wUvWRtLeKz+DZSZfw2PEDC+DGPJPl7f8g7zl56YymmmzH9liZLNrzg/qidokUv5u1pdGrcpLuPNeTODk0cqKB+OUbuKj9GShYECCEjaybJDl9276oalL9ghBtSeEv20kugatTvYy590wFlJkkvyl+nPxIH0EEYMKK9XRWlu9XYnoSfboiwcv8M3SlsjAgMBAAE=";
    const invalid_cid_multicodec = "bafyinvalidmulticodecexample";
    const invalid_cid_value = "QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L";
};

test "create id from a PublicKey" {
    const allocator = testing.allocator;

    const pubkey_no_pad = std.mem.trimRight(u8, TestFixtures.pubkey, "=");
    const pubkey_decoded_len = MultiBaseCodec.Base64.decodedLen(pubkey_no_pad);
    const pubkey_decoded_buf = try allocator.alloc(u8, pubkey_decoded_len);
    defer allocator.free(pubkey_decoded_buf);
    
    const pubkey_decoded = MultiBaseCodec.Base64.decode(pubkey_decoded_buf, pubkey_no_pad) catch {
        return PeerIdError.InvalidMultibase;
    };

    var id = try createPeerId(allocator, pubkey_decoded);
    defer id.deinit();

    const test_id_bytes = try allocator.alloc(u8, TestFixtures.id.len / 2);
    defer allocator.free(test_id_bytes);
    _ = try std.fmt.hexToBytes(test_id_bytes, TestFixtures.id);

    const test_id_b58_string = try toStringLegacy(allocator, PeerId{ .data = test_id_bytes, .allocator = allocator });
    defer allocator.free(test_id_b58_string);

    const id_b58_string = try toStringLegacy(allocator, id);
    defer allocator.free(id_b58_string);


    try testing.expect(std.mem.eql(u8, test_id_bytes, id.data));

    try testing.expectEqualStrings(test_id_b58_string, id_b58_string);
}


test "throws on invalid CID multicodec" {
    const allocator = testing.allocator;

    const invalid_cid = TestFixtures.invalid_cid_multicodec;

    const result = fromString(allocator, invalid_cid);

    try testing.expectError(PeerIdError.InvalidPeerIdString, result);
}

test "throws on invalid CID value" {
    const allocator = testing.allocator;

    const invalid_cid = TestFixtures.invalid_cid_value;

    const result = fromString(allocator, invalid_cid);
    
    try testing.expectError(PeerIdError.UnsupportedHashType, result);
}
