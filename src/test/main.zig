const ipcrypt = @cImport(@cInclude("ipcrypt2.h"));

const std = @import("std");
const testing = std.testing;

test "ip string encryption and decryption" {
    const key = "0123456789abcdef";
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    const ip_str = "1.2.3.4";

    var encrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];

    const expected_encrypted_ip = "9f4:e6e1:c77e:ffe8:49ac:6a6a:9f11:620f";
    try testing.expectEqualSlices(u8, expected_encrypted_ip, encrypted_ip);

    var decrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const decrypted_ip_len = ipcrypt.ipcrypt_decrypt_ip_str(&st, &decrypted_ip_buf, encrypted_ip.ptr);
    const decrypted_ip_str = decrypted_ip_buf[0..decrypted_ip_len];

    try testing.expectEqualSlices(u8, ip_str, decrypted_ip_str);
}

test "ip string non-deterministic encryption and decryption" {
    const key = "0123456789abcdef";
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    const ip_str = "1.2.3.4";
    const tweak: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_nd_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];

    const expected_encrypted_ip = "01020304050607085f8ec3223eaa68378ba06d3bc3df0209";
    try testing.expectEqualSlices(u8, expected_encrypted_ip, encrypted_ip);

    var decrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const decrypted_ip_len = ipcrypt.ipcrypt_nd_decrypt_ip_str(&st, &decrypted_ip_buf, encrypted_ip.ptr);
    const decrypted_ip_str = decrypted_ip_buf[0..decrypted_ip_len];

    try testing.expectEqualSlices(u8, ip_str, decrypted_ip_str);
}
