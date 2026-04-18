##! OQS Scanner — PQC Key Share Logger
##!
##! Hooks the TLS extension event to capture key_share group IDs from the
##! ClientHello and ServerHello. Vanilla ssl.log only records the cipher suite
##! and negotiated curve (string) but not the raw IANA SupportedGroup codepoints
##! used in TLS 1.3 key_share extensions. This script adds a pqc_key_share
##! column to ssl.log with a comma-separated list of hex codepoints observed
##! in the ClientHello key_share extension — enabling ML-KEM codepoint detection
##! without a separate log file.
##!
##! Install
##! -------
##! 1. Copy to $PREFIX/share/zeek/site/ (or any directory in @load search path).
##! 2. Add to local.zeek:
##!      @load oqs-pqc-key-share
##! 3. Restart Zeek (or zeekctl deploy).
##!
##! Compatible with Zeek 4.x / 5.x.  Tested against Zeek 5.2.
##!
##! Output field:
##!   pqc_key_share  — comma-separated hex codepoints (e.g. "11EC,0017")
##!                    from the ClientHello key_share extension (type 51 / 0x0033).
##!                    Empty string when no key_share extension is present
##!                    (TLS 1.2, resumed sessions, etc.).

module OQS;

export {
    ## Redef to false to disable the pqc_key_share column without unloading the script.
    const log_pqc_key_share: bool = T &redef;
}

redef record SSL::Info += {
    ## Comma-separated hex codepoints from the ClientHello key_share extension.
    pqc_key_share: string &log &optional;
};

## TLS extension type value for key_share (RFC 8446 §4.2.8).
const KEY_SHARE_EXTENSION_TYPE: count = 51;

## Known PQC-bearing SupportedGroup codepoints (IANA provisional registry,
## draft-ietf-tls-hybrid-design-16; FIPS 203 ML-KEM pure codepoints 0x0200–0x0202).
## Used to filter the full key_share list to just PQC-relevant entries when
## log_pqc_key_share=T but the operator only wants PQC signal.
const PQC_GROUP_CODEPOINTS: set[count] = {
    0x11EB,  # SecP256r1MLKEM768
    0x11EC,  # X25519MLKEM768  (dominant; >50% Cloudflare Oct 2025)
    0x11ED,  # SecP384r1MLKEM1024
    0x11EE,  # curveSM2MLKEM768
    0x0200,  # MLKEM512
    0x0201,  # MLKEM768
    0x0202,  # MLKEM1024
    0x6399,  # X25519Kyber768Draft00 (deprecated; still in the wild)
    0x636D,  # X25519Kyber768Draft00 alias (deprecated)
};

## ssl_extension fires once per extension in the ClientHello and ServerHello.
## We intercept key_share (type 51) to extract SupportedGroup codepoints.
##
## The raw extension data layout for key_share in a ClientHello (RFC 8446 §4.2.8):
##   2 bytes  client_shares length
##   for each KeyShareEntry:
##     2 bytes  group codepoint
##     2 bytes  key_exchange length
##     N bytes  key_exchange data
##
## In a ServerHello there is a single KeyShareEntry (no length prefix).
## We parse both forms defensively by walking the byte vector.
event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    if ( ! log_pqc_key_share )
        return;

    if ( code != KEY_SHARE_EXTENSION_TYPE )
        return;

    if ( ! c?$ssl )
        return;

    local data = val;
    local groups: vector of string = vector();

    if ( is_orig )
        {
        # ClientHello: 2-byte length prefix then repeated KeyShareEntry records.
        if ( |data| < 2 )
            return;

        local total_len = bytestring_to_count(data[0:2]);
        data = data[2:];

        local consumed: count = 0;
        while ( consumed < total_len && |data| >= 4 )
            {
            local group_id = bytestring_to_count(data[0:2]);
            local ke_len   = bytestring_to_count(data[2:4]);
            data = data[4:];
            consumed += 4;

            if ( |data| < ke_len )
                break;

            data = data[ke_len:];
            consumed += ke_len;

            # Log all groups or just PQC ones depending on operator preference.
            # Always log all — the oqs-scanner filter logic lives in Go.
            groups[|groups|] = fmt("%x", group_id);
            }
        }
    else
        {
        # ServerHello: single KeyShareEntry (2-byte group, 2-byte ke_len, ke_data).
        if ( |data| >= 2 )
            {
            local sg = bytestring_to_count(data[0:2]);
            groups[|groups|] = fmt("%x", sg);
            }
        }

    if ( |groups| > 0 )
        {
        local joined = join_string_vec(groups, ",");
        if ( c$ssl?$pqc_key_share )
            c$ssl$pqc_key_share = fmt("%s,%s", c$ssl$pqc_key_share, joined);
        else
            c$ssl$pqc_key_share = joined;
        }
    }
