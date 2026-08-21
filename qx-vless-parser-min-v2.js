/**
 * Quantumult X - Minimal VLESS Resource Parser
 *
 * Supported:
 * - VLESS + TCP
 * - VLESS + TLS
 * - VLESS + WebSocket (WS/WSS)
 * - VLESS + REALITY
 * - REALITY + xtls-rprx-vision
 *
 * Security:
 * - No network requests
 * - No eval()
 * - No remote code execution
 * - No subscription/node information upload
 *
 * Unsupported transports:
 * - gRPC
 * - XHTTP
 * - H2
 * - mKCP/KCP
 * - HTTP Upgrade
 */

(function () {
  "use strict";


  // =========================================================
  // URI Decode
  // =========================================================

  function safeDecodeURIComponent(s) {
    try {
      return decodeURIComponent(s || "");
    } catch (_) {
      return s || "";
    }
  }


  // =========================================================
  // UTF-8 Decode
  // =========================================================

  function utf8Decode(bin) {
    var out = "";
    var i = 0;
    var c, c2, c3, c4, cp;

    while (i < bin.length) {

      c = bin.charCodeAt(i++) & 255;

      if (c < 0x80) {

        out += String.fromCharCode(c);

      } else if ((c & 0xE0) === 0xC0) {

        if (i >= bin.length) break;

        c2 = bin.charCodeAt(i++) & 255;

        out += String.fromCharCode(
          ((c & 0x1F) << 6) |
          (c2 & 0x3F)
        );

      } else if ((c & 0xF0) === 0xE0) {

        if (i + 1 >= bin.length) break;

        c2 = bin.charCodeAt(i++) & 255;
        c3 = bin.charCodeAt(i++) & 255;

        out += String.fromCharCode(
          ((c & 0x0F) << 12) |
          ((c2 & 0x3F) << 6) |
          (c3 & 0x3F)
        );

      } else if ((c & 0xF8) === 0xF0) {

        if (i + 2 >= bin.length) break;

        c2 = bin.charCodeAt(i++) & 255;
        c3 = bin.charCodeAt(i++) & 255;
        c4 = bin.charCodeAt(i++) & 255;

        cp =
          ((c & 7) << 18) |
          ((c2 & 63) << 12) |
          ((c3 & 63) << 6) |
          (c4 & 63);

        cp -= 0x10000;

        out += String.fromCharCode(
          0xD800 + (cp >> 10),
          0xDC00 + (cp & 0x3FF)
        );
      }
    }

    return out;
  }


  // =========================================================
  // Base64 Decode
  // =========================================================

  function base64Decode(input) {

    var chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    var s = String(input || "")
      .replace(/\s+/g, "")
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    while (s.length % 4) {
      s += "=";
    }

    var out = "";

    var i = 0;

    var e1, e2, e3, e4;
    var c1, c2, c3;

    while (i < s.length) {

      e1 = chars.indexOf(s.charAt(i++));
      e2 = chars.indexOf(s.charAt(i++));
      e3 = chars.indexOf(s.charAt(i++));
      e4 = chars.indexOf(s.charAt(i++));

      if (e1 < 0 || e2 < 0) {
        break;
      }

      c1 = (e1 << 2) | (e2 >> 4);

      out += String.fromCharCode(c1);

      if (e3 >= 0) {

        c2 =
          ((e2 & 15) << 4) |
          (e3 >> 2);

        out += String.fromCharCode(c2);
      }

      if (e4 >= 0) {

        c3 =
          ((e3 & 3) << 6) |
          e4;

        out += String.fromCharCode(c3);
      }
    }

    return utf8Decode(out);
  }


  // =========================================================
  // UTF-8 Encode
  // =========================================================

  function utf8Encode(str) {

    var out = "";

    var i = 0;
    var c;
    var cp;

    for (; i < str.length; i++) {

      c = str.charCodeAt(i);

      if (c < 0x80) {

        out += String.fromCharCode(c);

      } else if (c < 0x800) {

        out += String.fromCharCode(
          0xC0 | (c >> 6)
        );

        out += String.fromCharCode(
          0x80 | (c & 63)
        );

      } else if (
        c >= 0xD800 &&
        c <= 0xDBFF &&
        i + 1 < str.length
      ) {

        cp =
          ((c - 0xD800) << 10) +
          (str.charCodeAt(++i) - 0xDC00) +
          0x10000;

        out += String.fromCharCode(
          0xF0 | (cp >> 18)
        );

        out += String.fromCharCode(
          0x80 | ((cp >> 12) & 63)
        );

        out += String.fromCharCode(
          0x80 | ((cp >> 6) & 63)
        );

        out += String.fromCharCode(
          0x80 | (cp & 63)
        );

      } else {

        out += String.fromCharCode(
          0xE0 | (c >> 12)
        );

        out += String.fromCharCode(
          0x80 | ((c >> 6) & 63)
        );

        out += String.fromCharCode(
          0x80 | (c & 63)
        );
      }
    }

    return out;
  }


  // =========================================================
  // Base64 Encode
  // =========================================================

  function base64Encode(input) {

    var chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    var bin = utf8Encode(
      String(input || "")
    );

    var out = "";

    var i = 0;

    var c1, c2, c3;

    var e1, e2, e3, e4;

    while (i < bin.length) {

      c1 =
        bin.charCodeAt(i++) & 255;

      c2 =
        i < bin.length
          ? bin.charCodeAt(i++) & 255
          : NaN;

      c3 =
        i < bin.length
          ? bin.charCodeAt(i++) & 255
          : NaN;

      e1 =
        c1 >> 2;

      e2 =
        ((c1 & 3) << 4) |
        (isNaN(c2) ? 0 : (c2 >> 4));

      e3 =
        isNaN(c2)
          ? 64
          : (
              ((c2 & 15) << 2) |
              (isNaN(c3) ? 0 : (c3 >> 6))
            );

      e4 =
        isNaN(c3)
          ? 64
          : (c3 & 63);

      out += chars.charAt(e1);

      out += chars.charAt(e2);

      out +=
        e3 === 64
          ? "="
          : chars.charAt(e3);

      out +=
        e4 === 64
          ? "="
          : chars.charAt(e4);
    }

    return out;
  }


  // =========================================================
  // Parse URL Query
  // =========================================================

  function parseQuery(qs) {

    var obj = {};

    if (!qs) {
      return obj;
    }

    qs.split("&").forEach(function (part) {

      if (!part) {
        return;
      }

      var p =
        part.indexOf("=");

      var k =
        p >= 0
          ? part.slice(0, p)
          : part;

      var v =
        p >= 0
          ? part.slice(p + 1)
          : "";

      k =
        safeDecodeURIComponent(k)
          .toLowerCase();

      v =
        safeDecodeURIComponent(v);

      obj[k] = v;
    });

    return obj;
  }


  // =========================================================
  // Node Name
  // =========================================================

  function sanitizeTag(tag, fallback) {

    tag =
      String(
        tag ||
        fallback ||
        "VLESS"
      )
      .replace(
        /[\r\n]+/g,
        " "
      )
      .replace(
        /,/g,
        "，"
      )
      .trim();

    return tag || "VLESS";
  }


  // =========================================================
  // Subscription Content
  // =========================================================

  function normalizeContent(content) {

    var s =
      String(content || "")
        .trim();

    if (!s) {
      return "";
    }

    // Already plain VLESS URI
    if (
      s.indexOf("vless://") !== -1
    ) {
      return s;
    }

    // Try Base64 subscription
    if (
      /^[A-Za-z0-9+/_=\-\r\n]+$/.test(s)
    ) {

      try {

        var decoded =
          base64Decode(s);

        if (
          decoded.indexOf("vless://") !== -1
        ) {
          return decoded;
        }

      } catch (_) {}
    }

    return s;
  }


  // =========================================================
  // Server Address
  // =========================================================

  function parseAuthority(authority) {

    // IPv6:
    // [2001:db8::1]:443

    var m =
      authority.match(
        /^\[([^\]]+)\]:(\d+)$/
      );

    if (m) {

      return {
        endpoint:
          "[" +
          m[1] +
          "]:" +
          m[2]
      };
    }

    // IPv4 / domain
    var idx =
      authority.lastIndexOf(":");

    if (idx <= 0) {
      return null;
    }

    var host =
      authority.slice(0, idx);

    var port =
      authority.slice(idx + 1);

    if (!/^\d+$/.test(port)) {
      return null;
    }

    return {
      endpoint:
        host +
        ":" +
        port
    };
  }


  // =========================================================
  // Parse VLESS URI
  // =========================================================

  function parseVless(uri) {

    uri =
      String(uri || "")
        .trim();

    if (
      uri.indexOf("vless://") !== 0
    ) {
      return null;
    }


    // Remove vless://
    var body =
      uri.slice(8);


    // ---------------------------------------------------------
    // Node name
    // ---------------------------------------------------------

    var hashPos =
      body.indexOf("#");

    var tag = "";

    if (hashPos >= 0) {

      tag =
        safeDecodeURIComponent(
          body.slice(hashPos + 1)
        );

      body =
        body.slice(0, hashPos);
    }


    // ---------------------------------------------------------
    // Query
    // ---------------------------------------------------------

    var qPos =
      body.indexOf("?");

    var query =
      qPos >= 0
        ? body.slice(qPos + 1)
        : "";

    var main =
      qPos >= 0
        ? body.slice(0, qPos)
        : body;


    // ---------------------------------------------------------
    // UUID + Server
    // ---------------------------------------------------------

    var atPos =
      main.lastIndexOf("@");

    if (atPos <= 0) {
      return null;
    }


    var uuid =
      safeDecodeURIComponent(
        main.slice(0, atPos)
      )
      .trim();


    var authority =
      main.slice(atPos + 1)
        .trim();


    if (!uuid || !authority) {
      return null;
    }


    var addr =
      parseAuthority(authority);


    if (!addr) {
      return null;
    }


    // ---------------------------------------------------------
    // Parameters
    // ---------------------------------------------------------

    var q =
      parseQuery(query);


    var transport =
      String(
        q.type || "tcp"
      )
      .toLowerCase();


    var security =
      String(
        q.security ||
        (
          q.tls === "1"
            ? "tls"
            : "none"
        )
      )
      .toLowerCase();


    // ---------------------------------------------------------
    // Unsupported transports
    // ---------------------------------------------------------

    if (
      [
        "grpc",
        "xhttp",
        "h2",
        "mkcp",
        "kcp",
        "httpupgrade",
        "http-upgrade"
      ].indexOf(transport) !== -1
    ) {
      return null;
    }


    if (
      transport !== "tcp" &&
      transport !== "ws"
    ) {
      return null;
    }


    // ---------------------------------------------------------
    // Security type
    // ---------------------------------------------------------

    var isTLS =
      security === "tls";


    var isReality =
      security === "reality";


    // ---------------------------------------------------------
    // Common parameters
    // ---------------------------------------------------------

    var sni =
      q.sni ||
      q.servername ||
      q.peer ||
      "";


    var wsHost =
      q.host ||
      "";


    var path =
      q.path ||
      "";


    var pbk =
      q.pbk ||
      q["public-key"] ||
      "";


    var sid =
      q.sid ||
      q["short-id"] ||
      "";


    var flow =
      q.flow ||
      "";


    // Reality must have PBK
    if (
      isReality &&
      !pbk
    ) {
      return null;
    }


    // =========================================================
    // Quantumult X Result
    // =========================================================

    var out = [
      "vless=" + addr.endpoint,
      "method=none",
      "password=" + uuid
    ];


    // ---------------------------------------------------------
    // WebSocket
    // ---------------------------------------------------------

    if (
      transport === "ws"
    ) {

      out.push(
        "obfs=" +
        (
          isTLS || isReality
            ? "wss"
            : "ws"
        )
      );


      if (
        wsHost ||
        sni
      ) {

        out.push(
          "obfs-host=" +
          (
            wsHost ||
            sni
          )
        );
      }


      if (path) {

        out.push(
          "obfs-uri=" +
          path
        );
      }


    // ---------------------------------------------------------
    // TCP + TLS / Reality
    // ---------------------------------------------------------

    } else if (
      isTLS ||
      isReality
    ) {

      out.push(
        "obfs=over-tls"
      );


      if (sni) {

        out.push(
          "obfs-host=" +
          sni
        );
      }
    }


    // ---------------------------------------------------------
    // Reality
    // ---------------------------------------------------------

    if (isReality) {

      out.push(
        "reality-base64-pubkey=" +
        pbk
      );


      if (sid) {

        out.push(
          "reality-hex-shortid=" +
          sid
        );
      }


      if (
        flow ===
          "xtls-rprx-vision" ||
        flow ===
          "xtls-rprx-vision-udp443"
      ) {

        out.push(
          "vless-flow=xtls-rprx-vision"
        );
      }


    // ---------------------------------------------------------
    // Normal TLS
    // ---------------------------------------------------------

    } else if (isTLS) {

      var insecure =
        String(
          q.allowinsecure || ""
        )
        .toLowerCase();


      out.push(
        "tls-verification=" +
        (
          insecure === "1" ||
          insecure === "true"
            ? "false"
            : "true"
        )
      );
    }


    // ---------------------------------------------------------
    // UDP
    // ---------------------------------------------------------

    out.push(
      "udp-relay=" +
      (
        q.udp === "1" ||
        String(q.udp)
          .toLowerCase() === "true"
          ? "true"
          : "false"
      )
    );


    // ---------------------------------------------------------
    // TCP Fast Open
    // ---------------------------------------------------------

    out.push(
      "fast-open=" +
      (
        q.tfo === "1" ||
        String(q.tfo)
          .toLowerCase() === "true"
          ? "true"
          : "false"
      )
    );


    // ---------------------------------------------------------
    // Node name
    // ---------------------------------------------------------

    out.push(
      "tag=" +
      sanitizeTag(
        tag,
        "[vless] " +
        addr.endpoint
      )
    );


    return out.join(", ");
  }


  // =========================================================
  // Main
  // =========================================================

  try {

    if (
      typeof $resource === "undefined"
    ) {

      $done({
        error:
          "No $resource object."
      });

      return;
    }


    // Resource type:
    // server / uri / filter / rewrite ...

    var resourceType =
      String(
        $resource.type || ""
      );


    // ---------------------------------------------------------
    // Get source
    // ---------------------------------------------------------

    var source =
      String(
        $resource.content || ""
      )
      .trim();


    // Single VLESS URI may exist in $resource.link
    if (
      source.indexOf("vless://") === -1 &&
      typeof $resource.link === "string" &&
      $resource.link.indexOf("vless://") === 0
    ) {

      source =
        $resource.link;
    }


    // ---------------------------------------------------------
    // Decode subscription
    // ---------------------------------------------------------

    var content =
      normalizeContent(source);


    var lines =
      content.split(/\r?\n/);


    var nodes = [];


    // ---------------------------------------------------------
    // Parse every VLESS node
    // ---------------------------------------------------------

    for (
      var i = 0;
      i < lines.length;
      i++
    ) {

      var line =
        lines[i].trim();


      if (
        line.indexOf("vless://") !== 0
      ) {
        continue;
      }


      var node =
        parseVless(line);


      if (node) {

        nodes.push(node);
      }
    }


    // ---------------------------------------------------------
    // No node
    // ---------------------------------------------------------

    if (
      nodes.length === 0
    ) {

      $done({
        error:
          "No valid VLESS node found. resource.type=" +
          resourceType
      });

      return;
    }


    // =========================================================
    // Important:
    // Quantumult X node resource result is Base64 encoded.
    // Same behavior as KOP-XIAO resource-parser.
    // =========================================================

    var result =
      nodes.join("\n");


    result =
      base64Encode(result);


    $done({
      content: result
    });


  } catch (e) {

    $done({
      error:
        "VLESS parser error: " +
        e
    });
  }

})();
