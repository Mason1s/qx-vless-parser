/**
 * Quantumult X - Minimal VLESS Resource Parser
 * Purpose: parse VLESS URI/subscription content into Quantumult X node format.
 *
 * Security design:
 * - No network requests
 * - No eval / Function / remote code execution
 * - Does not read or transmit subscription URL
 * - Only reads $resource.content and returns parsed content via $done()
 *
 * Supported:
 * - VLESS + TCP
 * - VLESS + TLS
 * - VLESS + WebSocket (WS/WSS)
 * - VLESS + REALITY
 * - REALITY + xtls-rprx-vision
 *
 * Unsupported VLESS transports are ignored:
 * grpc, xhttp, h2, mkcp/kcp, httpupgrade
 */

(function () {
  "use strict";

  function safeDecodeURIComponent(s) {
    try { return decodeURIComponent(s || ""); }
    catch (_) { return s || ""; }
  }

  function utf8Decode(bin) {
    var out = "", i = 0, c, c2, c3, c4, cp;
    while (i < bin.length) {
      c = bin.charCodeAt(i++) & 255;
      if (c < 0x80) {
        out += String.fromCharCode(c);
      } else if ((c & 0xE0) === 0xC0) {
        if (i >= bin.length) break;
        c2 = bin.charCodeAt(i++) & 255;
        out += String.fromCharCode(((c & 0x1F) << 6) | (c2 & 0x3F));
      } else if ((c & 0xF0) === 0xE0) {
        if (i + 1 >= bin.length) break;
        c2 = bin.charCodeAt(i++) & 255;
        c3 = bin.charCodeAt(i++) & 255;
        out += String.fromCharCode(
          ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F)
        );
      } else if ((c & 0xF8) === 0xF0) {
        if (i + 2 >= bin.length) break;
        c2 = bin.charCodeAt(i++) & 255;
        c3 = bin.charCodeAt(i++) & 255;
        c4 = bin.charCodeAt(i++) & 255;
        cp = ((c & 7) << 18) | ((c2 & 63) << 12) | ((c3 & 63) << 6) | (c4 & 63);
        cp -= 0x10000;
        out += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
      }
    }
    return out;
  }

  function base64Decode(input) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var s = String(input || "").replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";

    var out = "", i = 0, e1, e2, e3, e4, c1, c2, c3;
    while (i < s.length) {
      e1 = chars.indexOf(s.charAt(i++));
      e2 = chars.indexOf(s.charAt(i++));
      e3 = chars.indexOf(s.charAt(i++));
      e4 = chars.indexOf(s.charAt(i++));

      if (e1 < 0 || e2 < 0) break;

      c1 = (e1 << 2) | (e2 >> 4);
      out += String.fromCharCode(c1);

      if (e3 >= 0) {
        c2 = ((e2 & 15) << 4) | (e3 >> 2);
        out += String.fromCharCode(c2);
      }
      if (e4 >= 0) {
        c3 = ((e3 & 3) << 6) | e4;
        out += String.fromCharCode(c3);
      }
    }
    return utf8Decode(out);
  }

  function utf8Encode(str) {
    var out = "", i = 0, c, cp;
    for (; i < str.length; i++) {
      c = str.charCodeAt(i);
      if (c < 0x80) {
        out += String.fromCharCode(c);
      } else if (c < 0x800) {
        out += String.fromCharCode(0xC0 | (c >> 6));
        out += String.fromCharCode(0x80 | (c & 63));
      } else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
        cp = ((c - 0xD800) << 10) + (str.charCodeAt(++i) - 0xDC00) + 0x10000;
        out += String.fromCharCode(0xF0 | (cp >> 18));
        out += String.fromCharCode(0x80 | ((cp >> 12) & 63));
        out += String.fromCharCode(0x80 | ((cp >> 6) & 63));
        out += String.fromCharCode(0x80 | (cp & 63));
      } else {
        out += String.fromCharCode(0xE0 | (c >> 12));
        out += String.fromCharCode(0x80 | ((c >> 6) & 63));
        out += String.fromCharCode(0x80 | (c & 63));
      }
    }
    return out;
  }

  function base64Encode(input) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bin = utf8Encode(String(input || ""));
    var out = "", i = 0, c1, c2, c3, e1, e2, e3, e4;

    while (i < bin.length) {
      c1 = bin.charCodeAt(i++) & 255;
      c2 = i < bin.length ? bin.charCodeAt(i++) & 255 : NaN;
      c3 = i < bin.length ? bin.charCodeAt(i++) & 255 : NaN;

      e1 = c1 >> 2;
      e2 = ((c1 & 3) << 4) | (isNaN(c2) ? 0 : (c2 >> 4));
      e3 = isNaN(c2) ? 64 : (((c2 & 15) << 2) | (isNaN(c3) ? 0 : (c3 >> 6)));
      e4 = isNaN(c3) ? 64 : (c3 & 63);

      out += chars.charAt(e1);
      out += chars.charAt(e2);
      out += e3 === 64 ? "=" : chars.charAt(e3);
      out += e4 === 64 ? "=" : chars.charAt(e4);
    }
    return out;
  }

  function parseQuery(qs) {
    var obj = {};
    if (!qs) return obj;

    qs.split("&").forEach(function (part) {
      if (!part) return;
      var p = part.indexOf("=");
      var k = p >= 0 ? part.slice(0, p) : part;
      var v = p >= 0 ? part.slice(p + 1) : "";
      k = safeDecodeURIComponent(k).toLowerCase();
      v = safeDecodeURIComponent(v);
      obj[k] = v;
    });

    return obj;
  }

  function sanitizeTag(tag, fallback) {
    tag = String(tag || fallback || "VLESS")
      .replace(/[\r\n]+/g, " ")
      .replace(/,/g, "，")
      .trim();
    return tag || "VLESS";
  }

  function normalizeContent(content) {
    var s = String(content || "").trim();
    if (!s) return "";

    if (s.indexOf("vless://") !== -1) return s;

    if (/^[A-Za-z0-9+/_=\-\r\n]+$/.test(s)) {
      try {
        var decoded = base64Decode(s);
        if (decoded.indexOf("vless://") !== -1) return decoded;
      } catch (_) {}
    }
    return s;
  }

  function parseAuthority(authority) {
    var m = authority.match(/^\[([^\]]+)\]:(\d+)$/);
    if (m) return { endpoint: "[" + m[1] + "]:" + m[2] };

    var idx = authority.lastIndexOf(":");
    if (idx <= 0) return null;

    var host = authority.slice(0, idx);
    var port = authority.slice(idx + 1);
    if (!/^\d+$/.test(port)) return null;

    return { endpoint: host + ":" + port };
  }

  function parseVless(uri) {
    uri = String(uri || "").trim();
    if (uri.indexOf("vless://") !== 0) return null;

    var body = uri.slice(8);
    var hashPos = body.indexOf("#");
    var tag = "";
    if (hashPos >= 0) {
      tag = safeDecodeURIComponent(body.slice(hashPos + 1));
      body = body.slice(0, hashPos);
    }

    var qPos = body.indexOf("?");
    var query = qPos >= 0 ? body.slice(qPos + 1) : "";
    var main = qPos >= 0 ? body.slice(0, qPos) : body;

    var atPos = main.lastIndexOf("@");
    if (atPos <= 0) return null;

    var uuid = safeDecodeURIComponent(main.slice(0, atPos)).trim();
    var authority = main.slice(atPos + 1).trim();
    if (!uuid || !authority) return null;

    var addr = parseAuthority(authority);
    if (!addr) return null;

    var q = parseQuery(query);
    var transport = String(q.type || "tcp").toLowerCase();
    var security = String(q.security || (q.tls === "1" ? "tls" : "none")).toLowerCase();

    if (["grpc", "xhttp", "h2", "mkcp", "kcp", "httpupgrade", "http-upgrade"].indexOf(transport) !== -1) {
      return null;
    }
    if (transport !== "tcp" && transport !== "ws") return null;

    var isTLS = security === "tls";
    var isReality = security === "reality";
    var sni = q.sni || q.servername || q.peer || "";
    var wsHost = q.host || "";
    var path = q.path || "";
    var pbk = q.pbk || q["public-key"] || "";
    var sid = q.sid || q["short-id"] || "";
    var flow = q.flow || "";

    if (isReality && !pbk) return null;

    var out = [
      "vless=" + addr.endpoint,
      "method=none",
      "password=" + uuid
    ];

    if (transport === "ws") {
      out.push("obfs=" + ((isTLS || isReality) ? "wss" : "ws"));
      if (wsHost || sni) out.push("obfs-host=" + (wsHost || sni));
      if (path) out.push("obfs-uri=" + path);
    } else if (isTLS || isReality) {
      out.push("obfs=over-tls");
      if (sni) out.push("obfs-host=" + sni);
    }

    if (isReality) {
      out.push("reality-base64-pubkey=" + pbk);
      if (sid) out.push("reality-hex-shortid=" + sid);

      if (flow === "xtls-rprx-vision" || flow === "xtls-rprx-vision-udp443") {
        out.push("vless-flow=xtls-rprx-vision");
      }
    } else if (isTLS) {
      var insecure = String(q.allowinsecure || "").toLowerCase();
      out.push("tls-verification=" + ((insecure === "1" || insecure === "true") ? "false" : "true"));
    }

    out.push("udp-relay=" + ((q.udp === "1" || String(q.udp).toLowerCase() === "true") ? "true" : "false"));
    out.push("fast-open=" + ((q.tfo === "1" || String(q.tfo).toLowerCase() === "true") ? "true" : "false"));
    out.push("tag=" + sanitizeTag(tag, "[vless] " + addr.endpoint));

    return out.join(", ");
  }

  try {
    if (typeof $resource === "undefined") {
      $done({ content: "" });
      return;
    }

    var content = normalizeContent($resource.content);
    var lines = content.split(/\r?\n/);
    var nodes = [];

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line.indexOf("vless://") !== 0) continue;

      var node = parseVless(line);
      if (node) nodes.push(node);
    }

$done({ content: nodes.join("\n") });
  } catch (e) {
    console.log("Minimal VLESS parser error: " + e);
    $done({ content: "" });
  }
})();
