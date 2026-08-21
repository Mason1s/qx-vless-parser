/**
 * Quantumult X - VLESS Only Resource Parser
 *
 * 精简自 KOP-XIAO resource-parser 的 VLESS 处理逻辑
 *
 * 保留：
 * - VLESS TCP
 * - VLESS TLS
 * - VLESS WS/WSS
 * - VLESS Reality
 * - VLESS Reality + Vision
 * - 普通 VLESS URI
 * - Base64 VLESS 订阅
 * - server / uri 资源类型
 *
 * 删除：
 * - SS / SSR
 * - VMess
 * - Trojan
 * - AnyTLS
 * - Clash / Surge / Loon
 * - Rewrite / Filter
 * - rename / filter
 * - eval
 * - 网络请求
 * - UA Retry
 */

(function () {
  "use strict";

  // =========================================================
  // Quantumult X 环境
  // =========================================================

  var resource =
    typeof $resource !== "undefined"
      ? $resource
      : {};

  var link0 =
    String(resource.link || "");

  var content0 =
    String(resource.content || "");

  var typeQ =
    String(resource.type || "unsupported");


  // =========================================================
  // Quantumult X Build
  // =========================================================

  var version = 0;

  try {

    if (
      typeof $environment !== "undefined" &&
      $environment.version
    ) {

      var buildMatch =
        String($environment.version)
          .match(/build\s*(\d+)/i);

      if (buildMatch) {
        version =
          Number(buildMatch[1]);
      }
    }

  } catch (_) {}


  // =========================================================
  // 订阅 URL 参数
  //
  // 支持：
  // #udp=1
  // #tfo=1
  // #cert=1
  // =========================================================

  var para =
    /^(http|https):\/\//i.test(link0)
      ? link0
      : (
          content0
            .split(/\r?\n/)[0] || ""
        );


  var hashPos =
    para.indexOf("#");


  var para1 =
    hashPos >= 0
      ? para.slice(hashPos + 1)
      : "";


  function getParam(
    name,
    fallback
  ) {

    var reg =
      new RegExp(
        "(?:^|&)" +
        name +
        "=([^&]*)",
        "i"
      );


    var m =
      para1.match(reg);


    return m
      ? m[1]
      : fallback;
  }


  var Pudp0 =
    getParam(
      "udp",
      0
    );


  var Ptfo0 =
    getParam(
      "tfo",
      0
    );


  var Pcert0 =
    getParam(
      "cert",
      getParam(
        "tls-verification",
        0
      )
    );


  // =========================================================
  // Base64
  // =========================================================

  var Base64 = {

    chars:
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",


    utf8Encode: function (str) {

      str =
        String(str || "");

      var out = "";

      var i;
      var c;
      var cp;


      for (
        i = 0;
        i < str.length;
        i++
      ) {

        c =
          str.charCodeAt(i);


        if (
          c < 0x80
        ) {

          out +=
            String.fromCharCode(c);


        } else if (
          c < 0x800
        ) {

          out +=
            String.fromCharCode(
              0xC0 |
              (c >> 6)
            );


          out +=
            String.fromCharCode(
              0x80 |
              (c & 63)
            );


        } else if (
          c >= 0xD800 &&
          c <= 0xDBFF &&
          i + 1 < str.length
        ) {

          cp =
            (
              (c - 0xD800)
              << 10
            ) +
            (
              str.charCodeAt(++i)
              - 0xDC00
            ) +
            0x10000;


          out +=
            String.fromCharCode(
              0xF0 |
              (cp >> 18)
            );


          out +=
            String.fromCharCode(
              0x80 |
              (
                (cp >> 12) &
                63
              )
            );


          out +=
            String.fromCharCode(
              0x80 |
              (
                (cp >> 6) &
                63
              )
            );


          out +=
            String.fromCharCode(
              0x80 |
              (cp & 63)
            );


        } else {

          out +=
            String.fromCharCode(
              0xE0 |
              (c >> 12)
            );


          out +=
            String.fromCharCode(
              0x80 |
              (
                (c >> 6) &
                63
              )
            );


          out +=
            String.fromCharCode(
              0x80 |
              (c & 63)
            );
        }
      }


      return out;
    },


    utf8Decode: function (bin) {

      var out = "";

      var i = 0;

      var c;
      var c2;
      var c3;
      var c4;
      var cp;


      while (
        i < bin.length
      ) {

        c =
          bin.charCodeAt(i++)
          & 255;


        if (
          c < 0x80
        ) {

          out +=
            String.fromCharCode(c);


        } else if (
          (c & 0xE0)
          === 0xC0
        ) {

          if (
            i >= bin.length
          ) {
            break;
          }


          c2 =
            bin.charCodeAt(i++)
            & 255;


          out +=
            String.fromCharCode(
              (
                (c & 31)
                << 6
              ) |
              (
                c2 & 63
              )
            );


        } else if (
          (c & 0xF0)
          === 0xE0
        ) {

          if (
            i + 1 >=
            bin.length
          ) {
            break;
          }


          c2 =
            bin.charCodeAt(i++)
            & 255;


          c3 =
            bin.charCodeAt(i++)
            & 255;


          out +=
            String.fromCharCode(
              (
                (c & 15)
                << 12
              ) |
              (
                (c2 & 63)
                << 6
              ) |
              (
                c3 & 63
              )
            );


        } else if (
          (c & 0xF8)
          === 0xF0
        ) {

          if (
            i + 2 >=
            bin.length
          ) {
            break;
          }


          c2 =
            bin.charCodeAt(i++)
            & 255;


          c3 =
            bin.charCodeAt(i++)
            & 255;


          c4 =
            bin.charCodeAt(i++)
            & 255;


          cp =
            (
              (c & 7)
              << 18
            ) |
            (
              (c2 & 63)
              << 12
            ) |
            (
              (c3 & 63)
              << 6
            ) |
            (
              c4 & 63
            );


          cp -=
            0x10000;


          out +=
            String.fromCharCode(
              0xD800 +
              (cp >> 10),

              0xDC00 +
              (cp & 1023)
            );
        }
      }


      return out;
    },


    encode: function (input) {

      var bin =
        this.utf8Encode(
          input
        );


      var chars =
        this.chars;


      var out = "";

      var i = 0;

      var c1;
      var c2;
      var c3;

      var e1;
      var e2;
      var e3;
      var e4;


      while (
        i < bin.length
      ) {

        c1 =
          bin.charCodeAt(i++)
          & 255;


        c2 =
          i < bin.length
            ? (
                bin.charCodeAt(i++)
                & 255
              )
            : NaN;


        c3 =
          i < bin.length
            ? (
                bin.charCodeAt(i++)
                & 255
              )
            : NaN;


        e1 =
          c1 >> 2;


        e2 =
          (
            (c1 & 3)
            << 4
          ) |
          (
            isNaN(c2)
              ? 0
              : (
                  c2 >> 4
                )
          );


        e3 =
          isNaN(c2)
            ? 64
            : (
                (
                  (c2 & 15)
                  << 2
                ) |
                (
                  isNaN(c3)
                    ? 0
                    : (
                        c3 >> 6
                      )
                )
              );


        e4 =
          isNaN(c3)
            ? 64
            : (
                c3 & 63
              );


        out +=
          chars.charAt(e1);


        out +=
          chars.charAt(e2);


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
    },


    decode: function (input) {

      var chars =
        this.chars;


      var s =
        String(input || "")
          .replace(
            /\s+/g,
            ""
          )
          .replace(
            /-/g,
            "+"
          )
          .replace(
            /_/g,
            "/"
          );


      while (
        s.length % 4
      ) {
        s += "=";
      }


      var out = "";

      var i = 0;

      var e1;
      var e2;
      var e3;
      var e4;

      var c1;
      var c2;
      var c3;


      while (
        i < s.length
      ) {

        e1 =
          chars.indexOf(
            s.charAt(i++)
          );


        e2 =
          chars.indexOf(
            s.charAt(i++)
          );


        e3 =
          chars.indexOf(
            s.charAt(i++)
          );


        e4 =
          chars.indexOf(
            s.charAt(i++)
          );


        if (
          e1 < 0 ||
          e2 < 0
        ) {
          break;
        }


        c1 =
          (
            e1 << 2
          ) |
          (
            e2 >> 4
          );


        out +=
          String.fromCharCode(c1);


        if (
          e3 >= 0
        ) {

          c2 =
            (
              (e2 & 15)
              << 4
            ) |
            (
              e3 >> 2
            );


          out +=
            String.fromCharCode(c2);
        }


        if (
          e4 >= 0
        ) {

          c3 =
            (
              (e3 & 3)
              << 6
            ) |
            e4;


          out +=
            String.fromCharCode(c3);
        }
      }


      return this.utf8Decode(
        out
      );
    }
  };


  // =========================================================
  // 安全 URI Decode
  // =========================================================

  function decodeSafe(s) {

    try {

      return decodeURIComponent(
        s
      );

    } catch (_) {

      return s;
    }
  }


  // =========================================================
  // TLS Certificate
  //
  // 保持 KOP 默认行为：
  // 默认 tls-verification=false
  // =========================================================

  function tlsCertValue(
    cert
  ) {

    var raw =
      cert === undefined ||
      cert === null
        ? ""
        : String(cert).trim();


    if (!raw) {
      return "";
    }


    raw =
      decodeSafe(raw)
        .trim();


    var low =
      raw.toLowerCase();


    if (
      low === "1" ||
      low === "true"
    ) {
      return "true";
    }


    if (
      low === "-1" ||
      low === "0" ||
      low === "false"
    ) {
      return "false";
    }


    if (
      version >= 938 &&
      /^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}$/.test(raw)
    ) {
      return raw;
    }


    return "";
  }


  function tlsCertParam(
    cert,
    fallback
  ) {

    var value =
      tlsCertValue(cert);


    if (
      value === ""
    ) {
      value =
        fallback;
    }


    if (
      value === "" ||
      value === undefined ||
      value === null
    ) {

      return "";
    }


    return (
      "tls-verification=" +
      value
    );
  }


  // =========================================================
  // 读取 VLESS 参数
  // =========================================================

  function readParam(
    content,
    name
  ) {

    var key =
      name + "=";


    var pos =
      content.indexOf(key);


    if (
      pos === -1
    ) {
      return "";
    }


    return content
      .slice(
        pos + key.length
      )
      .split("&")[0]
      .split("#")[0]
      .replace(
        /\s/g,
        ""
      );
  }


  // =========================================================
  // Reality
  //
  // pbk  -> reality-base64-pubkey
  // sid  -> reality-hex-shortid
  // flow -> vless-flow
  // =========================================================

  function realityHandle(
    content
  ) {

    var result = [];


    var pbk =
      readParam(
        content,
        "pbk"
      );


    var sid =
      readParam(
        content,
        "sid"
      );


    if (pbk) {

      result.push(
        "reality-base64-pubkey=" +
        pbk
      );
    }


    if (sid) {

      result.push(
        "reality-hex-shortid=" +
        sid
      );
    }


    if (
      content.indexOf(
        "flow=xtls-rprx-vision"
      ) !== -1 ||
      content.indexOf(
        "xtls=2"
      ) !== -1
    ) {

      result.push(
        "vless-flow=xtls-rprx-vision"
      );
    }


    return result.join(
      ", "
    );
  }


  // =========================================================
  // VLESS -> Quantumult X
  //
  // 核心按照原版 VL2QX 行为处理
  // =========================================================

  function VL2QX(
    subs
  ) {

    var parts =
      String(subs)
        .split("vless://");


    if (
      parts.length < 2
    ) {
      return "";
    }


    var cnt =
      parts
        .slice(1)
        .join("vless://");


    // 当前精简版只处理标准 VLESS URI
    if (
      cnt.indexOf("@") === -1
    ) {
      return "";
    }


    var ip =
      cnt
        .split("@")[1]
        .split("encry")[0]
        .split("?")[0];


    var pwd =
      "password=" +
      cnt.split("@")[0];


    var method =
      "method=none";


    var tag =
      cnt.indexOf("#") !== -1
        ? (
            "tag=" +
            decodeSafe(
              cnt
                .split("#")
                .slice(-1)[0]
            )
          )
        : (
            "tag= [vless]" +
            ip
          );


    var obfs = "";

    var thost = "";

    var puri = "";

    var pcert = "";


    // ---------------------------------------------------------
    // 初始 SNI
    // ---------------------------------------------------------

    if (
      cnt.indexOf("sni=") !== -1
    ) {

      thost =
        "tls-host=" +
        cnt
          .split("sni=")[1]
          .split(/&|#/)[0];
    }


    if (
      cnt.indexOf("peer=") !== -1
    ) {

      thost =
        "tls-host=" +
        cnt
          .split("peer=")[1]
          .split(/&|#/)[0];
    }


    // ---------------------------------------------------------
    // V2RayN 标准 VLESS URI
    // ---------------------------------------------------------

    if (
      cnt.indexOf("&type=ws") !== -1 ||
      cnt.indexOf("?type=ws") !== -1 ||
      cnt.indexOf("type=http") !== -1 ||
      cnt.indexOf("security=tls") !== -1 ||
      cnt.indexOf("security=reality") !== -1
    ) {


      // HTTP
      if (
        cnt.indexOf(
          "type=http"
        ) !== -1
      ) {

        obfs =
          "obfs=http";


      // WS
      } else if (
        cnt.indexOf(
          "type=ws"
        ) !== -1
      ) {

        obfs =
          (
            cnt.indexOf(
              "security=tls"
            ) !== -1 ||
            cnt.indexOf(
              "security=reality"
            ) !== -1
          )
            ? "obfs=wss"
            : "obfs=ws";


      // TCP + TLS / Reality
      } else if (
        cnt.indexOf(
          "type="
        ) === -1 ||
        cnt.indexOf(
          "type=tcp"
        ) !== -1
      ) {

        obfs =
          "obfs=over-tls";


      // 不支持
      } else {

        return "";
      }


      // -------------------------------------------------------
      // Host
      // -------------------------------------------------------

      var host1 =
        thost;


      var host2 =
        thost;


      if (
        cnt.indexOf(
          "&host="
        ) !== -1
      ) {

        host1 =
          "obfs-host=" +
          decodeSafe(
            cnt
              .split("&host=")[1]
              .split("&")[0]
              .split("#")[0]
          );
      }


      if (
        cnt.indexOf(
          "sni="
        ) !== -1
      ) {

        host2 =
          "obfs-host=" +
          decodeSafe(
            cnt
              .split("sni=")[1]
              .split("&")[0]
              .split("#")[0]
          )
          .replace(
            /\"|(Host\":)|\{|\}/g,
            ""
          );
      }


      thost =
        host1.length >=
        host2.length
          ? host1
          : host2;


      // -------------------------------------------------------
      // WS Path
      // -------------------------------------------------------

      if (
        cnt.indexOf(
          "&path="
        ) !== -1
      ) {

        puri =
          "obfs-uri=" +
          decodeSafe(
            cnt
              .split("&path=")[1]
              .split("&")[0]
              .split("#")[0]
          );
      }
    }


    // =========================================================
    // TLS 验证
    // =========================================================

    if (
      obfs === "obfs=wss" ||
      obfs === "obfs=over-tls"
    ) {

      pcert =
        tlsCertParam(
          Pcert0,

          cnt.indexOf(
            "allowInsecure=0"
          ) !== -1
            ? "true"
            : "false"
        );

    } else {

      pcert = "";
    }


    // =========================================================
    // UDP
    //
    // 保持原版默认 false
    // =========================================================

    var pudp =
      (
        String(Pudp0) === "1" ||
        cnt.indexOf(
          "udp=1"
        ) !== -1
      )
        ? "udp-relay=true"
        : "udp-relay=false";


    // =========================================================
    // Fast Open
    //
    // 保持原版默认 false
    // =========================================================

    var ptfo =
      (
        String(Ptfo0) === "1" ||
        cnt.indexOf(
          "tfo=1"
        ) !== -1
      )
        ? "fast-open=true"
        : "fast-open=false";


    // =========================================================
    // Reality
    // =========================================================

    var reality = "";


    if (
      version === 0 ||
      version >= 891
    ) {

      reality =
        realityHandle(
          cnt
        );
    }


    // =========================================================
    // Quantumult X 节点
    // =========================================================

    var result = [

      "vless=" + ip,

      pwd,

      method,

      obfs,

      pcert,

      thost,

      puri,

      pudp,

      ptfo,

      reality,

      tag

    ]
    .filter(Boolean)
    .join(", ");


    return result;
  }


  // =========================================================
  // 订阅 Decode
  //
  // 原版同时支持：
  // 1. 明文 URI
  // 2. 整个订阅 Base64
  // =========================================================

  function decodeSubscription(
    content
  ) {

    var src =
      String(content || "")
        .trim();


    if (!src) {
      return "";
    }


    // 已经是 VLESS URI
    if (
      src.indexOf(
        "vless://"
      ) !== -1
    ) {

      return src;
    }


    // 尝试 Base64
    try {

      var decoded =
        Base64.decode(
          src
        );


      if (
        decoded.indexOf(
          "vless://"
        ) !== -1
      ) {

        return decoded;
      }

    } catch (_) {}


    return src;
  }


  // =========================================================
  // Subs2QX
  //
  // 原版 Subs2QX 的 VLESS-only 版本
  // =========================================================

  function Subs2QX(
    content
  ) {

    var decoded =
      decodeSubscription(
        content
      );


    var lines =
      decoded.split(
        /\r?\n/
      );


    var result = [];


    for (
      var i = 0;
      i < lines.length;
      i++
    ) {

      var line =
        lines[i].trim();


      if (
        line.indexOf(
          "vless://"
        ) !== 0
      ) {
        continue;
      }


      var node =
        VL2QX(
          line
        );


      if (node) {

        result.push(
          node
        );
      }
    }


    return result;
  }


  // =========================================================
  // Main
  // =========================================================

  try {


    // ---------------------------------------------------------
    // 原版 VLESS 节点应进入 server / uri 类型
    // ---------------------------------------------------------

    if (
      typeQ !== "server" &&
      typeQ !== "uri" &&
      typeQ !== "unsupported" &&
      typeQ !== ""
    ) {

      $done({
        content: ""
      });

      return;
    }


    // ---------------------------------------------------------
    // 一般情况从 content 获取
    // ---------------------------------------------------------

    var source =
      content0;


    // ---------------------------------------------------------
    // 单条 URI 情况
    // ---------------------------------------------------------

    if (
      !source.trim() &&
      /^vless:\/\//i.test(
        link0
      )
    ) {

      source =
        link0;
    }


    // ---------------------------------------------------------
    // VLESS 转换
    // ---------------------------------------------------------

    var nodes =
      Subs2QX(
        source
      );


    // ---------------------------------------------------------
    // 原版节点资源：
    // Quantumult X 节点统一 Base64 返回
    // ---------------------------------------------------------

    var total =
      nodes.length
        ? Base64.encode(
            nodes.join("\n")
          )
        : "";


    $done({
      content: total
    });


  } catch (error) {


    console.log(
      "VLESS parser error: " +
      error
    );


    // 不返回 error 对象，
    // 保持资源解析器 content 类型
    $done({
      content: ""
    });
  }

})();
