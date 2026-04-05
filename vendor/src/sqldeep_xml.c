// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
//
// SQLite runtime implementations of xml_element, xml_attrs, and xml_agg.
//
// BLOB protocol: all XML output is returned as BLOB so xml_element can
// distinguish "already-XML" children (pass through) from plain TEXT
// (which must be escaped).  The caller uses CAST(... AS TEXT) to
// convert the final result back to a string.

#include "sqldeep_xml.h"

#include <sqlite3.h>
#include <string.h>

static int is_xml_blob(sqlite3_value *v) {
    return sqlite3_value_type(v) == SQLITE_BLOB;
}

// ── Escaping helpers ────────────────────────────────────────────────

static int xml_escaped_len(const char *s) {
    int n = 0;
    for (; *s; ++s) {
        switch (*s) {
        case '<': n += 4; break;
        case '>': n += 4; break;
        case '&': n += 5; break;
        default:  n++; break;
        }
    }
    return n;
}

static void xml_escape_text_to(const char *s, char *out, int *pos) {
    for (; *s; ++s) {
        switch (*s) {
        case '<': memcpy(out + *pos, "&lt;", 4); *pos += 4; break;
        case '>': memcpy(out + *pos, "&gt;", 4); *pos += 4; break;
        case '&': memcpy(out + *pos, "&amp;", 5); *pos += 5; break;
        default:  out[*pos] = *s; (*pos)++; break;
        }
    }
}

// ── xml_attrs(name1, value1, name2, value2, ...) ────────────────────

static void sd_xml_attrs(sqlite3_context *ctx, int argc,
                          sqlite3_value **argv) {
    int i, len = 0;
    if (argc % 2 != 0) {
        sqlite3_result_error(ctx, "xml_attrs requires even number of args", -1);
        return;
    }
    for (i = 0; i < argc; i += 2) {
        const char *val;
        if (sqlite3_value_type(argv[i + 1]) == SQLITE_NULL) continue;
        len += 1; /* space */
        len += (int)strlen((const char *)sqlite3_value_text(argv[i]));
        val = (const char *)sqlite3_value_text(argv[i + 1]);
        len += 2 + xml_escaped_len(val); /* ="..." */
    }
    char *out = (char *)sqlite3_malloc(len + 1);
    if (!out) { sqlite3_result_error_nomem(ctx); return; }
    int pos = 0;
    for (i = 0; i < argc; i += 2) {
        const char *name, *val;
        if (sqlite3_value_type(argv[i + 1]) == SQLITE_NULL) continue;
        name = (const char *)sqlite3_value_text(argv[i]);
        val = (const char *)sqlite3_value_text(argv[i + 1]);
        out[pos++] = ' ';
        memcpy(out + pos, name, strlen(name));
        pos += (int)strlen(name);
        out[pos++] = '=';
        out[pos++] = '"';
        for (const char *p = val; *p; ++p) {
            switch (*p) {
            case '"': memcpy(out + pos, "&quot;", 6); pos += 6; break;
            case '<': memcpy(out + pos, "&lt;", 4); pos += 4; break;
            case '>': memcpy(out + pos, "&gt;", 4); pos += 4; break;
            case '&': memcpy(out + pos, "&amp;", 5); pos += 5; break;
            default:  out[pos++] = *p; break;
            }
        }
        out[pos++] = '"';
    }
    out[pos] = '\0';
    sqlite3_result_blob(ctx, out, pos, sqlite3_free);
}

// ── xml_element(tag, [attrs], ...children) ──────────────────────────

static void sd_xml_element(sqlite3_context *ctx, int argc,
                            sqlite3_value **argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "xml_element requires at least 1 arg", -1);
        return;
    }
    const char *tag = (const char *)sqlite3_value_text(argv[0]);
    int taglen = (int)strlen(tag);
    const char *attrs = "";
    int attrslen = 0;
    int child_start = 1;

    if (argc > 1 && is_xml_blob(argv[1])) {
        const char *a = (const char *)sqlite3_value_blob(argv[1]);
        int alen = sqlite3_value_bytes(argv[1]);
        if (alen > 0 && a[0] == ' ') {
            attrs = a;
            attrslen = alen;
            child_start = 2;
        }
    }

    int has_children = 0;
    int children_len = 0;
    for (int i = child_start; i < argc; ++i) {
        if (sqlite3_value_type(argv[i]) == SQLITE_NULL) continue;
        has_children = 1;
        if (is_xml_blob(argv[i])) {
            children_len += sqlite3_value_bytes(argv[i]);
        } else {
            const char *c = (const char *)sqlite3_value_text(argv[i]);
            children_len += xml_escaped_len(c);
        }
    }

    /* <tag attrs> children </tag> + NUL */
    int outlen = 1 + taglen + attrslen +
                 (has_children ? 1 + children_len + 2 + taglen + 1 : 2) + 1;
    char *out = (char *)sqlite3_malloc(outlen);
    if (!out) { sqlite3_result_error_nomem(ctx); return; }
    int pos = 0;
    out[pos++] = '<';
    memcpy(out + pos, tag, taglen); pos += taglen;
    memcpy(out + pos, attrs, attrslen); pos += attrslen;

    if (has_children) {
        out[pos++] = '>';
        for (int i = child_start; i < argc; ++i) {
            if (sqlite3_value_type(argv[i]) == SQLITE_NULL) continue;
            if (is_xml_blob(argv[i])) {
                int blen = sqlite3_value_bytes(argv[i]);
                memcpy(out + pos, sqlite3_value_blob(argv[i]), blen);
                pos += blen;
            } else {
                const char *c = (const char *)sqlite3_value_text(argv[i]);
                xml_escape_text_to(c, out, &pos);
            }
        }
        out[pos++] = '<';
        out[pos++] = '/';
        memcpy(out + pos, tag, taglen); pos += taglen;
        out[pos++] = '>';
    } else {
        out[pos++] = '/';
        out[pos++] = '>';
    }
    out[pos] = '\0';
    sqlite3_result_blob(ctx, out, pos, sqlite3_free);
}

// ── xml_agg (aggregate) ─────────────────────────────────────────────

typedef struct XmlAggCtx {
    char *buf;
    int len;
    int cap;
} XmlAggCtx;

static void xml_agg_append(XmlAggCtx *p, const char *s, int n) {
    if (p->len + n >= p->cap) {
        int newcap = (p->cap + n) * 2 + 64;
        p->buf = (char *)sqlite3_realloc(p->buf, newcap);
        p->cap = newcap;
    }
    memcpy(p->buf + p->len, s, n);
    p->len += n;
}

static void sd_xml_agg_step(sqlite3_context *ctx, int argc,
                             sqlite3_value **argv) {
    (void)argc;
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL) return;
    XmlAggCtx *p = (XmlAggCtx *)sqlite3_aggregate_context(ctx, sizeof(*p));
    if (!p) return;
    if (is_xml_blob(argv[0])) {
        int blen = sqlite3_value_bytes(argv[0]);
        xml_agg_append(p, (const char *)sqlite3_value_blob(argv[0]), blen);
    } else {
        const char *v = (const char *)sqlite3_value_text(argv[0]);
        for (const char *c = v; *c; ++c) {
            switch (*c) {
            case '<': xml_agg_append(p, "&lt;", 4); break;
            case '>': xml_agg_append(p, "&gt;", 4); break;
            case '&': xml_agg_append(p, "&amp;", 5); break;
            default: xml_agg_append(p, c, 1); break;
            }
        }
    }
}

static void sd_xml_agg_final(sqlite3_context *ctx) {
    XmlAggCtx *p = (XmlAggCtx *)sqlite3_aggregate_context(ctx, 0);
    if (!p || !p->buf || p->len == 0) {
        sqlite3_result_blob(ctx, "", 0, SQLITE_STATIC);
        return;
    }
    sqlite3_result_blob(ctx, p->buf, p->len, sqlite3_free);
}

// ── JSON string escaping helper ──────────────────────────────────────

static int json_escaped_len(const char *s, int n) {
    int len = 0;
    for (int i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"': case '\\': len += 2; break;
        case '\b': case '\f': case '\n': case '\r': case '\t': len += 2; break;
        default:
            if (c < 0x20) len += 6; /* \uXXXX */
            else len++;
            break;
        }
    }
    return len;
}

static void json_escape_to(const char *s, int n, char *out, int *pos) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  out[(*pos)++] = '\\'; out[(*pos)++] = '"'; break;
        case '\\': out[(*pos)++] = '\\'; out[(*pos)++] = '\\'; break;
        case '\b': out[(*pos)++] = '\\'; out[(*pos)++] = 'b'; break;
        case '\f': out[(*pos)++] = '\\'; out[(*pos)++] = 'f'; break;
        case '\n': out[(*pos)++] = '\\'; out[(*pos)++] = 'n'; break;
        case '\r': out[(*pos)++] = '\\'; out[(*pos)++] = 'r'; break;
        case '\t': out[(*pos)++] = '\\'; out[(*pos)++] = 't'; break;
        default:
            if (c < 0x20) {
                out[(*pos)++] = '\\'; out[(*pos)++] = 'u';
                out[(*pos)++] = '0'; out[(*pos)++] = '0';
                out[(*pos)++] = hex[c >> 4]; out[(*pos)++] = hex[c & 0xf];
            } else {
                out[(*pos)++] = (char)c;
            }
            break;
        }
    }
}

// ── xml_attrs_jsonml(name1, value1, name2, value2, ...) ─────────────

static void sd_xml_attrs_jsonml(sqlite3_context *ctx, int argc,
                                 sqlite3_value **argv) {
    int i, len = 2; /* {} */
    int nattrs = 0;
    if (argc % 2 != 0) {
        sqlite3_result_error(ctx, "xml_attrs_jsonml requires even number of args", -1);
        return;
    }
    for (i = 0; i < argc; i += 2) {
        const char *name, *val;
        int namelen, vallen;
        if (sqlite3_value_type(argv[i + 1]) == SQLITE_NULL) continue;
        nattrs++;
        name = (const char *)sqlite3_value_text(argv[i]);
        namelen = (int)strlen(name);
        val = (const char *)sqlite3_value_text(argv[i + 1]);
        vallen = (int)strlen(val);
        len += 2 + json_escaped_len(name, namelen); /* "name" */
        len += 1; /* : */
        len += 2 + json_escaped_len(val, vallen);   /* "val" */
    }
    if (nattrs > 1) len += nattrs - 1; /* commas */
    char *out = (char *)sqlite3_malloc(len + 1);
    if (!out) { sqlite3_result_error_nomem(ctx); return; }
    int pos = 0;
    int written = 0;
    out[pos++] = '{';
    for (i = 0; i < argc; i += 2) {
        const char *name, *val;
        int namelen, vallen;
        if (sqlite3_value_type(argv[i + 1]) == SQLITE_NULL) continue;
        if (written++ > 0) out[pos++] = ',';
        name = (const char *)sqlite3_value_text(argv[i]);
        namelen = (int)strlen(name);
        val = (const char *)sqlite3_value_text(argv[i + 1]);
        vallen = (int)strlen(val);
        out[pos++] = '"';
        json_escape_to(name, namelen, out, &pos);
        out[pos++] = '"';
        out[pos++] = ':';
        out[pos++] = '"';
        json_escape_to(val, vallen, out, &pos);
        out[pos++] = '"';
    }
    out[pos++] = '}';
    out[pos] = '\0';
    sqlite3_result_blob(ctx, out, pos, sqlite3_free);
}

// ── xml_element_jsonml(tag, [attrs], ...children) ───────────────────

static void sd_xml_element_jsonml(sqlite3_context *ctx, int argc,
                                   sqlite3_value **argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "xml_element_jsonml requires at least 1 arg", -1);
        return;
    }
    const char *tag = (const char *)sqlite3_value_text(argv[0]);
    int taglen = (int)strlen(tag);
    int child_start = 1;
    const char *attrs = NULL;
    int attrslen = 0;

    /* Detect attrs BLOB: starts with '{' */
    if (argc > 1 && is_xml_blob(argv[1])) {
        const char *a = (const char *)sqlite3_value_blob(argv[1]);
        int alen = sqlite3_value_bytes(argv[1]);
        if (alen > 0 && a[0] == '{') {
            attrs = a;
            attrslen = alen;
            child_start = 2;
        }
    }

    /* Calculate output length: ["tag",{attrs},children...] */
    int len = 1; /* [ */
    len += 2 + json_escaped_len(tag, taglen); /* "tag" */
    if (attrs) {
        len += 1 + attrslen; /* ,{attrs} */
    }
    for (int i = child_start; i < argc; ++i) {
        int blen;
        if (sqlite3_value_type(argv[i]) == SQLITE_NULL) continue;
        if (is_xml_blob(argv[i])) {
            blen = sqlite3_value_bytes(argv[i]);
            if (blen == 0) continue; /* empty agg result */
            len += 1 + blen; /* comma + raw JSONML */
        } else {
            /* Text — JSON string */
            const char *c = (const char *)sqlite3_value_text(argv[i]);
            int clen = (int)strlen(c);
            len += 1 + 2 + json_escaped_len(c, clen); /* comma + "..." */
        }
    }
    len += 1; /* ] */

    char *out = (char *)sqlite3_malloc(len + 1);
    if (!out) { sqlite3_result_error_nomem(ctx); return; }
    int pos = 0;
    out[pos++] = '[';
    out[pos++] = '"';
    json_escape_to(tag, taglen, out, &pos);
    out[pos++] = '"';
    if (attrs) {
        out[pos++] = ',';
        memcpy(out + pos, attrs, attrslen);
        pos += attrslen;
    }
    for (int i = child_start; i < argc; ++i) {
        if (sqlite3_value_type(argv[i]) == SQLITE_NULL) continue;
        if (is_xml_blob(argv[i])) {
            int blen = sqlite3_value_bytes(argv[i]);
            if (blen == 0) continue;
            out[pos++] = ',';
            memcpy(out + pos, sqlite3_value_blob(argv[i]), blen);
            pos += blen;
        } else {
            const char *c = (const char *)sqlite3_value_text(argv[i]);
            int clen = (int)strlen(c);
            out[pos++] = ',';
            out[pos++] = '"';
            json_escape_to(c, clen, out, &pos);
            out[pos++] = '"';
        }
    }
    out[pos++] = ']';
    out[pos] = '\0';
    sqlite3_result_blob(ctx, out, pos, sqlite3_free);
}

// ── jsonml_agg (aggregate) ──────────────────────────────────────────
// Collects JSONML fragments as comma-separated bytes in a BLOB.
// xml_element_jsonml splices the result into its children.

static void sd_jsonml_agg_step(sqlite3_context *ctx, int argc,
                                sqlite3_value **argv) {
    (void)argc;
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL) return;
    XmlAggCtx *p = (XmlAggCtx *)sqlite3_aggregate_context(ctx, sizeof(*p));
    if (!p) return;
    if (p->len > 0) xml_agg_append(p, ",", 1);
    if (is_xml_blob(argv[0])) {
        int blen = sqlite3_value_bytes(argv[0]);
        xml_agg_append(p, (const char *)sqlite3_value_blob(argv[0]), blen);
    } else {
        /* Text child — emit as JSON string */
        const char *v = (const char *)sqlite3_value_text(argv[0]);
        int vlen = (int)strlen(v);
        int elen = 2 + json_escaped_len(v, vlen);
        /* Ensure capacity and write directly */
        if (p->len + elen >= p->cap) {
            int newcap = (p->cap + elen) * 2 + 64;
            p->buf = (char *)sqlite3_realloc(p->buf, newcap);
            p->cap = newcap;
        }
        p->buf[p->len++] = '"';
        json_escape_to(v, vlen, p->buf, &p->len);
        p->buf[p->len++] = '"';
    }
}

static void sd_jsonml_agg_final(sqlite3_context *ctx) {
    XmlAggCtx *p = (XmlAggCtx *)sqlite3_aggregate_context(ctx, 0);
    if (!p || !p->buf || p->len == 0) {
        sqlite3_result_blob(ctx, "", 0, SQLITE_STATIC);
        return;
    }
    sqlite3_result_blob(ctx, p->buf, p->len, sqlite3_free);
}

// ── Public registration ─────────────────────────────────────────────

int sqldeep_register_sqlite_xml(sqlite3 *db) {
    int rc;
    rc = sqlite3_create_function(db, "xml_element", -1, SQLITE_UTF8,
                                 0, sd_xml_element, 0, 0);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "xml_attrs", -1, SQLITE_UTF8,
                                 0, sd_xml_attrs, 0, 0);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "xml_agg", 1, SQLITE_UTF8,
                                 0, 0, sd_xml_agg_step, sd_xml_agg_final);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "xml_element_jsonml", -1, SQLITE_UTF8,
                                 0, sd_xml_element_jsonml, 0, 0);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "xml_attrs_jsonml", -1, SQLITE_UTF8,
                                 0, sd_xml_attrs_jsonml, 0, 0);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "jsonml_agg", 1, SQLITE_UTF8,
                                 0, 0, sd_jsonml_agg_step, sd_jsonml_agg_final);
    return rc;
}
