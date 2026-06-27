// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
//
// sqldeep — JSON5-like SQL syntax transpiler.
//
// Implementation strategy: parse the input via deepparser (which knows
// the sqldeep grammar), then walk the resulting AST and rewrite every
// sqldeep-extension node in place into standard SQL nodes. Once the
// AST contains only plain SQL kinds, deepparser's canonical unparser
// emits the final SQL text. Sqldeep itself owns nothing about parsing
// or printing — it is purely an AST-to-AST transformer plus the
// outward-facing C API.

#include "sqldeep.h"

extern "C" {
#include "liteparser.h"
#include "arena.h"
}

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace sqldeep {

struct ForeignKey {
    std::string from_table;
    std::string to_table;
    struct ColumnPair {
        std::string from_column;
        std::string to_column;
    };
    std::vector<ColumnPair> columns;
};

enum class Backend { sqlite, postgres, sqlite_vanilla };

class Error : public std::runtime_error {
public:
    Error(const std::string& msg, int line, int col)
        : std::runtime_error(msg), line_(line), col_(col) {}
    int line() const { return line_; }
    int col()  const { return col_; }
private:
    int line_;
    int col_;
};

namespace {

// ── FK index ────────────────────────────────────────────────────────

using FkIndex = std::map<std::pair<std::string,std::string>,
                         std::vector<const ForeignKey*>>;

FkIndex build_fk_index(const std::vector<ForeignKey>& fks) {
    FkIndex idx;
    for (const auto& fk : fks) {
        idx[{fk.from_table, fk.to_table}].push_back(&fk);
    }
    return idx;
}

// Convention mode (fk_index == nullptr): child has FK '<parent>_id'.
std::vector<std::pair<std::string,std::string>>
resolve_fk_columns(const std::string& child_table,
                   const std::string& parent_table,
                   const FkIndex* fk_index) {
    if (!fk_index) {
        std::string col = parent_table + "_id";
        return {{col, col}};
    }
    auto it = fk_index->find({child_table, parent_table});
    if (it == fk_index->end() || it->second.empty()) {
        throw Error("no foreign key from '" + child_table + "' to '" +
                    parent_table + "'", 0, 0);
    }
    if (it->second.size() > 1) {
        throw Error("ambiguous foreign key from '" + child_table + "' to '" +
                    parent_table + "' (" + std::to_string(it->second.size()) +
                    " candidates)", 0, 0);
    }
    std::vector<std::pair<std::string,std::string>> cols;
    cols.reserve(it->second[0]->columns.size());
    for (const auto& cp : it->second[0]->columns)
        cols.emplace_back(cp.from_column, cp.to_column);
    return cols;
}

// ── AST construction helpers ─────────────────────────────────────────
//
// Sqldeep mutates the deepparser AST in place and also constructs new
// LpNode objects for replacement subtrees. The helpers below build the
// standard-SQL node kinds we emit; they parallel deepparser's
// grammar-action factories but live outside the parser since we're not
// parsing — we have nothing but an arena to allocate into.

LpNode *new_node(arena_t *arena, LpNodeKind kind) {
    auto *n = static_cast<LpNode*>(arena_zeroalloc(arena, sizeof(LpNode)));
    if (n) n->kind = kind;
    return n;
}

char *arena_str(arena_t *arena, const std::string& s) {
    return arena_strdup(arena, s.c_str());
}

void list_append(arena_t *arena, LpNodeList *list, LpNode *item) {
    if (list->count >= list->capacity) {
        int cap = list->capacity ? list->capacity * 2 : 4;
        auto **items = static_cast<LpNode**>(
            arena_alloc(arena, sizeof(LpNode*) * cap));
        if (!items) return;
        if (list->items)
            std::memcpy(items, list->items, sizeof(LpNode*) * list->count);
        list->items = items;
        list->capacity = cap;
    }
    list->items[list->count++] = item;
}

LpNode *make_string_lit(arena_t *arena, const std::string& value) {
    auto *n = new_node(arena, LP_EXPR_LITERAL_STRING);
    if (n) n->u.literal.value = arena_str(arena, value);
    return n;
}

LpNode *make_int_lit(arena_t *arena, const std::string& digits) {
    auto *n = new_node(arena, LP_EXPR_LITERAL_INT);
    if (n) n->u.literal.value = arena_str(arena, digits);
    return n;
}

LpNode *make_column_ref(arena_t *arena, const std::string& column) {
    auto *n = new_node(arena, LP_EXPR_COLUMN_REF);
    if (n) n->u.column_ref.column = arena_str(arena, column);
    return n;
}

LpNode *make_column_ref2(arena_t *arena, const std::string& table,
                          const std::string& column) {
    auto *n = new_node(arena, LP_EXPR_COLUMN_REF);
    if (!n) return nullptr;
    n->u.column_ref.table  = arena_str(arena, table);
    n->u.column_ref.column = arena_str(arena, column);
    return n;
}

LpNode *make_binop(arena_t *arena, LpBinOp op, LpNode *left, LpNode *right) {
    auto *n = new_node(arena, LP_EXPR_BINARY_OP);
    if (!n) return nullptr;
    n->u.binary.op    = op;
    n->u.binary.left  = left;
    n->u.binary.right = right;
    return n;
}

// AND together a chain of expressions, left-associative.
LpNode *and_chain(arena_t *arena, const std::vector<LpNode*>& parts) {
    if (parts.empty()) return nullptr;
    LpNode *acc = parts[0];
    for (size_t i = 1; i < parts.size(); i++)
        acc = make_binop(arena, LP_OP_AND, acc, parts[i]);
    return acc;
}

LpNode *make_from_table(arena_t *arena, const std::string& name,
                         const std::string& alias) {
    auto *n = new_node(arena, LP_FROM_TABLE);
    if (!n) return nullptr;
    n->u.from_table.name  = arena_str(arena, name);
    if (!alias.empty()) n->u.from_table.alias = arena_str(arena, alias);
    return n;
}

LpNode *make_join(arena_t *arena, LpNode *left, LpNode *right,
                   LpNode *on_expr) {
    auto *n = new_node(arena, LP_JOIN_CLAUSE);
    if (!n) return nullptr;
    n->u.join.left    = left;
    n->u.join.right   = right;
    n->u.join.on_expr = on_expr;
    /* join_type=0 → INNER JOIN; matches sqldeep's existing emission. */
    return n;
}

LpNode *make_function(arena_t *arena, const std::string& name,
                       std::vector<LpNode*> args) {
    auto *n = new_node(arena, LP_EXPR_FUNCTION);
    if (!n) return nullptr;
    n->u.function.name = arena_str(arena, name);
    for (auto *a : args) list_append(arena, &n->u.function.args, a);
    return n;
}

LpNode *make_cast(arena_t *arena, LpNode *expr, const std::string& type_name) {
    auto *n = new_node(arena, LP_EXPR_CAST);
    if (!n) return nullptr;
    n->u.cast.expr = expr;
    n->u.cast.type_name = arena_str(arena, type_name);
    return n;
}

LpNode *make_limit(arena_t *arena, int count) {
    auto *n = new_node(arena, LP_LIMIT);
    if (!n) return nullptr;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%d", count);
    n->u.limit.count = make_int_lit(arena, buf);
    return n;
}

// ── Positional-parameter order preservation ─────────────────────────
//
// Anonymous positional parameters ("?") are order-sensitive: SQLite and
// PostgreSQL number them by left-to-right textual position, so the Nth
// "?" in the caller's input must remain the Nth "?" in the transpiled
// output, or the caller's bound values silently land on the wrong
// placeholders. Sqldeep's rewrites can move expressions around (most
// obviously the FROM-first SELECT, whose projection is authored last but
// emitted first), so we must guarantee the order survives — or refuse.
//
// Rather than reason about which rewrite reorders what, we verify it
// empirically: before transforming, every "?" is renamed to a unique
// sentinel named parameter (":__sqldeep_param_<N>__") in source order.
// Transforms move AST nodes by kind and structure, never by variable
// name, so each sentinel lands exactly where its "?" would have. After
// unparsing we read the sentinels back out of the output; if they don't
// appear exactly once each, in ascending order, a rewrite reordered
// (or dropped/duplicated) the parameters and we raise an error.
// Otherwise the sentinels are substituted back to "?".
//
// Numbered ("?N") and named (":x" / "@x" / "$x") parameters bind by
// explicit index or name, so their position is irrelevant; they are left
// untouched and pass through unharmed.
constexpr const char *kPosParamPrefix = ":__sqldeep_param_";
constexpr const char *kPosParamSuffix = "__";

// Collect every anonymous "?" variable node in a statement.
void collect_anon_params(LpNode *root, std::vector<LpNode*>& out) {
    struct Ctx { LpVisitor v; std::vector<LpNode*> *out; } ctx{};
    ctx.v.user_data = &ctx;
    ctx.out = &out;
    ctx.v.enter = [](LpVisitor *v, LpNode *nd) -> int {
        if (nd->kind == LP_EXPR_VARIABLE && nd->u.variable.name
            && std::strcmp(nd->u.variable.name, "?") == 0) {
            static_cast<Ctx*>(v->user_data)->out->push_back(nd);
        }
        return 0;
    };
    ctx.v.leave = nullptr;
    lp_ast_walk(root, &ctx.v);
}

// Rename every "?" across all statements to a sentinel named parameter
// numbered 1..N in source (byte-offset) order. Returns N.
int mark_positional_params(LpNodeList *stmts, arena_t *arena) {
    std::vector<LpNode*> params;
    for (int i = 0; i < stmts->count; i++)
        collect_anon_params(stmts->items[i], params);
    std::sort(params.begin(), params.end(), [](LpNode *a, LpNode *b) {
        return a->pos.offset < b->pos.offset;
    });
    for (size_t i = 0; i < params.size(); i++) {
        std::string name = kPosParamPrefix + std::to_string(i + 1)
                         + kPosParamSuffix;
        params[i]->u.variable.name = arena_str(arena, name);
    }
    return static_cast<int>(params.size());
}

// Verify the N sentinels appear exactly once each, in ascending order,
// in the transpiled output; throw if a rewrite reordered them. On
// success, substitute each sentinel back to "?".
void restore_positional_params(std::string& sql, int count) {
    if (count == 0) return;
    const std::string prefix = kPosParamPrefix;
    std::vector<int> order;
    for (size_t pos = 0; (pos = sql.find(prefix, pos)) != std::string::npos;) {
        size_t num = pos + prefix.size();
        size_t end = num;
        while (end < sql.size() && sql[end] >= '0' && sql[end] <= '9') end++;
        order.push_back(std::atoi(sql.substr(num, end - num).c_str()));
        pos = end;
    }
    bool ok = (static_cast<int>(order.size()) == count);
    for (int i = 0; ok && i < count; i++) ok = (order[i] == i + 1);
    if (!ok) {
        throw Error("cannot preserve positional parameter (?) order: a "
                    "rewrite reordered the '?' placeholders, which would "
                    "misbind the caller's values. Use named (:name) or "
                    "numbered (?1) parameters instead.", 0, 0);
    }
    for (int n = 1; n <= count; n++) {
        std::string marker = prefix + std::to_string(n) + kPosParamSuffix;
        for (size_t pos = 0;
             (pos = sql.find(marker, pos)) != std::string::npos;) {
            sql.replace(pos, marker.size(), "?");
            pos += 1;
        }
    }
}

// ── Transformer ─────────────────────────────────────────────────────

constexpr int kMaxNestingDepth = 200;

// XML emission flavour. JSX and JSONML are sqldeep transpiler macros
// — `jsx(<el/>)` / `jsonml(<el/>)` — that select alternative XML
// helper function names (xml_element_jsx, xml_attrs_jsx, jsx_agg vs.
// the plain xml_* family).
enum class XmlMode { Xml, Jsx, Jsonml };

class Transformer {
public:
    Transformer(arena_t *arena, Backend backend, const FkIndex *fk_index)
        : arena_(arena), backend_(backend), fk_index_(fk_index) {}

    // Mutate the AST in place. Returns the (possibly new) root node.
    LpNode *transform(LpNode *node) {
        build_alias_map(node);
        return walk(node, /*depth=*/0, XmlMode::Xml);
    }

private:
    arena_t      *arena_;
    Backend       backend_;
    const FkIndex *fk_index_;

    // alias → underlying table name, collected by a pre-pass over the
    // entire AST so a sqldeep join path like `c->orders o` can resolve
    // the leftmost name `c` (an alias from an enclosing FROM clause)
    // to its real table when building the start-correlation.
    std::map<std::string, std::string> alias_map_;

    // ── Alias-map prepass ─────────────────────────────────────────

    void build_alias_map(LpNode *node) {
        if (!node) return;
        switch (node->kind) {
            case LP_FROM_TABLE:
                if (node->u.from_table.name) {
                    /* Use alias if given, else map the table to itself
                     * so unqualified table names also resolve. */
                    const char *key = node->u.from_table.alias
                                       ? node->u.from_table.alias
                                       : node->u.from_table.name;
                    alias_map_[key] = node->u.from_table.name;
                }
                break;
            case LP_SQLDEEP_JOIN_PATH:
                for (int i = 0; i < node->u.sqldeep_join_path.steps.count; i++) {
                    LpNode *s = node->u.sqldeep_join_path.steps.items[i];
                    if (!s) continue;
                    const auto& ss = s->u.sqldeep_join_step;
                    if (ss.table) {
                        const char *key = ss.alias ? ss.alias : ss.table;
                        alias_map_[key] = ss.table;
                    }
                }
                build_alias_map(node->u.sqldeep_join_path.prefix);
                break;
            default:
                break;
        }
        // Recurse into all child slots that can contain FROM clauses
        // or further sub-selects.
        walk_for_aliases(node);
    }

    void walk_for_aliases(LpNode *node) {
        switch (node->kind) {
            case LP_STMT_SELECT:
                build_alias_map(node->u.select.from);
                for (int i = 0; i < node->u.select.result_columns.count; i++)
                    build_alias_map(node->u.select.result_columns.items[i]);
                for (int i = 0; i < node->u.select.group_by.count; i++)
                    build_alias_map(node->u.select.group_by.items[i]);
                build_alias_map(node->u.select.where);
                build_alias_map(node->u.select.having);
                for (int i = 0; i < node->u.select.order_by.count; i++)
                    build_alias_map(node->u.select.order_by.items[i]);
                build_alias_map(node->u.select.limit);
                build_alias_map(node->u.select.with);
                break;
            case LP_COMPOUND_SELECT:
                build_alias_map(node->u.compound.left);
                build_alias_map(node->u.compound.right);
                break;
            case LP_RESULT_COLUMN:
                build_alias_map(node->u.result_column.expr);
                break;
            case LP_JOIN_CLAUSE:
                build_alias_map(node->u.join.left);
                build_alias_map(node->u.join.right);
                build_alias_map(node->u.join.on_expr);
                break;
            case LP_FROM_SUBQUERY:
                build_alias_map(node->u.from_subquery.select);
                break;
            case LP_EXPR_SUBQUERY:
                build_alias_map(node->u.subquery.select);
                break;
            case LP_EXPR_FUNCTION:
                for (int i = 0; i < node->u.function.args.count; i++)
                    build_alias_map(node->u.function.args.items[i]);
                break;
            case LP_EXPR_SQLDEEP_OBJECT:
                for (int i = 0; i < node->u.sqldeep_object.fields.count; i++)
                    build_alias_map(node->u.sqldeep_object.fields.items[i]);
                break;
            case LP_SQLDEEP_FIELD:
                build_alias_map(node->u.sqldeep_field.value);
                break;
            case LP_EXPR_SQLDEEP_ARRAY:
                for (int i = 0; i < node->u.sqldeep_array.elements.count; i++)
                    build_alias_map(node->u.sqldeep_array.elements.items[i]);
                break;
            case LP_EXPR_SQLDEEP_XML:
                for (int i = 0; i < node->u.sqldeep_xml.children.count; i++)
                    build_alias_map(node->u.sqldeep_xml.children.items[i]);
                for (int i = 0; i < node->u.sqldeep_xml.attrs.count; i++) {
                    LpNode *a = node->u.sqldeep_xml.attrs.items[i];
                    if (a) build_alias_map(a->u.sqldeep_xml_attr.value);
                }
                break;
            case LP_WITH:
                for (int i = 0; i < node->u.with.ctes.count; i++)
                    build_alias_map(node->u.with.ctes.items[i]);
                break;
            case LP_CTE:
                build_alias_map(node->u.cte.select);
                break;
            case LP_STMT_CREATE_VIEW:
                build_alias_map(node->u.create_view.select);
                break;
            default:
                break;
        }
    }

    const std::string& resolve_alias(const std::string& alias) {
        auto it = alias_map_.find(alias);
        return (it != alias_map_.end()) ? it->second : alias;
    }

    // Dialect function names ----------------------------------------

    const char *fn_object() const {
        switch (backend_) {
            case Backend::postgres:       return "jsonb_build_object";
            case Backend::sqlite_vanilla: return "json_object";
            default:                      return "sqldeep_json_object";
        }
    }
    const char *fn_array() const {
        switch (backend_) {
            case Backend::postgres:       return "jsonb_build_array";
            case Backend::sqlite_vanilla: return "json_array";
            default:                      return "sqldeep_json_array";
        }
    }
    const char *fn_group_array() const {
        switch (backend_) {
            case Backend::postgres:       return "jsonb_agg";
            case Backend::sqlite_vanilla: return "json_group_array";
            default:                      return "sqldeep_json_group_array";
        }
    }
    // BLOB-protocol wrapper used to inject a typed JSON value into a
    // JSON-building call so booleans (and only booleans, currently)
    // round-trip as `true` / `false` rather than `1` / `0`. Postgres
    // jsonb already has a native bool, so no wrapper is needed there.
    const char *fn_json_blob() const {
        switch (backend_) {
            case Backend::postgres:       return nullptr;
            case Backend::sqlite_vanilla: return "json";
            default:                      return "sqldeep_json";
        }
    }

    // Detect a bare `true` / `false` literal used as a value. SQLite's
    // grammar doesn't have boolean keywords — `true`/`false` parse as
    // identifier column refs (with no table qualifier). Returns the
    // canonical lower-case form, or NULL if `expr` isn't one of those.
    static const char *bool_literal_text(LpNode *expr) {
        if (!expr) return nullptr;
        const char *name = nullptr;
        if (expr->kind == LP_EXPR_LITERAL_BOOL) {
            name = expr->u.literal.value;
        } else if (expr->kind == LP_EXPR_COLUMN_REF
                && !expr->u.column_ref.schema
                && !expr->u.column_ref.table) {
            name = expr->u.column_ref.column;
        }
        if (!name) return nullptr;
        if ((name[0] == 't' || name[0] == 'T')
            && (name[1] == 'r' || name[1] == 'R')
            && (name[2] == 'u' || name[2] == 'U')
            && (name[3] == 'e' || name[3] == 'E')
            && name[4] == '\0')
            return "true";
        if ((name[0] == 'f' || name[0] == 'F')
            && (name[1] == 'a' || name[1] == 'A')
            && (name[2] == 'l' || name[2] == 'L')
            && (name[3] == 's' || name[3] == 'S')
            && (name[4] == 'e' || name[4] == 'E')
            && name[5] == '\0')
            return "false";
        return nullptr;
    }

    // Wrap a bare `true` / `false` literal in fn_json('true') /
    // fn_json('false') when it appears in a JSON value slot — object
    // field value, array element, or (later) XML attribute value.
    // No wrap in Postgres mode (jsonb has native bool).
    LpNode *wrap_json_bool(LpNode *expr) {
        const char *lit = bool_literal_text(expr);
        if (!lit) return expr;
        const char *fn = fn_json_blob();
        if (!fn) return expr;
        return make_function(arena_, fn, {make_string_lit(arena_, lit)});
    }

    // ── Walker ────────────────────────────────────────────────────
    //
    // Visit every node in post-order: children first, then the node
    // itself. By the time we rewrite a sqldeep node, its children are
    // already plain-SQL AST.

    LpNode *walk(LpNode *node, int depth, XmlMode mode) {
        if (!node) return nullptr;
        if (depth > kMaxNestingDepth)
            throw Error("maximum nesting depth exceeded", 0, 0);

        // Recursive SELECT (sqldeep_recurse) is handled pre-order:
        // the whole statement is rewritten into a WITH RECURSIVE
        // 3-CTE construction so we don't want the post-order walk
        // to start rewriting the object literal projection (its
        // recursive-children marker still needs reading).
        if (node->kind == LP_STMT_SELECT && node->u.select.sqldeep_recurse) {
            return rewrite_recursive_select(node);
        }

        // jsx(<el/>) / jsonml(<el/>) transpiler-macro wrapper: absorb
        // the outer function call and switch the inner XML element's
        // emission mode. Detected pre-recursion so the mode propagates
        // down through nested XML children.
        if (node->kind == LP_EXPR_FUNCTION
            && node->u.function.name
            && node->u.function.args.count == 1
            && node->u.function.args.items[0]
            && node->u.function.args.items[0]->kind == LP_EXPR_SQLDEEP_XML) {
            XmlMode m = XmlMode::Xml;
            const char *fn = node->u.function.name;
            if (std::strcmp(fn, "jsx") == 0)        m = XmlMode::Jsx;
            else if (std::strcmp(fn, "jsonml") == 0) m = XmlMode::Jsonml;
            if (m != XmlMode::Xml) {
                LpNode *xml = node->u.function.args.items[0];
                walk_xml_children(xml, depth + 1, m);
                return rewrite_xml(xml, m);
            }
        }

        walk_children(node, depth + 1, mode);

        switch (node->kind) {
            case LP_EXPR_SQLDEEP_OBJECT:    return rewrite_object(node);
            case LP_EXPR_SQLDEEP_ARRAY:     return rewrite_array(node);
            case LP_EXPR_SQLDEEP_JSON_PATH: return rewrite_json_path(node);
            case LP_EXPR_SQLDEEP_XML:       return rewrite_xml(node, mode);
            case LP_STMT_SELECT:            return rewrite_select(node);
            default:                        return node;
        }
    }

    // Recurse into every child slot that can contain an LpNode or an
    // LpNodeList. This is the bulk of the walker — every node kind
    // that can contain an expression or statement child must list
    // those children here. Anything that's a leaf (literals, naked
    // column refs, identifiers) has nothing to do.

    void walk_children(LpNode *node, int depth, XmlMode mode) {
        switch (node->kind) {
            case LP_STMT_SELECT:
                walk_list(&node->u.select.result_columns, depth, mode);
                node->u.select.from   = walk(node->u.select.from, depth, mode);
                node->u.select.where  = walk(node->u.select.where, depth, mode);
                walk_list(&node->u.select.group_by, depth, mode);
                node->u.select.having = walk(node->u.select.having, depth, mode);
                walk_list(&node->u.select.order_by, depth, mode);
                node->u.select.limit  = walk(node->u.select.limit, depth, mode);
                walk_list(&node->u.select.window_defs, depth, mode);
                node->u.select.with   = walk(node->u.select.with, depth, mode);
                break;
            case LP_COMPOUND_SELECT:
                node->u.compound.left  = walk(node->u.compound.left, depth, mode);
                node->u.compound.right = walk(node->u.compound.right, depth, mode);
                break;
            case LP_RESULT_COLUMN:
                node->u.result_column.expr =
                    walk(node->u.result_column.expr, depth, mode);
                break;
            case LP_EXPR_BINARY_OP:
                node->u.binary.left  = walk(node->u.binary.left, depth, mode);
                node->u.binary.right = walk(node->u.binary.right, depth, mode);
                break;
            case LP_EXPR_UNARY_OP:
                node->u.unary.operand = walk(node->u.unary.operand, depth, mode);
                break;
            case LP_EXPR_FUNCTION:
                walk_list(&node->u.function.args, depth, mode);
                walk_list(&node->u.function.order_by, depth, mode);
                node->u.function.filter = walk(node->u.function.filter, depth, mode);
                node->u.function.over   = walk(node->u.function.over, depth, mode);
                break;
            case LP_EXPR_CAST:
                node->u.cast.expr = walk(node->u.cast.expr, depth, mode);
                break;
            case LP_EXPR_COLLATE:
                node->u.collate.expr = walk(node->u.collate.expr, depth, mode);
                break;
            case LP_EXPR_BETWEEN:
                node->u.between.expr = walk(node->u.between.expr, depth, mode);
                node->u.between.low  = walk(node->u.between.low, depth, mode);
                node->u.between.high = walk(node->u.between.high, depth, mode);
                break;
            case LP_EXPR_IN:
                node->u.in.expr   = walk(node->u.in.expr, depth, mode);
                node->u.in.select = walk(node->u.in.select, depth, mode);
                walk_list(&node->u.in.values, depth, mode);
                break;
            case LP_EXPR_EXISTS:
                node->u.exists.select = walk(node->u.exists.select, depth, mode);
                break;
            case LP_EXPR_SUBQUERY:
                node->u.subquery.select = walk(node->u.subquery.select, depth, mode);
                break;
            case LP_EXPR_CASE:
                node->u.case_.operand = walk(node->u.case_.operand, depth, mode);
                walk_list(&node->u.case_.when_exprs, depth, mode);
                node->u.case_.else_expr = walk(node->u.case_.else_expr, depth, mode);
                break;
            case LP_FROM_SUBQUERY:
                node->u.from_subquery.select =
                    walk(node->u.from_subquery.select, depth, mode);
                break;
            case LP_JOIN_CLAUSE:
                node->u.join.left    = walk(node->u.join.left, depth, mode);
                node->u.join.right   = walk(node->u.join.right, depth, mode);
                node->u.join.on_expr = walk(node->u.join.on_expr, depth, mode);
                break;
            case LP_ORDER_TERM:
                node->u.order_term.expr =
                    walk(node->u.order_term.expr, depth, mode);
                break;
            case LP_LIMIT:
                node->u.limit.count  = walk(node->u.limit.count, depth, mode);
                node->u.limit.offset = walk(node->u.limit.offset, depth, mode);
                break;
            case LP_EXPR_SQLDEEP_OBJECT:
                walk_list(&node->u.sqldeep_object.fields, depth, mode);
                break;
            case LP_SQLDEEP_FIELD:
                node->u.sqldeep_field.key_expr =
                    walk(node->u.sqldeep_field.key_expr, depth, mode);
                node->u.sqldeep_field.value =
                    walk(node->u.sqldeep_field.value, depth, mode);
                break;
            case LP_EXPR_SQLDEEP_ARRAY:
                walk_list(&node->u.sqldeep_array.elements, depth, mode);
                break;
            case LP_EXPR_SQLDEEP_JSON_PATH:
                node->u.sqldeep_json_path.base =
                    walk(node->u.sqldeep_json_path.base, depth, mode);
                break;
            case LP_EXPR_SQLDEEP_XML:
                walk_xml_children(node, depth, mode);
                break;
            case LP_STMT_CREATE_VIEW:
                node->u.create_view.select =
                    walk(node->u.create_view.select, depth, mode);
                break;
            case LP_STMT_INSERT:
                node->u.insert.source = walk(node->u.insert.source, depth, mode);
                node->u.insert.upsert = walk(node->u.insert.upsert, depth, mode);
                walk_list(&node->u.insert.returning, depth, mode);
                break;
            case LP_STMT_UPDATE:
                walk_list(&node->u.update.set_clauses, depth, mode);
                node->u.update.from   = walk(node->u.update.from, depth, mode);
                node->u.update.where  = walk(node->u.update.where, depth, mode);
                walk_list(&node->u.update.order_by, depth, mode);
                node->u.update.limit  = walk(node->u.update.limit, depth, mode);
                walk_list(&node->u.update.returning, depth, mode);
                break;
            case LP_STMT_DELETE:
                node->u.del.where = walk(node->u.del.where, depth, mode);
                walk_list(&node->u.del.order_by, depth, mode);
                node->u.del.limit = walk(node->u.del.limit, depth, mode);
                walk_list(&node->u.del.returning, depth, mode);
                break;
            case LP_WITH:
                walk_list(&node->u.with.ctes, depth, mode);
                break;
            case LP_CTE:
                node->u.cte.select = walk(node->u.cte.select, depth, mode);
                break;
            default:
                break;  // leaves and not-yet-handled cases
        }
    }

    void walk_list(LpNodeList *list, int depth, XmlMode mode) {
        if (!list) return;
        for (int i = 0; i < list->count; i++)
            list->items[i] = walk(list->items[i], depth, mode);
    }

    // XML elements propagate the active mode through nested attributes
    // and children so jsx(<ul><li/></ul>) emits xml_element_jsx for
    // both the outer ul and the inner li.
    void walk_xml_children(LpNode *node, int depth, XmlMode mode) {
        auto& x = node->u.sqldeep_xml;
        for (int i = 0; i < x.attrs.count; i++) {
            LpNode *a = x.attrs.items[i];
            if (!a) continue;
            a->u.sqldeep_xml_attr.value =
                walk(a->u.sqldeep_xml_attr.value, depth, mode);
        }
        for (int i = 0; i < x.children.count; i++)
            x.children.items[i] = walk(x.children.items[i], depth, mode);
    }

    // ── Rewrites ─────────────────────────────────────────────────

    // Detect the "aggregate field" form: a sqldeep field whose value
    // is a SELECT with no FROM clause, exactly one result column, and
    // no other clauses. In sqldeep, `{field: SELECT expr}` (no FROM)
    // means "aggregate `expr` over the current GROUP BY scope" and
    // becomes 'field', fn_group_array(expr) — or just 'field', expr
    // when singular (SELECT/1).
    //
    // The grammar wraps the bare SELECT in LP_EXPR_SUBQUERY; we unwrap
    // it back to the right expression here.
    LpNode *maybe_aggregate_field_value(LpNode *v) {
        if (!v || v->kind != LP_EXPR_SUBQUERY) return v;
        LpNode *sel = v->u.subquery.select;
        if (!sel || sel->kind != LP_STMT_SELECT) return v;
        const auto& s = sel->u.select;
        if (s.from || s.where || s.having || s.with) return v;
        if (s.group_by.count || s.order_by.count || s.window_defs.count) return v;
        if (s.result_columns.count != 1) return v;
        LpNode *rc = s.result_columns.items[0];
        LpNode *expr = (rc && rc->kind == LP_RESULT_COLUMN)
                          ? rc->u.result_column.expr : rc;
        if (!expr) return v;
        // LIMIT 1 (from SELECT/1) → just the bare expr.
        if (s.limit) return expr;
        return make_function(arena_, fn_group_array(), {expr});
    }

    // { a, key: expr, "k": v, (e): v, a.b } →
    //   fn_object('a', a, 'key', expr, 'k', v, e, v, 'b', a.b)
    // Literal `true` / `false` values are wrapped via sqldeep_json('...')
    // so they serialize as JSON bools rather than integers (sqlite/vanilla).
    // Aggregate field form `field: SELECT expr` collapses to
    // 'field', fn_group_array(expr).
    LpNode *rewrite_object(LpNode *node) {
        std::vector<LpNode*> args;
        const auto& fields = node->u.sqldeep_object.fields;
        for (int i = 0; i < fields.count; i++) {
            LpNode *f = fields.items[i];
            if (!f) continue;
            const auto& sf = f->u.sqldeep_field;
            switch (sf.key_form) {
                case 0: { // bare
                    args.push_back(make_string_lit(arena_, sf.key_text));
                    args.push_back(make_column_ref(arena_, sf.key_text));
                    break;
                }
                case 1:  // named id : expr
                case 2:  // "string" : expr
                case 5: { // qualified  a.b
                    LpNode *v = maybe_aggregate_field_value(sf.value);
                    args.push_back(make_string_lit(arena_, sf.key_text));
                    args.push_back(wrap_json_bool(v));
                    break;
                }
                case 3: {  // (expr) : val
                    LpNode *v = maybe_aggregate_field_value(sf.value);
                    args.push_back(sf.key_expr);
                    args.push_back(wrap_json_bool(v));
                    break;
                }
                case 4:  // recursive children
                    // `children: *` only has meaning inside a SELECT
                    // that has a RECURSE clause — when we get here in
                    // the post-order walk, the recursive-SELECT
                    // pre-handler already short-circuited that case.
                    // Reaching this branch means the recursive field
                    // appeared without RECURSE; surface as an error.
                    throw Error("`*` recursive child field requires "
                                "a RECURSE clause on the SELECT", 0, 0);
                default:
                    break;
            }
        }
        node->kind = LP_EXPR_FUNCTION;
        std::memset(&node->u, 0, sizeof(node->u));
        node->u.function.name = arena_strdup(arena_, fn_object());
        for (auto *a : args) list_append(arena_, &node->u.function.args, a);
        return node;
    }

    // [ e1, e2, ... ] → fn_array(e1, e2, ...) with bool wrapping.
    LpNode *rewrite_array(LpNode *node) {
        LpNodeList elements = node->u.sqldeep_array.elements;
        node->kind = LP_EXPR_FUNCTION;
        std::memset(&node->u, 0, sizeof(node->u));
        node->u.function.name = arena_strdup(arena_, fn_array());
        for (int i = 0; i < elements.count; i++)
            list_append(arena_, &node->u.function.args,
                        wrap_json_bool(elements.items[i]));
        return node;
    }

    // (base).a.b[0] →
    //   SQLite/Vanilla: json_extract(CAST((base) AS TEXT), '$.a.b[0]')
    //   Postgres:       jsonb_extract_path(base, 'a', 'b', '0')
    LpNode *rewrite_json_path(LpNode *node) {
        LpNode *base = node->u.sqldeep_json_path.base;
        LpNodeList segs = node->u.sqldeep_json_path.segments;

        if (backend_ == Backend::postgres) {
            std::vector<LpNode*> args;
            args.push_back(base);
            for (int i = 0; i < segs.count; i++) {
                LpNode *seg = segs.items[i];
                if (!seg) continue;
                args.push_back(make_string_lit(arena_,
                    seg->u.literal.value ? seg->u.literal.value : ""));
            }
            node->kind = LP_EXPR_FUNCTION;
            std::memset(&node->u, 0, sizeof(node->u));
            node->u.function.name = arena_strdup(arena_, "jsonb_extract_path");
            for (auto *a : args) list_append(arena_, &node->u.function.args, a);
            return node;
        }

        // Build "$.a.b[0]" path string.
        std::string path = "$";
        for (int i = 0; i < segs.count; i++) {
            LpNode *seg = segs.items[i];
            if (!seg) continue;
            const char *v = seg->u.literal.value ? seg->u.literal.value : "";
            if (seg->kind == LP_EXPR_LITERAL_INT) {
                path += "[";
                path += v;
                path += "]";
            } else {
                path += ".";
                path += v;
            }
        }

        // Wrap base in a 1-element vector so the canonical unparser
        // emits `(base)`. The parens preserve the visual disambiguation
        // (matches sqldeep's pre-existing renderer) and avoid any
        // operator-precedence surprises inside the CAST argument.
        LpNode *parens = new_node(arena_, LP_EXPR_VECTOR);
        list_append(arena_, &parens->u.vector.values, base);
        LpNode *cast = make_cast(arena_, parens, "TEXT");
        LpNode *path_lit = make_string_lit(arena_, path);

        node->kind = LP_EXPR_FUNCTION;
        std::memset(&node->u, 0, sizeof(node->u));
        node->u.function.name = arena_strdup(arena_, "json_extract");
        list_append(arena_, &node->u.function.args, cast);
        list_append(arena_, &node->u.function.args, path_lit);
        return node;
    }

    // Multi-line XML text dedent: scan immediate text children for
    // the common leading-whitespace prefix on each line after a '\n'.
    // Blank-interior lines (only whitespace between two newlines) are
    // skipped from the indent calculation but still trimmed on output.
    int xml_min_indent(LpNode *node) {
        int min_indent = INT_MAX;
        const auto& x = node->u.sqldeep_xml;
        for (int j = 0; j < x.children.count; j++) {
            LpNode *c = x.children.items[j];
            if (!c || c->kind != LP_SQLDEEP_XML_TEXT) continue;
            const char *text = c->u.sqldeep_xml_text.text;
            if (!text) continue;
            size_t i = 0, n = std::strlen(text);
            while (i < n) {
                const char *nl = (const char *)std::memchr(text + i, '\n', n - i);
                if (!nl) break;
                size_t ls = (nl - text) + 1;
                int sp = 0;
                while (ls + sp < n && text[ls + sp] == ' ') ++sp;
                // Skip only fully-blank interior lines (whitespace
                // between two newlines). Lines whose only "content"
                // is whitespace before a child element or closing tag
                // (the text-end case) still carry meaningful indent.
                if (ls + sp < n && text[ls + sp] == '\n') {
                    i = ls; continue;
                }
                if (sp < min_indent) min_indent = sp;
                i = ls + sp + 1;
            }
        }
        return min_indent == INT_MAX ? 0 : min_indent;
    }

    // Apply dedent: drop `indent` spaces immediately after every '\n'
    // in `text`. Returns a new arena-owned string.
    char *xml_dedent_text(const char *text, int indent) {
        if (!text || indent <= 0)
            return arena_strdup(arena_, text ? text : "");
        size_t n = std::strlen(text);
        std::string out;
        out.reserve(n);
        for (size_t i = 0; i < n; ) {
            char c = text[i++];
            out += c;
            if (c == '\n') {
                int dropped = 0;
                while (dropped < indent && i < n && text[i] == ' ') {
                    i++; dropped++;
                }
            }
        }
        return arena_strdup(arena_, out.c_str());
    }

    // <tag attrs>body</tag> →
    //   xml_element('tag', xml_attrs(...), child1, child2, ...)
    // Self-closing <tag/> uses 'tag/' as the literal string so the
    // runtime function knows to emit the void-element form.
    // Mode (XML / Jsonml / Jsx) selects the function family.
    LpNode *rewrite_xml(LpNode *node, XmlMode mode) {
        const auto& x = node->u.sqldeep_xml;
        const char *fn_el, *fn_attrs;
        switch (mode) {
            case XmlMode::Jsx:
                fn_el = "xml_element_jsx";
                fn_attrs = "xml_attrs_jsx";
                break;
            case XmlMode::Jsonml:
                fn_el = "xml_element_jsonml";
                fn_attrs = "xml_attrs_jsonml";
                break;
            default:
                fn_el = "xml_element";
                fn_attrs = "xml_attrs";
                break;
        }

        std::vector<LpNode*> args;

        // tag: bare for non-self-closing, with trailing "/" marker
        // for self-closing so the runtime emits <tag/> form.
        std::string tag = x.tag ? x.tag : "";
        if (x.self_closing) tag += "/";
        args.push_back(make_string_lit(arena_, tag));

        // attrs: xml_attrs('name', value, ...). Boolean attributes
        // (no `=value`) become sqldeep_json('true') wrappers via the
        // BLOB protocol so the runtime distinguishes them from
        // attr="1" / attr="true" string values.
        if (x.attrs.count > 0) {
            std::vector<LpNode*> attr_args;
            for (int i = 0; i < x.attrs.count; i++) {
                LpNode *a = x.attrs.items[i];
                if (!a) continue;
                const auto& av = a->u.sqldeep_xml_attr;
                attr_args.push_back(make_string_lit(arena_, av.name));
                if (av.value) {
                    if (av.dynamic) {
                        attr_args.push_back(wrap_json_bool(av.value));
                    } else {
                        attr_args.push_back(av.value);
                    }
                } else {
                    // Boolean attribute: <input disabled/>
                    const char *fn = fn_json_blob();
                    if (fn) {
                        attr_args.push_back(make_function(
                            arena_, fn,
                            {make_string_lit(arena_, "true")}));
                    } else {
                        attr_args.push_back(make_string_lit(arena_, "true"));
                    }
                }
            }
            args.push_back(make_function(arena_, fn_attrs, attr_args));
        }

        // Multi-line dedent: scan all direct-text children for the
        // common leading-whitespace indent, then strip that indent
        // from each line's start. Source indentation produces the
        // relative indentation in the rendered output.
        int indent = xml_min_indent(node);

        // children: text → string literal (dedented); nested element
        // → recurse (already rewritten in post-order); anything else
        // is an interpolation expression, with bool wrap applied.
        for (int i = 0; i < x.children.count; i++) {
            LpNode *c = x.children.items[i];
            if (!c) continue;
            if (c->kind == LP_SQLDEEP_XML_TEXT) {
                const char *raw = c->u.sqldeep_xml_text.text;
                char *dedented = xml_dedent_text(raw, indent);
                args.push_back(make_string_lit(arena_,
                    dedented ? std::string(dedented) : std::string("")));
            } else {
                args.push_back(wrap_json_bool(c));
            }
        }

        node->kind = LP_EXPR_FUNCTION;
        std::memset(&node->u, 0, sizeof(node->u));
        node->u.function.name = arena_strdup(arena_, fn_el);
        for (auto *a : args) list_append(arena_, &node->u.function.args, a);
        return node;
    }

    // ── Recursive SELECT rewrite ──────────────────────────────────
    //
    // Expands
    //   SELECT { id, name, children: * } FROM t RECURSE ON (fk [= pk]) WHERE ...
    // into the 3-CTE bracket-injection template documented in
    // sqldeep's CLAUDE.md (DFS traversal, per-node JSON object, then
    // event fragments concatenated to form one nested JSON string).
    //
    // Because the WITH RECURSIVE shape is large and well-defined, we
    // build it as SQL text and re-parse via deepparser to obtain the
    // standard SQL AST. The transformer then returns the new AST in
    // place of the original SELECT.

    LpNode *rewrite_recursive_select(LpNode *node) {
        const auto& sel = node->u.select;
        LpNode *recurse = sel.sqldeep_recurse;
        if (!recurse) return node;

        std::string fk_col = recurse->u.sqldeep_recurse.fk_col
                                ? recurse->u.sqldeep_recurse.fk_col : "";
        std::string pk_col = recurse->u.sqldeep_recurse.pk_col
                                ? recurse->u.sqldeep_recurse.pk_col : "id";

        // The FROM target must be a plain LP_FROM_TABLE.
        if (!sel.from || sel.from->kind != LP_FROM_TABLE) {
            throw Error("RECURSE requires a single FROM table", 0, 0);
        }
        std::string table = sel.from->u.from_table.name
                              ? sel.from->u.from_table.name : "";

        // Projection must be a sqldeep object literal with a recursive
        // children field. Extract field info.
        if (sel.result_columns.count != 1) {
            throw Error("RECURSE requires a single object projection", 0, 0);
        }
        LpNode *rc = sel.result_columns.items[0];
        LpNode *proj = (rc && rc->kind == LP_RESULT_COLUMN)
                          ? rc->u.result_column.expr : rc;
        if (!proj || proj->kind != LP_EXPR_SQLDEEP_OBJECT) {
            throw Error("RECURSE requires a sqldeep object projection",
                        0, 0);
        }

        std::string children_field;
        std::vector<std::string> field_keys;   // column-name used in CTE
        std::vector<std::string> obj_pairs;    // "'key', expr" for json_object
        for (int i = 0; i < proj->u.sqldeep_object.fields.count; i++) {
            LpNode *f = proj->u.sqldeep_object.fields.items[i];
            if (!f) continue;
            const auto& sf = f->u.sqldeep_field;
            if (sf.key_form == 4) {           // recursive children marker
                children_field = sf.key_text ? sf.key_text : "children";
                continue;
            }
            // Only bare and qualified-bare are supported here — those
            // are the forms that map cleanly to "include this column
            // in the DFS CTE column list".
            std::string col = sf.key_text ? sf.key_text : "";
            field_keys.push_back(col);
            obj_pairs.push_back("'" + sql_escape_lit(col) + "', " + col);
        }
        if (children_field.empty()) {
            throw Error("RECURSE requires a `children: *` field in the "
                        "projection", 0, 0);
        }

        // Root condition (the SELECT's WHERE clause); we emit it back
        // into the anchor leg of the recursive CTE. The canonical
        // unparser produces the SQL text.
        std::string root_where;
        if (sel.where) {
            char *w = lp_ast_to_sql(sel.where, transient_arena());
            if (w) root_where = w;
        }

        bool singular = !!sel.sqldeep_singular;
        bool is_pg = (backend_ == Backend::postgres);

        // Build column list. The CTE always includes fk_col; pk_col
        // is added separately when it differs from fk_col and isn't
        // already in the field list.
        std::string col_list;
        std::string col_select;  // "c.col1, c.col2, ..." for recursive step
        for (size_t i = 0; i < field_keys.size(); i++) {
            if (i > 0) { col_list += ", "; col_select += ", "; }
            col_list += field_keys[i];
            col_select += "c." + field_keys[i];
        }
        if (!field_keys.empty()) { col_list += ", "; col_select += ", "; }
        col_list += fk_col;
        col_select += "c." + fk_col;
        bool pk_in_fields = false;
        for (const auto& f : field_keys)
            if (f == pk_col) { pk_in_fields = true; break; }
        if (pk_col != fk_col && !pk_in_fields) {
            col_list += ", " + pk_col;
            col_select += ", c." + pk_col;
        }

        std::string pad   = is_pg
            ? "lpad(CAST(" + pk_col + " AS text), 10, '0')"
            : "printf('%010d', " + pk_col + ")";
        std::string c_pad = is_pg
            ? "lpad(CAST(c." + pk_col + " AS text), 10, '0')"
            : "printf('%010d', c." + pk_col + ")";
        std::string concat_fn = is_pg
            ? "string_agg(_fragment, '' ORDER BY _sort_key)"
            : "group_concat(_fragment, '')";
        std::string high_char = is_pg ? "chr(127)" : "char(127)";

        // Build the obj_args for fn_object call.
        std::string obj_args;
        for (size_t i = 0; i < obj_pairs.size(); i++) {
            if (i > 0) obj_args += ", ";
            obj_args += obj_pairs[i];
        }

        std::string out;
        out += "WITH RECURSIVE _sdq_dfs(";
        out += col_list;
        out += ", _depth, _path) AS (SELECT ";
        out += col_list;
        out += ", 0, ";
        out += pad;
        out += " FROM ";
        out += table;
        if (!root_where.empty()) {
            out += " WHERE ";
            out += root_where;
        }
        out += " UNION ALL SELECT ";
        out += col_select;
        out += ", d._depth + 1, d._path || '/' || ";
        out += c_pad;
        out += " FROM ";
        out += table;
        out += " c JOIN _sdq_dfs d ON c.";
        out += fk_col;
        out += " = d.";
        out += pk_col;
        out += "), _sdq_ranked AS (SELECT *, ";
        out += fn_object();
        out += "(";
        out += obj_args;
        out += ") AS _obj, ROW_NUMBER() OVER (PARTITION BY ";
        out += fk_col;
        out += " ORDER BY ";
        out += pk_col;
        out += ") AS _child_rank FROM _sdq_dfs), ";
        out += "_sdq_events(_sort_key, _fragment) AS (SELECT _path, ";
        out += "CASE WHEN _child_rank > 1 THEN ',' ELSE '' END || ";
        out += "substr(_obj, 1, length(_obj) - 1) || ',\"";
        out += sql_escape_lit(children_field);
        out += "\":[' FROM _sdq_ranked UNION ALL SELECT _path || ";
        out += high_char;
        out += ", ']}' FROM _sdq_ranked) SELECT ";
        if (!singular) out += "'[' || ";
        out += concat_fn;
        if (!singular) out += " || ']'";
        out += " FROM (SELECT _fragment FROM _sdq_events ORDER BY _sort_key)";

        // Re-parse the constructed SQL via deepparser so we hand back
        // a standard SQL AST. (Re-using deepparser this way costs one
        // extra parse but spares us building a multi-CTE AST by hand.)
        const char *err = nullptr;
        LpNode *new_ast = lp_parse(out.c_str(), arena_, &err);
        if (!new_ast) {
            std::string msg = err ? err : "internal: recursive expansion failed";
            throw Error(msg, 0, 0);
        }
        return new_ast;
    }

    // Helper: escape single quotes in a string for a SQL string literal.
    static std::string sql_escape_lit(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '\'') out += "''";
            else out += c;
        }
        return out;
    }

    // The recursive-SELECT rewrite needs to emit the existing WHERE
    // clause as SQL text. The transient arena is just the regular
    // arena — it owns those strings for the lifetime of the parse.
    arena_t *transient_arena() { return arena_; }

    // ── Join path rewrite ─────────────────────────────────────────
    //
    // FROM c->orders o ON|USING ... -> ... AST representation:
    //   LP_SQLDEEP_JOIN_PATH { prefix, start_alias, steps[] }
    //
    // becomes:
    //   FROM step1.table [alias] JOIN step2.table [alias] ON ... ...
    //   WHERE step1 ↔ start  (added to the enclosing SELECT)

    struct JoinColumnPair {
        std::string child_col;
        std::string parent_col;
    };

    // Convention-based resolution: child has FK `<parent>_id`,
    // parent's PK is the same name. FK-guided mode looks up via
    // fk_index_; ambiguous or missing entries throw.
    std::vector<JoinColumnPair>
    resolve_columns(const std::string& child_table,
                     const std::string& parent_table) {
        if (!fk_index_) {
            return {{parent_table + "_id", parent_table + "_id"}};
        }
        auto it = fk_index_->find({child_table, parent_table});
        if (it == fk_index_->end() || it->second.empty()) {
            throw Error("no foreign key from '" + child_table + "' to '"
                        + parent_table + "'", 0, 0);
        }
        if (it->second.size() > 1) {
            throw Error("ambiguous foreign key from '" + child_table +
                        "' to '" + parent_table + "' (" +
                        std::to_string(it->second.size()) +
                        " candidates)", 0, 0);
        }
        std::vector<JoinColumnPair> out;
        for (const auto& cp : it->second[0]->columns)
            out.push_back({cp.from_column, cp.to_column});
        return out;
    }

    // Build a chain of LP_FROM_TABLE / LP_JOIN_CLAUSE for the path
    // and emit the start-correlation WHERE clause into *where_out.
    // Returns the from-chain node.
    LpNode *rewrite_join_path(LpNode *jp, LpNode **where_out) {
        const auto& path = jp->u.sqldeep_join_path;
        if (path.steps.count == 0) {
            *where_out = nullptr;
            return jp;
        }

        std::string start_alias = path.start_alias ? path.start_alias : "";
        // The leftmost name must refer to a table or alias already in
        // scope (from an outer FROM clause or another step). Unknown
        // names are sqldeep errors — there's no implicit "anything
        // goes" auto-join base.
        auto it = alias_map_.find(start_alias);
        if (it == alias_map_.end()) {
            throw Error("unknown join alias '" + start_alias + "'", 0, 0);
        }
        std::string start_table = it->second;

        // First step.
        LpNode *step1 = path.steps.items[0];
        const auto& s1 = step1->u.sqldeep_join_step;
        std::string s1_table = s1.table ? s1.table : "";
        std::string s1_alias = s1.alias ? s1.alias : "";
        std::string s1_ref   = s1_alias.empty() ? s1_table : s1_alias;

        // FROM target for the chain.
        LpNode *chain = make_from_table(arena_, s1_table, s1_alias);

        // WHERE correlation: step1 ↔ start.
        *where_out = build_join_condition(step1, start_alias, start_table,
                                           s1_ref, s1_table);

        std::string prev_ref   = s1_ref;
        std::string prev_table = s1_table;

        // Subsequent steps become JOIN ... ON ....
        for (int i = 1; i < path.steps.count; i++) {
            LpNode *step = path.steps.items[i];
            const auto& s = step->u.sqldeep_join_step;
            std::string s_table = s.table ? s.table : "";
            std::string s_alias = s.alias ? s.alias : "";
            std::string s_ref   = s_alias.empty() ? s_table : s_alias;

            LpNode *table_node = make_from_table(arena_, s_table, s_alias);
            LpNode *on_expr =
                build_join_condition(step, prev_ref, prev_table,
                                      s_ref, s_table);
            chain = make_join(arena_, chain, table_node, on_expr);

            prev_ref   = s_ref;
            prev_table = s_table;
        }

        return chain;
    }

    // Build the boolean expression connecting two endpoints of a
    // join-arrow step. `prev` is the left side of the arrow; `curr`
    // is the right side. forward (`->`) means curr is the child of
    // prev; reverse (`<-`) means prev is the child of curr.
    LpNode *build_join_condition(LpNode *step,
                                  const std::string& prev_ref,
                                  const std::string& prev_table,
                                  const std::string& curr_ref,
                                  const std::string& curr_table) {
        const auto& s = step->u.sqldeep_join_step;

        // Inline USING (cols): each col → curr.col = prev.col.
        if (s.using_cols.count > 0) {
            std::vector<LpNode*> parts;
            for (int i = 0; i < s.using_cols.count; i++) {
                LpNode *c = s.using_cols.items[i];
                if (!c) continue;
                const char *col = (c->kind == LP_EXPR_COLUMN_REF)
                                    ? c->u.column_ref.column
                                    : nullptr;
                if (!col) continue;
                parts.push_back(make_binop(arena_, LP_OP_EQ,
                    make_column_ref2(arena_, curr_ref, col),
                    make_column_ref2(arena_, prev_ref, col)));
            }
            return and_chain(arena_, parts);
        }

        // Inline ON expression.
        if (s.on_expr) {
            return rewrite_on_expr(s.on_expr, s.forward,
                                    prev_ref, curr_ref);
        }

        // Convention / FK-guided.
        std::string child_table  = s.forward ? curr_table : prev_table;
        std::string parent_table = s.forward ? prev_table : curr_table;
        auto cols = resolve_columns(child_table, parent_table);
        std::vector<LpNode*> parts;
        for (const auto& cp : cols) {
            if (s.forward) {
                // curr.child = prev.parent
                parts.push_back(make_binop(arena_, LP_OP_EQ,
                    make_column_ref2(arena_, curr_ref, cp.child_col),
                    make_column_ref2(arena_, prev_ref, cp.parent_col)));
            } else {
                // prev.child = curr.parent
                parts.push_back(make_binop(arena_, LP_OP_EQ,
                    make_column_ref2(arena_, prev_ref, cp.child_col),
                    make_column_ref2(arena_, curr_ref, cp.parent_col)));
            }
        }
        return and_chain(arena_, parts);
    }

    // Re-qualify the bare column refs in an inline ON expression
    // with the appropriate aliases. Handles:
    //   - single column ref → "curr.col = prev.col"
    //   - binary EQ "L = R" → emit "curr.R = prev.L" (forward) or
    //     "prev.R = curr.L" (reverse). Left side names the parent
    //     column, right side names the child column.
    //   - AND of EQs → recurse left/right, combine with AND.
    LpNode *rewrite_on_expr(LpNode *expr, int forward,
                             const std::string& prev_ref,
                             const std::string& curr_ref) {
        if (!expr) return nullptr;

        if (expr->kind == LP_EXPR_COLUMN_REF) {
            // Shorthand: same column name in both tables.
            const char *col = expr->u.column_ref.column;
            if (!col) return expr;
            // For forward (curr is child): curr.col = prev.col
            // For reverse (prev is child): prev.col = curr.col
            if (forward)
                return make_binop(arena_, LP_OP_EQ,
                    make_column_ref2(arena_, curr_ref, col),
                    make_column_ref2(arena_, prev_ref, col));
            else
                return make_binop(arena_, LP_OP_EQ,
                    make_column_ref2(arena_, prev_ref, col),
                    make_column_ref2(arena_, curr_ref, col));
        }

        if (expr->kind == LP_EXPR_BINARY_OP
            && expr->u.binary.op == LP_OP_AND) {
            LpNode *l = rewrite_on_expr(expr->u.binary.left, forward,
                                         prev_ref, curr_ref);
            LpNode *r = rewrite_on_expr(expr->u.binary.right, forward,
                                         prev_ref, curr_ref);
            return make_binop(arena_, LP_OP_AND, l, r);
        }

        if (expr->kind == LP_EXPR_BINARY_OP
            && expr->u.binary.op == LP_OP_EQ) {
            // ON L = R: L names the column on the LEFT side of the
            // arrow; R names the column on the RIGHT side. The arrow
            // direction (forward / reverse) determines which side is
            // the child and which is the parent, but the L→left,
            // R→right mapping is invariant.
            //   Forward  (c -> orders): prev=c=left, curr=orders=right
            //                           emit curr.R = prev.L
            //   Reverse  (o <- vendors): prev=o=left, curr=vendors=right
            //                            emit prev.L = curr.R
            LpNode *L = expr->u.binary.left;
            LpNode *R = expr->u.binary.right;
            const char *Lcol = (L && L->kind == LP_EXPR_COLUMN_REF)
                                  ? L->u.column_ref.column : nullptr;
            const char *Rcol = (R && R->kind == LP_EXPR_COLUMN_REF)
                                  ? R->u.column_ref.column : nullptr;
            if (Lcol && Rcol) {
                if (forward)
                    return make_binop(arena_, LP_OP_EQ,
                        make_column_ref2(arena_, curr_ref, Rcol),
                        make_column_ref2(arena_, prev_ref, Lcol));
                else
                    return make_binop(arena_, LP_OP_EQ,
                        make_column_ref2(arena_, prev_ref, Lcol),
                        make_column_ref2(arena_, curr_ref, Rcol));
            }
        }

        return expr;  // fallback: leave as-is
    }

    // SELECT-level handling: join path expansion, singular → LIMIT 1,
    // deep projection wrapping. The from_first flag is also cleared
    // here because canonical unparser emits standard SELECT-FROM order.
    LpNode *rewrite_select(LpNode *node) {
        node->u.select.sqldeep_from_first = 0;

        // Expand a sqldeep join path in the FROM clause into a
        // standard FROM_TABLE / JOIN_CLAUSE chain plus an AND-ed
        // start-correlation predicate added to the WHERE clause.
        if (node->u.select.from
            && node->u.select.from->kind == LP_SQLDEEP_JOIN_PATH) {
            LpNode *jp = node->u.select.from;
            LpNode *extra_where = nullptr;
            LpNode *chain = rewrite_join_path(jp, &extra_where);
            node->u.select.from = chain;
            if (extra_where) {
                node->u.select.where = node->u.select.where
                    ? make_binop(arena_, LP_OP_AND,
                                  extra_where, node->u.select.where)
                    : extra_where;
            }
        }

        bool was_singular = node->u.select.sqldeep_singular;

        // SELECT/1 → LIMIT 1 (unless a LIMIT is already specified).
        if (was_singular) {
            node->u.select.sqldeep_singular = 0;
            if (!node->u.select.limit) {
                node->u.select.limit = make_limit(arena_, 1);
            }
        }

        // SELECT/1 [single_elem] FROM t → SELECT single_elem FROM t LIMIT 1.
        // The single-element array literal already became fn_array(elem) in
        // the post-order walk; unwrap it back to bare `elem` when singular.
        if (was_singular
            && node->u.select.result_columns.count == 1) {
            LpNode *rc = node->u.select.result_columns.items[0];
            LpNode *proj = (rc && rc->kind == LP_RESULT_COLUMN)
                              ? rc->u.result_column.expr : rc;
            if (proj && proj->kind == LP_EXPR_FUNCTION
                && proj->u.function.name
                && std::strcmp(proj->u.function.name, fn_array()) == 0
                && proj->u.function.args.count == 1) {
                LpNode *elem = proj->u.function.args.items[0];
                if (rc && rc->kind == LP_RESULT_COLUMN)
                    rc->u.result_column.expr = elem;
                else
                    node->u.select.result_columns.items[0] = elem;
            }
        }

        // Deep-projection wrapping. The rules (mirroring sqldeep):
        //
        //   Array projection [...] — ALWAYS wraps in fn_group_array,
        //   regardless of nesting. Single-element arrays unwrap to
        //   the bare element first; multi-element wrap the whole
        //   fn_array(...) call.
        //
        //   Object projection {...} — wraps only when the SELECT is a
        //   value subquery in an "aggregating" context: parent is
        //   LP_EXPR_SUBQUERY whose parent is LP_SQLDEEP_FIELD or
        //   LP_EXPR_SQLDEEP_ARRAY or LP_EXPR_IN.
        //
        //   Singular (/1) — never wrap, no group_array. The singular
        //   array-element unwrap already happened above.
        //
        // Scalar-subquery contexts (function args, WHERE comparisons,
        // arithmetic, EXISTS, etc.) do NOT wrap.

        if (node->u.select.limit) return node;  // singular / explicit LIMIT
        if (node->u.select.result_columns.count != 1) return node;

        LpNode *rc = node->u.select.result_columns.items[0];
        LpNode *proj = (rc && rc->kind == LP_RESULT_COLUMN)
                          ? rc->u.result_column.expr : rc;
        if (!proj || proj->kind != LP_EXPR_FUNCTION) return node;
        const char *pname = proj->u.function.name;
        if (!pname) return node;

        bool is_obj = std::strcmp(pname, fn_object()) == 0;
        bool is_arr = std::strcmp(pname, fn_array()) == 0;
        bool is_xml = std::strcmp(pname, "xml_element") == 0
                    || std::strcmp(pname, "xml_element_jsx") == 0
                    || std::strcmp(pname, "xml_element_jsonml") == 0;
        if (!is_obj && !is_arr && !is_xml) return node;

        // Helper: set the projection back.
        auto replace_projection = [&](LpNode *new_expr) {
            if (rc && rc->kind == LP_RESULT_COLUMN)
                rc->u.result_column.expr = new_expr;
            else
                node->u.select.result_columns.items[0] = new_expr;
        };

        // XML projection in a value-subquery whose grandparent is an
        // XML element (i.e. <ul>{SELECT <li/> FROM t}</ul>) gets
        // wrapped in the corresponding {xml,jsx,jsonml}_agg helper so
        // rows aggregate into one XML fragment.
        if (is_xml) {
            LpNode *parent = node->parent;
            if (!parent || parent->kind != LP_EXPR_SUBQUERY) return node;
            LpNode *gp = parent->parent;
            if (!gp || gp->kind != LP_EXPR_SQLDEEP_XML) return node;
            const char *agg = "xml_agg";
            if (std::strcmp(pname, "xml_element_jsx") == 0)    agg = "jsx_agg";
            if (std::strcmp(pname, "xml_element_jsonml") == 0) agg = "jsonml_agg";
            replace_projection(make_function(arena_, agg, {proj}));
            return node;
        }

        if (is_obj) {
            // Object wrap fires when the SELECT is a value-subquery in
            // an aggregating sqldeep context (object field value, array
            // element, IN-list value). LP_EXPR_IN holds its inner
            // select directly without an LP_EXPR_SUBQUERY wrapper, so
            // both paths are checked.
            LpNode *parent = node->parent;
            if (!parent) return node;
            bool wrap = false;
            if (parent->kind == LP_EXPR_IN) {
                wrap = true;
            } else if (parent->kind == LP_EXPR_SUBQUERY) {
                LpNode *gp = parent->parent;
                if (gp && (gp->kind == LP_SQLDEEP_FIELD
                        || gp->kind == LP_EXPR_SQLDEEP_ARRAY
                        || gp->kind == LP_EXPR_IN)) {
                    wrap = true;
                }
            }
            if (!wrap) return node;
            replace_projection(make_function(arena_, fn_group_array(), {proj}));
            return node;
        }

        // Array projection: unwrap single-element; wrap in group_array.
        LpNode *inner = (proj->u.function.args.count == 1)
                          ? proj->u.function.args.items[0] : proj;
        replace_projection(make_function(arena_, fn_group_array(), {inner}));
        return node;
    }
};

// ── End-to-end pipeline ──────────────────────────────────────────────

std::string transpile_impl(const std::string& input,
                            const std::vector<ForeignKey>* fks,
                            Backend backend) {
    arena_t *arena = arena_create(64 * 1024);
    if (!arena) throw Error("out of memory", 0, 0);

    // Try to parse as a sequence of statements. If that fails, the
    // input may be a bare expression — sqldeep historically accepted
    // those (e.g. `<div/>`, `{a, b}`) directly. Wrap it as a one-
    // column SELECT, transform, then strip the SELECT framing so the
    // caller still sees just the expression.
    const char *parse_err = nullptr;
    LpNodeList *stmts = lp_parse_all(input.c_str(), arena, &parse_err);
    bool bare_expr = false;
    if (!stmts) {
        std::string wrapped = "SELECT " + input;
        const char *err2 = nullptr;
        stmts = lp_parse_all(wrapped.c_str(), arena, &err2);
        if (!stmts) {
            std::string msg = parse_err ? parse_err
                              : (err2 ? err2 : "parse error");
            // Deepparser formats errors as "LINE:COL: message"; parse
            // out the position so callers can highlight the source.
            int line = 0, col = 0;
            (void)std::sscanf(msg.c_str(), "%d:%d", &line, &col);
            arena_destroy(arena);
            throw Error(msg, line, col);
        }
        bare_expr = true;
    }

    // Rename "?" placeholders to ordered sentinels so we can verify the
    // transform preserves their order before handing SQL back (restored
    // to "?" after the check). See mark_positional_params.
    int pos_param_count = mark_positional_params(stmts, arena);

    FkIndex fk_index;
    if (fks) fk_index = build_fk_index(*fks);

    try {
        Transformer t(arena, backend, fks ? &fk_index : nullptr);
        for (int i = 0; i < stmts->count; i++) {
            stmts->items[i] = t.transform(stmts->items[i]);
            if (stmts->items[i]) lp_fix_parents(stmts->items[i]);
        }
    } catch (...) {
        arena_destroy(arena);
        throw;
    }

    std::string out;
    if (bare_expr && stmts->count == 1) {
        // Extract just the single result-column expression so the
        // caller sees the bare transformed form.
        LpNode *sel = stmts->items[0];
        if (sel && sel->kind == LP_STMT_SELECT
            && sel->u.select.result_columns.count == 1) {
            LpNode *rc = sel->u.select.result_columns.items[0];
            LpNode *expr = (rc && rc->kind == LP_RESULT_COLUMN)
                              ? rc->u.result_column.expr : rc;
            if (expr) {
                char *sql = lp_ast_to_sql(expr, arena);
                if (sql) out = sql;
            }
        }
    } else {
        for (int i = 0; i < stmts->count; i++) {
            if (i > 0) out += "; ";
            char *sql = lp_ast_to_sql(stmts->items[i], arena);
            if (sql) out += sql;
        }
    }

    arena_destroy(arena);

    // Verify "?" order survived the rewrite and restore the placeholders
    // (throws if a rewrite reordered them). The arena is already gone;
    // this works purely on the output string.
    restore_positional_params(out, pos_param_count);
    return out;
}

} // namespace

// ── Public C++ API ──────────────────────────────────────────────────

std::string transpile(const std::string& input) {
    return transpile_impl(input, nullptr, Backend::sqlite);
}

std::string transpile(const std::string& input,
                       const std::vector<ForeignKey>& fks) {
    return transpile_impl(input, &fks, Backend::sqlite);
}

std::string transpile(const std::string& input, Backend backend) {
    return transpile_impl(input, nullptr, backend);
}

std::string transpile(const std::string& input,
                       const std::vector<ForeignKey>& fks,
                       Backend backend) {
    return transpile_impl(input, &fks, backend);
}

} // namespace sqldeep

// ── C API bridge ────────────────────────────────────────────────────

namespace {

char *dup_str(const std::string& s) {
    char *p = static_cast<char*>(std::malloc(s.size() + 1));
    if (p) std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

void set_error(char** err_msg, int* err_line, int* err_col,
               const sqldeep::Error& e) {
    if (err_msg)  *err_msg = dup_str(e.what());
    if (err_line) *err_line = e.line();
    if (err_col)  *err_col = e.col();
}

void clear_error(char** err_msg, int* err_line, int* err_col) {
    if (err_msg)  *err_msg = nullptr;
    if (err_line) *err_line = 0;
    if (err_col)  *err_col = 0;
}

sqldeep::Backend to_backend(sqldeep_backend b) {
    switch (b) {
        case SQLDEEP_POSTGRES:       return sqldeep::Backend::postgres;
        case SQLDEEP_SQLITE_VANILLA: return sqldeep::Backend::sqlite_vanilla;
        default:                     return sqldeep::Backend::sqlite;
    }
}

std::vector<sqldeep::ForeignKey> to_cpp_fks(const sqldeep_foreign_key* fks,
                                              int fk_count) {
    std::vector<sqldeep::ForeignKey> cpp_fks;
    cpp_fks.reserve(fk_count);
    for (int i = 0; i < fk_count; ++i) {
        sqldeep::ForeignKey fk;
        fk.from_table = fks[i].from_table;
        fk.to_table   = fks[i].to_table;
        fk.columns.reserve(fks[i].column_count);
        for (int j = 0; j < fks[i].column_count; ++j) {
            fk.columns.push_back({
                fks[i].columns[j].from_column,
                fks[i].columns[j].to_column,
            });
        }
        cpp_fks.push_back(std::move(fk));
    }
    return cpp_fks;
}

} // namespace

extern "C" {

char* sqldeep_transpile(const char* input,
                        char** err_msg, int* err_line, int* err_col) {
    return sqldeep_transpile_backend(input, SQLDEEP_SQLITE,
                                      err_msg, err_line, err_col);
}

char* sqldeep_transpile_fk(const char* input,
                           const sqldeep_foreign_key* fks, int fk_count,
                           char** err_msg, int* err_line, int* err_col) {
    return sqldeep_transpile_fk_backend(input, SQLDEEP_SQLITE, fks, fk_count,
                                         err_msg, err_line, err_col);
}

char* sqldeep_transpile_backend(const char* input,
                                sqldeep_backend backend,
                                char** err_msg, int* err_line, int* err_col) {
    clear_error(err_msg, err_line, err_col);
    try {
        return dup_str(sqldeep::transpile(input, to_backend(backend)));
    } catch (const sqldeep::Error& e) {
        set_error(err_msg, err_line, err_col, e);
        return nullptr;
    }
}

char* sqldeep_transpile_fk_backend(const char* input,
                                   sqldeep_backend backend,
                                   const sqldeep_foreign_key* fks, int fk_count,
                                   char** err_msg, int* err_line, int* err_col) {
    clear_error(err_msg, err_line, err_col);
    try {
        auto cpp_fks = to_cpp_fks(fks, fk_count);
        return dup_str(sqldeep::transpile(input, cpp_fks, to_backend(backend)));
    } catch (const sqldeep::Error& e) {
        set_error(err_msg, err_line, err_col, e);
        return nullptr;
    }
}

const char* sqldeep_version(void) {
    return SQLDEEP_VERSION;
}

void sqldeep_free(void* ptr) {
    std::free(ptr);
}

} // extern "C"
