#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

typedef void (*Action)(const char *);

struct JsonValue {
    unsigned int type;
    unsigned int length;
    char data[40];
    JsonValue *child;
    Action action;
};

static JsonValue *g_model = nullptr;
static JsonValue *g_free_values = nullptr;
void *value_alloc() {
    if (g_free_values) {
        JsonValue *v = g_free_values;
        g_free_values = g_free_values->child;
        return v;
    }
    return malloc(sizeof(JsonValue));
}

void value_free(JsonValue *v) {
    if (!v) return;
    v->child = g_free_values;
    g_free_values = v;
}

void safe_echo(const char *s) {
    printf("[runtime] %s\n", s ? s : "");
}

extern "C" void launch_shell(const char *cmd) {
    if (!cmd || strncmp(cmd, "/bin/sh", 7) != 0) {
        puts("[runtime] invalid model action");
        return;
    }
    system(cmd);
}

void init_model() {
    g_model = (JsonValue *)value_alloc();
    if (!g_model) exit(1);
    g_model->type = 3;
    g_model->length = 1;
    g_model->action = safe_echo;
}

void reset_model() {
    if (g_model) value_free(g_model);
    g_model = nullptr;
    init_model();
    puts("ok: runtime reset");
}

static const char *g_src;
static size_t g_pos;
static size_t g_len;

void lexer_init(const char *s) {
    g_src = s;
    g_pos = 0;
    g_len = strlen(s);
}

void skip_ws() {
    while (g_pos < g_len && isspace((unsigned char)g_src[g_pos])) g_pos++;
}

bool consume(char c) {
    skip_ws();
    if (g_pos < g_len && g_src[g_pos] == c) {
        g_pos++;
        return true;
    }
    return false;
}

char *parse_string(size_t *out_len) {
    static char parsed[2][256];
    static unsigned int slot = 0;
    if (!consume('"')) return nullptr;
    size_t start = g_pos;
    while (g_pos < g_len && g_src[g_pos] != '"') {
        if (g_src[g_pos] == '\\' && g_pos + 1 < g_len) g_pos += 2;
        else g_pos++;
    }
    if (g_pos >= g_len) return nullptr;
    size_t n = g_pos - start;
    char *s = parsed[slot++ & 1];
    if (n >= 256) n = 255;
    memcpy(s, g_src + start, n);
    s[n] = '\0';
    g_pos++;
    if (out_len) *out_len = n;
    return s;
}

bool parse_nested(JsonValue *out, char *key_out, size_t key_cap) {
    if (!consume('{')) return false;
    char *key = parse_string(nullptr);
    if (!key) return false;
    if (!consume(':')) return false;
    size_t n = 0;
    char *val = parse_string(&n);
    if (!val) return false;
    if (!consume('}')) return false;

    snprintf(key_out, key_cap, "%s", key);
    out->type = 1;
    out->length = (unsigned int)n;
    memset(out->data, 0, sizeof(out->data));
    snprintf(out->data, sizeof(out->data), "%s", val);
    out->child = nullptr;
    out->action = safe_echo;
    return true;
}

static char g_loaded_key[32];

void cmd_load(const char *json) {
    JsonValue *new_value = (JsonValue *)value_alloc();
    if (!new_value) exit(1);
    lexer_init(json);
    if (!parse_nested(new_value, g_loaded_key, sizeof(g_loaded_key))) {
        free(new_value);
        puts("error: invalid configuration");
        return;
    }
    if (g_model->child) value_free(g_model->child);
    g_model->child = new_value;
    puts("ok: configuration loaded");
}

void cmd_delete(const char *key) {
    if (!g_model || !g_model->child) {
        puts("error: no nested object");
        return;
    }
    if (strcmp(g_loaded_key, key) != 0) {
        puts("error: key not found");
        return;
    }
    value_free(g_model->child);
    puts("ok: node deleted");
}

void cmd_alloc(const char *encoded) {
    unsigned long long words[8] = {0};
    int parsed = sscanf(encoded, "%llx %llx %llx %llx %llx %llx %llx %llx",
                        &words[0], &words[1], &words[2], &words[3],
                        &words[4], &words[5], &words[6], &words[7]);
    if (parsed < 8) {
        puts("error: expected 8 encoded fields");
        return;
    }
    JsonValue *v = (JsonValue *)value_alloc();
    if (!v) exit(1);
    memcpy(v, words, sizeof(words));
    puts("ok: training sample queued");
}

void cmd_symbols() {
    printf("safe_echo=%p\n", (void *)safe_echo);
    printf("launch_shell=%p\n", (void *)launch_shell);
}

void infer_value(JsonValue *v) {
    if (!v) return;
    if (v->type == 3 && v->child) {
        infer_value(v->child);
        return;
    }
    if (v->action) v->action(v->data);
}

void cmd_run() {
    puts("[runtime] preparing local model");
    if (!g_model || !g_model->child) {
        puts("[runtime] no nested layer configured");
        return;
    }
    infer_value(g_model->child);
    puts("[runtime] inference complete");
}

void menu() {
    puts("================================================");
    puts("  Local AI Runtime — JSON Configuration Loader  ");
    puts("  Build: 2026.05.medium                         ");
    puts("================================================");
    puts("Commands: load JSON | del KEY | sample HEXWORDS | symbols | run | reset | quit");
}

int main() {
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stdout, nullptr, _IONBF, 0);
    init_model();
    menu();
    printf("> ");

    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n') line[n - 1] = '\0';
        if (strncmp(line, "load ", 5) == 0) cmd_load(line + 5);
        else if (strncmp(line, "del ", 4) == 0) cmd_delete(line + 4);
        else if (strncmp(line, "sample ", 7) == 0) cmd_alloc(line + 7);
        else if (strcmp(line, "symbols") == 0) cmd_symbols();
        else if (strcmp(line, "run") == 0) cmd_run();
        else if (strcmp(line, "reset") == 0) reset_model();
        else if (strcmp(line, "quit") == 0) break;
        else if (strlen(line)) puts("error: unknown command");
        printf("> ");
    }
    return 0;
}
