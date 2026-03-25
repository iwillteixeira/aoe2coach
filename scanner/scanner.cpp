/**
 * scanner.cpp — AOB scanner externo para AoE2DE.
 *
 * Recebe padrões AOB como argumentos de linha de comando e imprime
 * um JSON com os RVAs encontrados (relativos ao módulo principal).
 *
 * Compilar com MSVC:
 *   cl.exe scanner.cpp /O2 /W3 /Fe:scanner.exe /link psapi.lib
 *
 * Compilar com MinGW-w64 (WSL2 ou Windows):
 *   x86_64-w64-mingw32-g++ -O3 -o scanner.exe scanner.cpp -lpsapi -static
 *
 * Uso:
 *   scanner.exe <processo.exe> "label:padrão AOB" ["label2:padrão2"] ...
 *
 * Padrão AOB: bytes em hex separados por espaço, wildcards como "??"
 *   "48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 40"
 *
 * Saída (stdout, JSON):
 *   {"tribePanelInven": "0x2BA7190", "pathfindingSystem": "0x2BB80D0"}
 *   Campos não encontrados aparecem como null.
 *
 * Modos de resolução (após o padrão AOB):
 *   rip:field:instr_size  — resolve RIP-relative disp32 (padrão: rip:3:7)
 *     ex: "tribePanelInven:48 8B 0D ?? ?? ?? ??:rip:3:7"
 *   bytes:field:size      — lê N bytes literais no offset field do match
 *     ex: "localPlayerOff:48 8B 83 ?? ?? ?? ?? 48 8B 48 70:bytes:3:4"
 *
 * Saída JSON:
 *   modo rip   → RVA relativo ao módulo (subtrai base)
 *   modo bytes → valor literal lido (ex: offset de struct)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Estruturas
// ---------------------------------------------------------------------------

enum class ResolveMode { RIP, BYTES };

struct Pattern {
    std::string          label;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;      // 0xFF = fixo, 0x00 = wildcard
    ResolveMode          mode       = ResolveMode::RIP;
    int                  field      = 3;  // byte offset dentro do match
    int                  param      = 7;  // RIP: instr_size  |  BYTES: nº de bytes a ler
};

// ---------------------------------------------------------------------------
// Parse de padrão AOB: "48 8B 0D ?? ?? ?? ??"
// ---------------------------------------------------------------------------

static Pattern parse_pattern(const std::string& label,
                              const std::string& sig,
                              ResolveMode mode = ResolveMode::RIP,
                              int field = 3, int param = 7)
{
    Pattern p;
    p.label = label;
    p.mode  = mode;
    p.field = field;
    p.param = param;

    size_t i = 0;
    while (i < sig.size()) {
        while (i < sig.size() && sig[i] == ' ') ++i;
        if (i >= sig.size()) break;

        if (sig[i] == '?') {
            p.bytes.push_back(0x00);
            p.mask.push_back(0x00);
            i += (i + 1 < sig.size() && sig[i+1] == '?') ? 2 : 1;
        } else {
            char hex[3] = { sig[i], (i+1 < sig.size()) ? sig[i+1] : '0', 0 };
            p.bytes.push_back((uint8_t)strtol(hex, nullptr, 16));
            p.mask.push_back(0xFF);
            i += 2;
        }

        while (i < sig.size() && sig[i] == ' ') ++i;
    }
    return p;
}

// ---------------------------------------------------------------------------
// Busca PID pelo nome do processo
// ---------------------------------------------------------------------------

static DWORD find_pid(const char* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// ---------------------------------------------------------------------------
// Scan de um chunk de memória: retorna offset da primeira ocorrência ou -1
// ---------------------------------------------------------------------------

static int64_t scan_chunk(const uint8_t* data, size_t size,
                           const uint8_t* pat,  const uint8_t* mask, size_t plen)
{
    if (size < plen) return -1;

    // Encontra o primeiro byte fixo para "salto rápido"
    size_t  first_fixed = 0;
    uint8_t first_byte  = 0;
    for (size_t j = 0; j < plen; j++) {
        if (mask[j]) { first_fixed = j; first_byte = pat[j]; break; }
    }

    const size_t limit = size - plen;
    for (size_t i = 0; i <= limit; i++) {
        if (data[i + first_fixed] != first_byte) continue;

        bool ok = true;
        for (size_t j = 0; j < plen; j++) {
            if (mask[j] && data[i + j] != pat[j]) { ok = false; break; }
        }
        if (ok) return (int64_t)i;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Resolução do resultado
// ---------------------------------------------------------------------------

// Modo RIP: resolve disp32 RIP-relative → endereço absoluto
static uintptr_t resolve_rip(HANDLE proc, uintptr_t instr_addr,
                              int field, int instr_size)
{
    int32_t disp = 0;
    SIZE_T  read_ok = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(instr_addr + field),
                           &disp, sizeof(disp), &read_ok) || read_ok != 4)
        return 0;
    return instr_addr + (uintptr_t)instr_size + (intptr_t)disp;
}

// Modo BYTES: lê N bytes literais no offset field e retorna como uint64
static uintptr_t resolve_bytes(HANDLE proc, uintptr_t match_addr,
                                int field, int nbytes)
{
    if (nbytes < 1 || nbytes > 8) return 0;
    uint64_t val = 0;
    SIZE_T   read_ok = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(match_addr + field),
                           &val, (SIZE_T)nbytes, &read_ok) || (int)read_ok != nbytes)
        return 0;
    return (uintptr_t)val;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "Uso: scanner.exe <processo.exe> \"label:padrao\" [\"label2:padrao2:field:instr_size\"] ...\n"
            "Saida: JSON com RVAs encontrados (relativos ao modulo principal)\n");
        return 1;
    }

    // Parse dos padrões
    // Formato: "label:padrão AOB[:modo[:field[:param]]]"
    //   modo "rip"   (padrão) → resolve RIP-relative; field=3, param=instr_size=7
    //   modo "bytes"          → lê bytes literais;    field=3, param=nbytes=4
    std::vector<Pattern> patterns;
    for (int i = 2; i < argc; i++) {
        std::string arg(argv[i]);
        size_t c1 = arg.find(':');
        if (c1 == std::string::npos) continue;

        std::string label = arg.substr(0, c1);
        std::string rest  = arg.substr(c1 + 1);

        // Extrai tokens opcionais do final: modo, field, param
        // Separados por ':'; o padrão AOB só contém hex e '?' e espaços
        ResolveMode mode  = ResolveMode::RIP;
        int field = 3, param = 7;

        // Divide no último ':' repetidamente enquanto o token parece um número ou "rip"/"bytes"
        auto pop_int = [&](int& out) -> bool {
            size_t pos = rest.rfind(':');
            if (pos == std::string::npos) return false;
            std::string tok = rest.substr(pos + 1);
            char* e; long v = strtol(tok.c_str(), &e, 10);
            if (*e != '\0' || tok.empty() || tok.size() > 4) return false;
            out = (int)v; rest = rest.substr(0, pos); return true;
        };
        auto pop_mode = [&]() -> bool {
            size_t pos = rest.rfind(':');
            if (pos == std::string::npos) return false;
            std::string tok = rest.substr(pos + 1);
            if (tok == "rip")   { mode = ResolveMode::RIP;   rest = rest.substr(0, pos); return true; }
            if (tok == "bytes") { mode = ResolveMode::BYTES; rest = rest.substr(0, pos);
                                  if (param == 7) { param = 4; } return true; }
            return false;
        };

        pop_int(param);
        pop_int(field);
        pop_mode();

        patterns.push_back(parse_pattern(label, rest, mode, field, param));
    }

    if (patterns.empty()) {
        fprintf(stderr, "Nenhum padrao valido fornecido.\n");
        return 1;
    }

    // Abre processo
    DWORD pid = find_pid(argv[1]);
    if (!pid) {
        fprintf(stderr, "Processo '%s' nao encontrado.\n", argv[1]);
        return 2;
    }

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) {
        fprintf(stderr, "OpenProcess falhou: %lu\n", GetLastError());
        return 3;
    }

    // Base do módulo principal
    HMODULE  mod     = nullptr;
    DWORD    needed  = 0;
    uintptr_t base   = 0;
    if (EnumProcessModules(proc, &mod, sizeof(mod), &needed) && mod)
        base = (uintptr_t)mod;

    // Resultados
    std::vector<uintptr_t> results(patterns.size(), 0);
    int remaining = (int)patterns.size();

    // Buffer de leitura reutilizável (4 MB)
    const size_t BUF_SIZE = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(BUF_SIZE);

    // Varre todas as regiões MEM_COMMIT legíveis
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (remaining > 0 && addr < (uintptr_t)0x7FFFFFFFFFFF) {
        if (!VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) break;

        uintptr_t region_base = (uintptr_t)mbi.BaseAddress;
        size_t    region_size = mbi.RegionSize;

        const DWORD readable = PAGE_READONLY | PAGE_READWRITE |
                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                               PAGE_EXECUTE_WRITECOPY;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & readable) &&
            !(mbi.Protect & PAGE_GUARD) &&
            region_size > 0)
        {
            size_t offset = 0;
            while (offset < region_size && remaining > 0) {
                size_t to_read = (region_size - offset < BUF_SIZE)
                                  ? (region_size - offset) : BUF_SIZE;
                SIZE_T read_ok = 0;

                if (!ReadProcessMemory(proc,
                                       (LPCVOID)(region_base + offset),
                                       buf.data(), to_read, &read_ok)
                    || read_ok == 0)
                {
                    offset += to_read;
                    continue;
                }

                for (size_t pi = 0; pi < patterns.size(); pi++) {
                    if (results[pi]) continue;  // já encontrado

                    const Pattern& p = patterns[pi];
                    int64_t hit = scan_chunk(buf.data(), read_ok,
                                             p.bytes.data(), p.mask.data(),
                                             p.bytes.size());
                    if (hit >= 0) {
                        uintptr_t match = region_base + offset + (uintptr_t)hit;
                        uintptr_t res   = 0;
                        if (p.mode == ResolveMode::RIP)
                            res = resolve_rip(proc, match, p.field, p.param);
                        else
                            res = resolve_bytes(proc, match, p.field, p.param);
                        if (res) {
                            results[pi] = res;
                            --remaining;
                        }
                    }
                }

                offset += read_ok;
            }
        }

        uintptr_t next = region_base + region_size;
        if (next <= addr) break;
        addr = next;
    }

    CloseHandle(proc);

    // Saída JSON
    // modo rip   → RVA (results[i] - base)
    // modo bytes → valor literal (results[i] já é o valor)
    printf("{");
    for (size_t i = 0; i < patterns.size(); i++) {
        if (i > 0) printf(", ");
        if (results[i]) {
            uintptr_t val = (patterns[i].mode == ResolveMode::RIP && base)
                            ? results[i] - base
                            : results[i];
            printf("\"%s\": \"0x%llX\"",
                   patterns[i].label.c_str(),
                   (unsigned long long)val);
        } else {
            printf("\"%s\": null", patterns[i].label.c_str());
        }
    }
    printf("}\n");

    return 0;
}
