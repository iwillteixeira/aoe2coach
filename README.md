# AoE2Coach

Sistema de coaching em tempo real para **Age of Empires 2 Definitive Edition** com leitura de memória via `pymem` e dicas geradas por IA (Claude / Anthropic).

---

## Requisitos

- **Windows 10/11** (64-bit)
- **Python 3.10+** ([python.org](https://python.org))
- **Age of Empires 2 DE** instalado e em execução
- Chave de API da Anthropic (`ANTHROPIC_API_KEY`)

---

## Instalação

```bash
git clone <repo>
cd aoe2coach

# Instale as dependências
pip install -r requirements.txt
```

> **Importante:** Execute o terminal (ou o instalador Python) como **Administrador**. A leitura de memória de outros processos requer privilégios elevados no Windows.

---

## Uso

### 1. Defina a chave da API

```bash
# PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# CMD
set ANTHROPIC_API_KEY=sk-ant-...
```

### 2. Execute (como Administrador)

```bash
python main.py
```

O overlay aparecerá no canto superior direito da tela.
Inicie o AoE2DE e entre em uma partida — o coach começará a funcionar automaticamente.

### Opções da linha de comando

| Opção          | Padrão | Descrição                                      |
|----------------|--------|------------------------------------------------|
| `--hotkey KEY` | `F8`   | Tecla para mostrar/ocultar o overlay           |
| `--no-coach`   | —      | Modo monitor: sem chamadas à API               |
| `--poll N`     | `3.0`  | Intervalo de polling em segundos               |
| `--debug`      | —      | Logs detalhados no terminal                    |

```bash
# Exemplos
python main.py --hotkey F9 --poll 5
python main.py --no-coach          # apenas mostra os dados, sem IA
python main.py --debug             # logs detalhados
```

---

## Calibração de offsets após patches

Cada atualização do jogo pode mover os endereços de memória. Quando isso acontece,
o overlay mostrará zeros em todos os campos.

### Calibração automática

Execute como Administrador **com o jogo aberto em uma partida**:

```bash
python calibrate.py
```

O script:
1. Varre toda a memória do processo buscando cada signature de bytes
2. Resolve o endereço final via decodificação RIP-relative
3. Salva os endereços atualizados em `offsets.json`
4. Reporta quais signatures não foram encontradas

### Quando a calibração automática falha (signature quebrada)

Se o patch alterou também o código em volta da variável, a signature não será
encontrada. Nesses casos, é necessário remapear manualmente com **Cheat Engine**.

#### Passo a passo com Cheat Engine

1. **Abra o Cheat Engine** como Administrador e anexe ao `AoE2DE.exe`
2. **Encontre o valor:** use *First Scan* → pesquise o valor atual do recurso
   (ex: quantidade de comida)
3. **Refine:** jogue um pouco, altere o recurso, clique *Next Scan* com o novo
   valor. Repita até ter 1–3 resultados
4. **Encontre a instrução que escreve neste endereço:**
   clique com o botão direito no endereço → *Find out what writes to this address*
5. **Identifique o padrão de bytes:** em Cheat Engine, clique no endereço da
   instrução → *Show disassembler* → anote os bytes ao redor (ex: `F3 0F 11 05 ?? ?? ?? ??`)
6. **Atualize `offsets.json`:**
   - Coloque os novos bytes na chave `"signatures"` do campo quebrado
   - Ou coloque o endereço resolvido diretamente em `"offsets"` (válido apenas
     até o próximo patch)
7. Abra uma issue no repositório com a nova signature para que outros jogadores
   se beneficiem

#### Campos e o que representam

| Campo              | Tipo    | Descrição                                  |
|--------------------|---------|--------------------------------------------|
| `tc_count`         | int     | Número de Town Centers construídos         |
| `villager_count`   | int     | Total de aldeões vivos                     |
| `tc_queue`         | int     | Unidades em fila em todos os TCs           |
| `idle_tc`          | int     | Town Centers sem produção no momento       |
| `food`             | float   | Quantidade de comida                       |
| `wood`             | float   | Quantidade de madeira                      |
| `gold`             | float   | Quantidade de ouro                         |
| `stone`            | float   | Quantidade de pedra                        |
| `game_time`        | int     | Tempo de jogo em segundos                  |
| `current_age`      | int     | Idade atual (0=Dark, 1=Feudal, 2=Castle, 3=Imperial) |
| `age_research`     | bool    | True se um age-up está sendo pesquisado    |

---

## Estrutura dos arquivos

```
aoe2coach/
├── main.py           # Entry point
├── memory_reader.py  # Leitura de memória via pymem + signature scanning
├── calibrate.py      # Recalibração de offsets após patches
├── coach.py          # Integração com a API da Anthropic
├── overlay.py        # Overlay tkinter (transparente, sempre-no-topo)
├── offsets.json      # Signatures e offsets (versionado por patch)
├── requirements.txt  # Dependências Python
└── README.md         # Este arquivo
```

---

## Como funciona

```
AoE2DE.exe  ←──── pymem (leitura de memória) ────→  MemoryReader
                                                           │
                                                   (a cada 3 s, se mudou)
                                                           │
                                                      AoE2Coach
                                                    (API Anthropic)
                                                           │
                                                      Overlay (tkinter)
                                                  (janela transparente)
```

1. O `MemoryReader` faz polling a cada 3 segundos lendo os valores do jogo
2. Quando detecta uma mudança relevante (TC ocioso, aldeão concluído, age-up, etc.)
   dispara um evento
3. O `AoE2Coach` monta um payload de contexto e chama a API da Anthropic
4. A dica retornada aparece no overlay em destaque amarelo

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---------|----------------|---------|
| "Processo AoE2DE.exe não encontrado" | Jogo não aberto | Abra o jogo primeiro |
| Todos os campos mostram 0 | Patch quebrou os offsets | Execute `calibrate.py` |
| "ANTHROPIC_API_KEY inválida" | Chave errada ou expirada | Verifique em console.anthropic.com |
| Overlay não aparece | Bloqueado por antivírus/UAC | Execute como Administrador |
| Hotkey não funciona | Conflito com outra aplicação | Use `--hotkey` para mudar a tecla |

---

## Aviso legal

Este projeto é para fins educacionais e de suporte ao jogador. A leitura de
memória é uma técnica usada por ferramentas de acessibilidade e overlays (como
Overwolf). Verifique os Termos de Serviço da Microsoft/Xbox antes de usar em
partidas ranqueadas ou torneios oficiais.
# aoe2coach
