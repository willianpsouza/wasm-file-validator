# Validador de Arquivos em WASM

> [English version](README.md)

Repositório de exemplo mostrando como validar arquivos compactados / de imagem
não confiáveis **no navegador** com Rust/WebAssembly, assinar e criptografar o
veredito para que um backend em Go possa confiar nele.

```
navegador ──upload──▶ Rust/WASM ──inspeciona──▶ veredito
                           │ assina (Ed25519)
                           │ sela (ECDH x25519 + XChaCha20-Poly1305)
                           ▼
                      envelope base64 ──POST /api/verify──▶ Go (chi)
                                                             descriptografa + verifica assinatura
                                                             devolve o veredito confiável
```

O servidor Go serve **os três** a partir de um único processo:

| Rota               | Serve                                             |
|--------------------|---------------------------------------------------|
| `GET /`            | SPA de upload (`web/static/index.html`)           |
| `GET /pkg/*`       | o artefato WASM compilado + cola JS               |
| `POST /api/verify` | descriptografa o envelope selado e verifica a assinatura |

## O que ele detecta

Todas as checagens leem **somente cabeçalhos / metadados do diretório central**
— o validador nunca descompacta o corpo dos arquivos e nunca decodifica pixels
de imagem, então um arquivo hostil não consegue transformar a própria validação
no ataque.

- **Zip bombs** — razão de compressão, tamanho total declarado descompactado,
  tamanho por entrada, número de entradas e arquivos aninhados (vetor de bomba
  recursiva).
- **JPEG** — EOI ausente, dados anexados depois do EOI e assinaturas embutidas
  de executável/script/arquivo (carregadores poliglotas "worm").
- **GIF** — trailer ausente, dados anexados depois do trailer (GIFAR) e a mesma
  varredura de assinaturas embutidas.
- **PDF** — `/JavaScript` + `/OpenAction` (execução automática ao abrir),
  `/Launch` (programa externo), `/AA`, `/EmbeddedFile`, `/URI` / `launchURL`
  de saída (extrai a URL) e dados anexados depois do último `%%EOF`.

Assinaturas procuradas: `MZ` (PE), `\x7fELF`, `PK\x03\x04` (zip aninhado),
`<?php`, `<script`, `#!/`, `\xca\xfe\xba\xbe`.

## ⚠️ Nota de segurança — leia isto

Este repositório embute uma **chave privada de assinatura Ed25519 dentro do WASM
cliente** porque o exercício pediu isso. **Isso não oferece autenticidade real**:
o `.wasm` é público, então qualquer pessoa pode extrair a chave e forjar
assinaturas. A etapa de assinatura aqui apenas demonstra o mecanismo.

A direção de **criptografia** é sólida: o WASM guarda apenas a chave **pública**
x25519 do backend e sela para ela (ECDH com remetente anônimo), então só o
backend consegue ler o payload. Essa parte corresponde a um padrão real.

Para produção, em vez disso você deveria:

- assinar em um servidor / enclave confiável, ou usar chaves por sessão +
  attestation;
- tratar o veredito do cliente como **dica** e re-executar a validação no
  servidor sobre os bytes brutos antes de confiar nele.

Como o repositório é **público**, as chaves são geradas em tempo de build por
`cmd/genkeys` em arquivos ignorados pelo git (`keys_gen.rs`, `keys_gen.go`) e
**nunca são commitadas**.

## Executar (Docker — recomendado)

```bash
docker compose up --build
# abra http://localhost:8099
```

A porta `8099` é usada porque `8080`/`8090` costumam estar ocupadas. Troque em
`docker-compose.yml`.

## Build local (sem Docker)

Precisa de Go ≥1.23, Rust e [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
go mod tidy
go run ./cmd/genkeys .                 # escreve keys_gen.rs + keys_gen.go
cd web/wasm && wasm-pack build --release --target web --out-dir ../static/pkg
cd ../..
go run ./cmd/server                    # http://localhost:8099
```

## Testes e cobertura

Stack mínima de testes com meta de **80% de cobertura** (Go + Rust).

```bash
make keys           # gera os keys_gen.* (necessário antes de testar)
make test           # testes unitários Go + Rust
make cover          # porta de 80% em Go e Rust (precisa de cargo-llvm-cov)
make cover-docker   # roda tudo em container, sem instalar nada no host
```

- **Go** (`cmd/server`, `cmd/genkeys`): recria o selamento dentro do teste para
  exercitar `unseal`/`handleVerify`, cobre rotas, assinatura válida/inválida e
  entradas malformadas.
- **Rust** (`web/wasm`): testa cada inspetor (zip/jpeg/gif/pdf/desconhecido),
  os auxiliares e o selamento (`seal_to_backend`) rodando nativamente (o backend
  `getrandom` fica em JS só no alvo wasm).

A CI (`.github/workflows/ci.yml`) roda a mesma porta de 80% em cada push/PR.

## Limitações & evasão (leia antes de confiar no veredito)

Isto é um **scanner estrutural rápido, não um parser completo**. Lacunas
conhecidas e como o código as trata:

- **Ofuscação de PDF.** Escapes hex em nomes são normalizados (`/J#61vaScript`
  → `/JavaScript`) antes do match, mas conteúdo dentro de **FlateDecode /
  object streams não é descomprimido**. Um payload escondido ali escapa do scan
  de string, então a presença desses streams é sinalizada como
  `pdf_compressed_streams` ("inspecionar no servidor") em vez de passar em
  silêncio. Cobertura real exige um parser de PDF que descomprima objetos.
- **Zip bombs recursivas.** Arquivos aninhados são detectados por uma sonda de
  magic de 4 bytes (independente do nome, então `payload.bin` ainda é pego), mas
  a detecção é **de uma camada** — uma bomba recursiva tipo 42.zip exige
  extração com limite de profundidade e tetos rígidos de bytes/tempo. Os
  tamanhos do diretório central do ZIP são **meramente informativos**; para
  confirmar um mentiroso é preciso inflar de verdade com teto.
- **Fim de arquivo de imagem.** Marcadores JPEG e blocos GIF são percorridos
  estruturalmente até o fim real (então um `FF D9` numa miniatura ou um `0x3B`
  como byte de dado não é confundido com o fim). Imagens truncadas ou fora do
  padrão reportam "fim não alcançado" em vez de chutar.
- **`decrypted` não é autenticação.** O selamento é de remetente anônimo para
  uma chave pública, e a chave de assinatura é extraível do `.wasm`, então
  **qualquer um pode forjar um envelope válido**. `decrypted: true` significa só
  "selado para nós". Mantenha autenticação real (sessão/token/mTLS) e validação
  no servidor.
- **Sem proteção contra replay.** Um envelope capturado descriptografa de novo.
  Em produção, vincule cada envelope a um nonce/timestamp emitido pelo servidor
  (como AAD) e rejeite repetições.

## Criptografia, em detalhe

- **Assinatura:** Ed25519 sobre os bytes canônicos do veredito em JSON.
- **Selamento:** par x25519 efêmero;
  `shared = X25519(eph_secret, backend_pub)`;
  `key = HKDF-SHA256(shared, info="wasm-file-validator-v1")`;
  `XChaCha20-Poly1305(key, nonce)` com a chave pública efêmera como AAD.
- **Envelope:** `eph_pub(32) || nonce(24) || ciphertext`, codificado em base64.

## Estrutura

```
cmd/genkeys/      gera os pares de chave + arquivos-fonte com chaves embutidas
cmd/server/       servidor chi: SPA + wasm + /api/verify
web/wasm/         crate Rust (validação + assinatura + selamento)
web/static/       SPA; a saída do wasm-pack vai para web/static/pkg/
```

## Licença

MIT
