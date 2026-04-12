# jsecret

> [English version](README.md)

`jsecret` é um scanner estático sem dependências externas para ativos JavaScript e TypeScript. Foi construído para encontrar segredos expostos, padrões arriscados no lado do cliente e achados relevantes para bug bounty em código-fonte, bundles compilados, scripts remotos e source maps expostos.

Combina um extenso catálogo de assinaturas com heurísticas contextuais, com foco real na supressão de falsos positivos que normalmente tornam scanners ruidosos em projetos reais.

Versão atual: `v4.0.3`

## Por que usar o jsecret

- construído para alvos JS e TS reais, não apenas exemplos didáticos
- útil para bug bounty, revisões de segurança, gates de CI e recon client-side
- saídas determinísticas em TXT, CSV, JSON, SARIF e Markdown
- calibrado para reduzir ruído de testes, fixtures, placeholders, referências de env, bundles e código gerado
- implementação Go usando apenas stdlib, sem dependências de terceiros em runtime
- respaldado por `128` testes automatizados, incluindo cobertura de integração CLI

## O que detecta

### Detecções por assinatura

O `jsecret` inclui `200+` padrões de assinatura nas categorias:

- cloud e infraestrutura: AWS, GCP, Azure, Alibaba, DigitalOcean, Heroku, Scaleway, Hetzner, Linode, Vultr, Fastly
- IA, LLM e provedores de vetores: OpenAI, Anthropic, DeepSeek, xAI, Perplexity, Fireworks, Groq, Cohere, Mistral, Together, Pinecone, Weaviate, Qdrant, Replicate
- bancos de dados e filas: MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch, Snowflake, CockroachDB, ClickHouse, Cassandra, RabbitMQ, Memcached, InfluxDB
- controle de versão e CI/CD: GitHub, GitLab, Bitbucket, CircleCI, Travis, Jenkins, Azure DevOps, GitHub Actions, Buildkite, Terraform, Pulumi
- pagamentos e comunicações: Stripe, Square, Braintree, PayPal, Adyen, Coinbase, Plaid, Slack, Twilio, SendGrid, Mailgun, Telegram, Discord, Postmark, Mailchimp, SparkPost, Vonage, Pusher, Ably
- plataformas SaaS e deploy: Vercel, Clerk, PlanetScale, Neon, Railway, Render, Fly.io, Deno Deploy, Expo, Arcjet, Trigger.dev, Resend, Infisical, Doppler
- chaves e certificados: blocos de chave privada, material PEM, material de autenticação de alto sinal, JWTs, bearer tokens e mais

### Detecções heurísticas

O `jsecret` também detecta `50+` padrões de código arriscados, incluindo:

- DOM XSS e sinks HTML inseguros
- injeção de SQL, NoSQL, comandos e templates
- SSRF, redirecionamento aberto e fluxos de requisição externa inseguros
- criptografia fraca, geração insegura de tokens e validação TLS desativada
- credenciais hardcoded e uso indevido de JWT
- CORS permissivo e uso de postMessage com wildcard
- configurações inseguras de cookies e abuso de web storage
- prototype pollution, mass assignment e construção insegura de regex
- exposição de introspecção GraphQL e exposição de source maps
- stack traces expostos e vazamento de autenticação npm

## Estratégia contra falsos positivos

O projeto é explicitamente otimizado para qualidade de sinal. Não apenas adiciona padrões — também remove os ruins.

Controles principais:

- supressão de placeholders e exemplos como `changeme`, `your_key_here`, `${TOKEN}` e `{{SECRET}}`
- thresholds de entropia por padrão para classes de tokens ruidosos
- reconhecimento de arquivos de teste, spec, fixture, mock e env-example
- reconhecimento de hashes bcrypt, Argon2 e scrypt
- supressão de conteúdo minificado para assinaturas ruidosas selecionadas
- supressão de vendor e bundles gerados
- supressão de valores comuns como hashes vazios, charsets e material de exemplo
- supressão de referências a código como `process.env.*` e `config.*`
- supressão de valores com aparência de paths e seletores CSS
- refinamentos heurísticos para sanitização React, handlers de webhook, verificações de debug, CORS wildcard, introspecção GraphQL, vazamento de erros, taint de headers, source maps e regexes controladas pelo usuário

## Início rápido

### Instalação

Com Go:

```bash
go install github.com/jjardel-infosec/jsecret@latest
```

A partir do código-fonte:

```bash
git clone https://github.com/jjardel-infosec/jsecret.git
cd jsecret
go build -o jsecret
```

Instalação opcional no Linux ou macOS:

```bash
sudo mv jsecret /usr/local/bin/
```

### Primeiro scan

Escanear um projeto local:

```bash
jsecret -d ./frontend
```

Escanear ativos remotos via stdin:

```bash
cat urls.txt | jsecret
```

Gerar relatório SARIF compatível com CI e falhar em achados bloqueadores:

```bash
jsecret -d . -min HIGH -strict -sarif results.sarif
```

## Modos de scan

| Modo | Flag | Entrada |
|------|------|---------|
| Alvo único | `-u` | uma URL de script remoto |
| Arquivo de alvos | `-f` | um alvo por linha |
| Scan recursivo de diretório | `-d` | diretório local |
| Modo stdin | nenhuma | um alvo por linha via stdin |

O modo de diretório escaneia estas extensões por padrão:

`.js, .mjs, .cjs, .jsx, .ts, .tsx, .vue, .svelte`

Use `-ext` para sobrescrever o conjunto.

## Referência de CLI

| Flag | Descrição | Padrão |
|------|-----------|--------|
| `-u` | URL única para escanear | |
| `-f` | Arquivo com lista de alvos | |
| `-d` | Diretório para scan recursivo | |
| `-o` | Salvar resultados em arquivo TXT | |
| `-csv` | Salvar resultados em arquivo CSV | |
| `-json` | Salvar resultados em arquivo JSON | |
| `-sarif` | Salvar resultados em arquivo SARIF v2.1.0 | |
| `-md` | Salvar resultados em relatório Markdown | |
| `-min` | Severidade mínima: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | todas |
| `-proxy` | URL de proxy HTTP/HTTPS | |
| `-k` | Ignorar verificação de certificado TLS para requisições HTTPS | `false` |
| `-ext` | Extensões personalizadas para scans de diretório | `.js,.mjs,.cjs,.jsx,.ts,.tsx,.vue,.svelte` |
| `-t` | Threads concorrentes | `50` |
| `-s` | Modo silencioso: suprime banner, sumário e avisos de fetch | `false` |
| `-strict` | Sai com código `1` se existirem achados `CRITICAL` ou `HIGH` | `false` |
| `-version` | Exibe a versão e sai | |
| `-h` | Exibe ajuda | |

## Exemplos práticos

Escanear uma aplicação local mantendo apenas achados de alto sinal:

```bash
jsecret -d ./webapp -min HIGH
```

Gerar relatório Markdown para revisão manual:

```bash
jsecret -d ./assets -md report.md
```

Escanear arquivo com URLs de scripts coletados:

```bash
jsecret -f js_urls.txt -json findings.json
```

Usar proxy durante o recon:

```bash
jsecret -f urls.txt -proxy http://127.0.0.1:8080 -json proxy-scan.json
```

Escanear alvo de staging com certificado autoassinado:

```bash
jsecret -u https://staging.example.local/app.js -k
```

Escanear tipos de arquivo personalizados em um repositório:

```bash
jsecret -d . -ext .js,.ts,.scan,.bundle
```

Usar modo stdin em pipeline:

```bash
cat subdomains.txt | httpx | jsecret -min HIGH
```

## Workflow recon com recon-js.sh

O repositório inclui `recon-js.sh`, um script de recon completo que combina enumeração de subdomínios, detecção de hosts ativos, descoberta de URLs JS e download automatizado.

### Uso

```bash
./recon-js.sh booking.com
```

### Fases do script

| Fase | O que faz |
|------|-----------|
| 1 — Enumeração de subdomínios | subfinder, amass, crt.sh, wayback, gau, chaos, assetfinder, findomain, puredns |
| 2 — Probing HTTP | httpx filtra apenas hosts ativos |
| 3 — Descoberta de URLs JS | subjs, getJS, katana, gau, wayback CDX |
| 3b — Verificação de URLs | httpx descarta 404s, redirects e respostas não-JS |
| 4 — Download | curl baixa os arquivos JS verificados |

### Onde os arquivos são salvos

```
$HOME/01-All-Domains/<dominio>.txt   → subdomínios encontrados
$HOME/03-JS-Download/<dominio>/      → arquivos JS baixados
$HOME/03-JS-Download/<dominio>/url_map.txt  → mapeamento filename → URL original
```

### Integração com jsecret

O `url_map.txt` gerado pelo script é lido automaticamente pelo jsecret ao escanear o diretório. O output mostrará a URL original do arquivo, não o caminho local:

```bash
jsecret -d ~/03-JS-Download/booking.com
```

```
[https://cf.bstatic.com/static/vendor-es5.ABC123.js] [CRITICAL] AWS Access Key ID : AKIA...
```

## Formatos de saída

### TXT

Saída padrão no console, também disponível via `-o`.

```text
[https://example.com/app.js] [CRITICAL] AWS Access Key ID : AKIAIOSFODNN7EXAMPLE
```

### CSV

Útil para planilhas e exportações de triagem rápida.

Colunas: `Target`, `Priority`, `Finding Type`, `Evidence`

### JSON

Saída estruturada para automações personalizadas.

```json
[
  {
    "target": "https://example.com/app.js",
    "priority": "CRITICAL",
    "finding": "AWS Access Key ID",
    "evidence": "AKIAIOSFODNN7EXAMPLE",
    "category": "signature",
    "line": 42
  }
]
```

### SARIF

Use `-sarif` para GitHub Code Scanning, viewers SARIF no VS Code ou outras ferramentas compatíveis com SARIF.

### Markdown

Use `-md` para relatórios legíveis agrupados por severidade e alvo. Ideal para submissões de bug bounty, handoffs de revisão e triagem manual.

## Modelo de severidade

O `jsecret` emite quatro severidades:

- `CRITICAL`: segredos de alta confiança ou exposições imediatamente perigosas
- `HIGH`: achados provavelmente exploráveis ou de alto risco
- `MEDIUM`: fraqueza de segurança relevante que precisa de revisão
- `LOW`: achado informativo que pode apoiar análise mais ampla

Use `-min` para suprimir saídas de baixa prioridade e `-strict` para falhar quando achados bloqueadores estiverem presentes.

## Ignorando arquivos com .jsecretignore

Crie um arquivo `.jsecretignore` na raiz do scan para excluir conteúdo conhecido ou intencionalmente ignorado.

Exemplo:

```text
# Ignorar diretórios de teste
tests/
__tests__/
__mocks__/

# Ignorar arquivos específicos
config.example.js
*.test.js
*.spec.ts

# Ignorar código gerado
**/generated/**
dist/
/build/
```

## Integração com CI/CD

```bash
jsecret -d ./src -min HIGH -strict -sarif results.sarif
```

Exemplo de step no GitHub Actions:

```yaml
- name: Scan JavaScript assets
  run: ./jsecret -d . -min HIGH -strict -sarif results.sarif
```

## Códigos de saída

- `0`: scan concluído sem achados bloqueadores, ou ajuda exibida
- `1`: entrada CLI inválida, falha de saída ou proxy, ou `-strict` encontrou resultados `CRITICAL` ou `HIGH`

## Arquitetura

Decisões centrais de design:

- zero dependências externas
- análise em duas passagens: assinaturas + heurísticas
- deduplicação de conteúdo por SHA-256 para ignorar ativos repetidos
- connection pooling com reuso keep-alive
- limite de `10 MB` no corpo de resposta para fetches remotos
- resolução de source maps quando ativos expostos os referenciam
- pré-filtragem por prefixo antes da avaliação de regex custosa
- ordenação determinística de resultados em JSON, SARIF e Markdown

## Limitações

O `jsecret` é um scanner estático. Ele não executa JavaScript, não emula estado de browser e não prova exploitabilidade.

Isso significa:

- um achado ainda pode precisar de validação humana
- a cobertura remota depende do que o alvo realmente serve
- a análise de source maps só acontece quando o source map é referenciado e recuperável
- scans de diretório consideram apenas as extensões configuradas

## Desenvolvimento

Requisitos: Go `1.21+`

Comandos comuns:

```bash
make verify
make build
make test
make bench
make cover
make cross
```

---

## Declaração de Uso Ético e Responsável

As ferramentas `jsecret` e `recon-js.sh` foram desenvolvidas exclusivamente para apoiar atividades legítimas de segurança da informação, incluindo testes de intrusão autorizados, programas de bug bounty, auditorias técnicas e pesquisas acadêmicas.

Seu uso deve estar estritamente alinhado aos seguintes princípios:

**Autorização prévia**
As ferramentas devem ser utilizadas apenas em ativos, sistemas ou ambientes para os quais exista autorização formal e documentada.

**Conformidade legal e regulatória**
O usuário é integralmente responsável por garantir que o uso esteja em conformidade com todas as leis aplicáveis, incluindo legislações de proteção de dados e crimes cibernéticos.

**Respeito à confidencialidade e integridade**
É proibido acessar, coletar, armazenar ou divulgar dados sensíveis sem necessidade técnica justificável e sem autorização explícita.

**Uso proporcional e responsável**
A exploração de vulnerabilidades deve ser limitada ao necessário para validação técnica, evitando impactos operacionais, indisponibilidade de serviços ou qualquer forma de dano.

**Responsabilização**
O uso indevido dessas ferramentas pode resultar em sanções civis, administrativas e penais, sendo de total responsabilidade do usuário.

O objetivo dessas ferramentas é contribuir para o fortalecimento da segurança dos sistemas e da privacidade dos usuários, promovendo práticas éticas e responsáveis no ecossistema de segurança ofensiva.

---

## Licença

Este projeto é distribuído sob a licença disponível em [LICENSE](LICENSE).
