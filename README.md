# Detecção de Exfiltração e Classificação de Dados Sensíveis com IA

> **PIBITI — Iniciação Tecnológica** · Centro Universitário Martha Falcão Wyden · Linha de pesquisa: Segurança Cibernética
> Pesquisador: Jorge Vieira · Orientação: Profª Danielle Lima de Figueiredo · Ago/2026 – Jul/2027

Protótipo de baixo custo, construído só com ferramentas open source, para ajudar **Organizações da Sociedade Civil (OSCs) de Manaus** a proteger os dados sensíveis que tratam, em conformidade com a **LGPD**.

🚧 **Status:** em desenvolvimento (fase atual: engenharia de dados e NLP).

---

## O problema

OSCs lidam com dados de saúde, vulnerabilidade social e direitos civis de populações vulneráveis. Um vazamento gera sanções e danos éticos graves, mas essas organizações raramente têm orçamento para soluções de segurança comerciais.

## A proposta

Um sistema híbrido com duas frentes que se complementam:

| Frente | O que faz | Técnica |
|---|---|---|
| **Tráfego de rede** | Aprende o comportamento normal da rede e sinaliza desvios que podem indicar exfiltração | Autoencoder (detecção de anomalias não supervisionada) |
| **Conteúdo** | Identifica dados pessoais em payloads e textos pelo contexto, indo além de padrões fixos | Regex para dados estruturados (CPF, e-mail, telefone) + NLP com BERTimbau |

```
.pcap ──► scapy (features por pacote) ──► Autoencoder ──► score de anomalia ─┐
                                                                             ├──► alerta (LGPD)
payload/texto ──► regex + NLP (BERTimbau) ──► dados pessoais detectados ─────┘
```

A avaliação compara algoritmos tradicionais de detecção de anomalias com deep learning, usando precisão, recall e latência em hardware local.

## Estrutura do repositório

```
.
├── notebooks/
│   ├── 01_test_environment.ipynb        # verificação do ambiente (PyTorch / GPU)
│   └── 02_nlp_lgpd_pii_detection.ipynb  # experimentos de detecção de PII com regex + NLP
├── src/
│   ├── feature_extractor.py  # lê .pcap e extrai features numéricas por pacote para o Autoencoder
│   └── pcap_parser.py        # analisa payloads e detecta dados pessoais (regex + BERTimbau)
├── models/                   # modelos treinados (não versionados)
├── data/raw | data/processed # capturas e datasets (não versionados)
└── requirements.txt
```

**Features extraídas por pacote** (`feature_extractor.py`): intervalo entre pacotes, tamanho do frame, protocolo, portas de origem e destino, flags TCP, tamanho do payload e presença de PII.

## Como executar

```bash
git clone https://github.com/JorgeVieirah/pibiti-pibid-osc.git
cd pibiti-pibid-osc
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# coloque um arquivo .pcap em data/raw/ e extraia as features:
python src/feature_extractor.py
```

> Os dados de rede usados nos testes são capturados em laboratório virtualizado ou vêm de datasets públicos. **Nenhum dado real de OSCs é versionado neste repositório.**

## Cronograma

- [x] Ago–Set/2026 · configuração do laboratório e revisão bibliográfica
- [ ] Out–Nov/2026 · coleta de dados e módulo de NLP *(em andamento)*
- [ ] Dez/2026–Jan/2027 · arquitetura do Autoencoder
- [ ] Fev–Mar/2027 · testes de exfiltração e ajuste de hiperparâmetros
- [ ] Abr–Mai/2027 · análise comparativa entre os modelos
- [ ] Jun–Jul/2027 · relatório final e submissão à Jornada Científica

## Stack

Python · PyTorch · Hugging Face Transformers · scikit-learn · pandas · Scapy · spaCy · Jupyter · Linux

## Contexto ético

A pesquisa não envolve seres humanos nem dados pessoais reais. Os ataques de exfiltração são simulados em ambiente controlado.
