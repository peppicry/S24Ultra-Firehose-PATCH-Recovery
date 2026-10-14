# Organização do arquivo de investigação

## Estrutura

```text
README.md                         síntese técnica e procedimento observado
docs/                             explicação detalhada e limites
historical/scripts/*.py.txt        snapshots dos clientes/probes do caso
historical/audit/*.py.txt          inspeção AVB/CPIO e empacotamento
historical/config/*.xml.txt        configuração de restauração histórica
historical/reports/                relatórios anteriores, com seu contexto temporal
evidence/results/                 resultados diretos de protocolo e restauração
evidence/audit/                   inspeções de imagens e comparações
evidence/unlocktool/               logs HTML convertidos em texto
evidence/transport/                log persistido da tentativa UsbDk
evidence/reproduction/             resultados da análise offline documental
evidence/source_manifest.json      hashes dos originais e das cópias sanitizadas
evidence/binary_manifest.json      hashes dos binários preservados localmente
tools/                            ferramentas executáveis exclusivamente offline
tests/                            testes de enquadramento, integridade e limites
```

## Clientes e probes históricos

| Código em `historical/scripts` | Papel |
|---|---|
| `observe_protocol.py.txt` | Observação passiva da COM; ausência de bytes não certifica modo |
| `probe_firehose_nop.py.txt` | NOP solicitado, detecção de resposta e funções |
| `read_current_images.py.txt` | NOP, READ de GPT/init_boot/vbmeta e verificação da GPT |
| `restore_init_boot_direct.py.txt` | Tentativas PROGRAM de imagem inteira que falharam |
| `restore_init_boot_fragmented.py.txt` | Teste em blocos que capturou a recusa explícita |
| `probe_init_boot_patch.py.txt` | PATCH de valor já igual, sem prova de mudança |
| `probe_original_word_patch.py.txt` | Primeiro teste de palavra original diferente |
| `restore_init_boot_patch.py.txt` | Cliente que concluiu a restauração por palavras, setores e leitura completa |
| `usb_firehose_client.py.txt` | Alternativa USB investigada, sem escrita bem-sucedida |
| `inspect_public_loader.py.txt` | Inspeção offline do candidato público; não o carregou |

Os arquivos são código-fonte arquivado como texto, não executáveis incluídos num caminho de importação. Preservam a implementação final salvo remoção de caminhos pessoais e normalização de newline. Seus imports e caminhos relativos dependiam do layout privado da investigação. Renomear um deles não basta para transformar o repositório em um pacote de flash genérico.

Os snapshots finais não provam cada configuração de versões anteriores. A versão final do leitor tem RTS/CTS e DSR/DTR habilitados; os primeiros probes não tinham. O escritor direto final tem timeout de escrita maior que o primeiro teste. As diferenças conhecidas são documentadas sem inventar uma versão completa que não foi conservada.

## Auditoria e empacotamento

`historical/audit` conserva o código de LZ4 legacy/CPIO/AVB, comparação de ramdisks, pares de imagem/vbmeta e conferência de outras imagens. `package_restore.py.txt` gerou o pacote rawprogram de uma partição; `package_odin.py.txt` produziu uma alternativa TAR que não foi a solução usada.

Não há biblioteca vendorizada, DLL, executável de UnlockTool, programmer, firmware ou ramdisk no repositório. Os históricos de auditoria dependiam de `cryptography`; os novos utilitários offline usam apenas biblioteca padrão.

## Resultados que exigem leitura no contexto

- `current_read_post_fragmented.json` corresponde às **11:29**, quando a imagem ainda estava modificada. Não descreve o estado depois do PATCH final.
- `diagnostico-program-recusado-11-29.txt` precede a descoberta de PATCH. Sua conclusão sobre restrição do Firehose atual foi refinada posteriormente para a **recusa observada do comando PROGRAM**.
- `init_boot_patch_probe_result.json` não demonstra escrita de dados diferentes.
- `patch_restore_20261014_115410.json` é restauração parcial, não sucesso final.
- `patch_restore_20261014_115515.json` é o sucesso final; `remaining_original_words` é o contador pendente inicial da execução.
- `restauracao_confirmada.json` distingue igualdade de bytes e relato de boot do proprietário.
- `public_loader_offline_inspection.json` descreve arquivo baixado apenas para inspeção; não é o Firehose que restaurou o aparelho.

## Como verificar as cópias

O manifesto contém `source_sha256` dos bytes originais locais e `export_sha256` das cópias sanitizadas. Eles podem diferir por caminhos removidos, formato JSON/newlines, campos omitidos ou conversão HTML → texto. Não se apresenta uma cópia sanitizada como byte-idêntica ao original bruto.

Os utilitários verificam os exports pela coluna `export_sha256`. A preservação dos originais foi conferida separadamente, lendo os arquivos locais selecionados e comparando com `source_sha256`, sem publicá-los. O mapa de caminhos privados usado nessa checagem permanece fora deste repositório.

As novas análises em `evidence/reproduction` são resultados offline produzidos na documentação, não operações novas no aparelho. `capture_summary.json` conta apenas as respostas persistidas nos arquivos, e não todos os ACKs que ocorreram na execução.

[publication_manifest.json](../evidence/publication_manifest.json) registra tamanho e SHA-256 de todos os arquivos textuais dessa entrega, exceto o próprio manifesto. `tools/verify_publication.py` permite conferir esse snapshot offline.
