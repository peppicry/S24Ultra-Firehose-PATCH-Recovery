# Samsung S24 Ultra: recuperação de `init_boot` pela sessão Firehose do UnlockTool

Registro técnico de um caso concluído em **14/10/2026**, no **SM-S928B, BIT-6**, build identificada **S928BXXU6ZZI4**. O aparelho apresentava `SECURE CHECK FAIL: init_boot(3)` e estava acessível em Qualcomm 9008/EDL. O comando Firehose `PROGRAM` recusava o início de `init_boot`; o comando `PATCH`, enviado a sessões Firehose preparadas pelo UnlockTool, permitiu restaurar as palavras originais. Os clientes reutilizaram o estado acessível sem carregar outro programmer; a identidade binária entre todas as sessões não foi confirmada. A leitura final dos **8.388.608 bytes** ficou idêntica ao original. O proprietário confirmou que, após reiniciar, abriu o Android.

**Este repositório é um arquivo de investigação e uma reprodução offline.** As ferramentas executáveis analisam arquivos locais. Os clientes históricos que acessavam COM/USB estão arquivados como `.py.txt`, sem serem importados ou executados pelos testes. A preparação deste repositório não enviou comandos ao aparelho.

| Resultado | Evidência |
|---|---|
| Original e leitura final iguais, byte por byte | [Confirmação](evidence/results/restauracao_confirmada.json) e [reverificação offline das imagens preservadas](evidence/reproduction/offline_verification.json) |
| SHA-256 final | `f61c74bab1781862e48f8abc4a8b7865f0ba661658a3807431395edc1ce069c8` |
| Permissão de escrita efetiva por `PATCH` | [Primeira palavra diferente restaurada e relida](evidence/results/original_word_patch_result.json) |
| Execução final | [277.570 comandos, 545 setores conferidos, leitura completa](evidence/results/patch_restore_20261014_115515.json) |
| Android iniciado | Relato do proprietário, registrado na confirmação; não houve captura independente dessa tela pelo cliente Python |

## Navegação

- [Problema, tentativas e linha do tempo](docs/timeline.md)
- [Comunicação com o Firehose carregado pelo UnlockTool](docs/firehose-session.md)
- [Integridade, hashes e plano de restauração](docs/integrity.md)
- [Inventário dos códigos e evidências](docs/archive.md)
- [Fatos, hipóteses e limitações](docs/findings-and-limits.md)
- [Investigação complementar: sete questões, antecedentes e limites](docs/investigacao-complementar.md)
- [Preservação e remoção de informações sensíveis](docs/privacy.md)
- [Referências técnicas](docs/references.md)

## Investigação complementar e verificação posterior

A [investigação complementar](docs/investigacao-complementar.md) reúne as sete questões técnicas, suas fontes e os limites das conclusões. A técnica de escrita PATCH já tinha antecedentes publicados pela Hydra em 2022 e pela UMT em 2023. Esses registros não identificam o binário utilizado neste S24 nem demonstram suas regras internas de autorização. A causa exata dos timeouts permanece desconhecida; o suplemento detalha também as diferenças históricas na GPT e as limitações dos clientes Python.

O PROGRAM fragmentado que recebeu NAK e os PATCH bem-sucedidos ocorreram na **COM1**. As tentativas diretas anteriores ocorreram na COM20. A mesma porta COM não comprova estados internos idênticos entre sessões.

Após a recuperação por PATCH, o proprietário informou ter instalado o firmware completo da **One UI 8.5 pelo Odin, com configurações padrão**. Em **14/10/2026**, forneceu esta saída de uma verificação posterior feita no aparelho:

```text
=== VERIFICACAO GPT / MBR ===
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
init_boot: /dev/block/sda28
Tamanho do setor: 4096
=== SIZE IN LBA ===
Valor esperado: 124888063
Valor encontrado: 124888063
=== TIPO MBR (esperado ee) ===
 ee
=== ASSINATURA MBR (esperado 55 aa) ===
 55 aa
=== CABECALHO GPT (esperado EFI PART) ===
   E   F   I       P   A   R   T
=== RESULTADO SIZE IN LBA ===
OK: campo corresponde ao tamanho esperado.
```

**Evidência fornecida pelo proprietário:** a saída informa `SizeInLBA=124888063`, tipo protetor `0xEE`, assinatura MBR `55 AA` e identificação GPT `EFI PART`. O tamanho informado coincide com o campo do backup histórico anterior ao ERASE relatado, em vez do zero observado nos dumps posteriores daquele período. A declaração do suplemento de que o MBR atual ainda não havia sido verificado descreve o conhecimento anterior a esta nova saída.

Não houve novo acesso ao aparelho por estes clientes. A saída textual não inclui o comando completo, um dump do MBR ou os CRCs do header, da matriz de entradas e da GPT secundária; portanto, não constitui uma validação integral da GPT. A sequência relatada é compatível com o campo ter sido corrigido depois da instalação pelo Odin, mas não demonstra qual operação produziu a correção. Os dumps e resultados históricos continuam preservados.

## 1. Problema inicial e escolha do original

A imagem lida do celular continha alterações de KernelSU: substituição de `init` e inclusão de `init.real`, `kernelsu.ko`, `ksu_config` e `stock_image.sha1`. O `init.real` preservava exatamente o `init` da referência original. O SHA-1 registrado no ramdisk correspondia ao SHA-1 da referência. Esses achados estão na [comparação de ramdisks](evidence/audit/comparison.json).

A referência original também correspondia ao descritor de hash de `init_boot` no **vbmeta raiz lido do próprio aparelho**. A imagem modificada não correspondia. A assinatura interna do vbmeta foi verificada contra a chave embutida; isso não constitui autenticação independente dessa chave como uma chave oficial Samsung. [Verificação do par real](evidence/audit/actual_readback_verification.json).

Uma comparação inicial confundiu uma cópia local do pacote original com uma leitura posterior à gravação. Essa inferência foi retirada. Os resultados conclusivos passaram a exigir **origem READ real**, extensão completa, confirmação do protocolo e comparação dos bytes. [Leitura das 22:03](evidence/audit/comparacao_pos_write_22-03.json).

## 2. Como o Firehose do UnlockTool ficou acessível

A sequência observada foi:

```mermaid
sequenceDiagram
    participant U as UnlockTool
    participant W as Windows / qcusbser / COM
    participant T as Aparelho em EDL / Firehose
    participant P as Cliente Python
    U->>T: BOOT DEVICE / Auth Flash
    U->>T: Carregar programmer e configurar UFS
    U->>T: Ler tabela e informações do software
    U->>W: Closing connection... OK
    Note over T: Estado Firehose segue respondendo
    P->>W: Abrir a porta COM selecionada
    P->>T: XML NOP
    T-->>P: Logs de build/funções + ACK, rawmode=false
    P->>T: READ de GPT, init_boot e vbmeta
    T-->>P: ACK true + bytes exatos + ACK false
    P->>T: PATCH de palavras do original em init_boot
    T-->>P: ACK false; READ confirma os bytes
```

O [log de BOOT DEVICE das 10:15:55](evidence/unlocktool/2026-10-14_10-15-55_BOOT%20DEVICE.txt) registra autenticação, carregamento do programmer, configuração, leitura e **fechamento da conexão**. Depois, o [NOP das 10:18:29](evidence/results/firehose_nop_result.json) enviado por outro cliente recebeu XML Firehose na mesma COM20.

O cliente Python utilizou **pySerial 3.5**, diretamente sobre a COM exposta pelo driver `qcusbser`. Não chamou uma API do UnlockTool, não injetou código no processo e não carregou outro programmer. O papel do UnlockTool foi preparar a sessão do alvo. Os scripts reutilizaram o estado já acessível e ficaram com a porta enquanto executavam suas operações. A interface do UnlockTool podia permanecer aberta, sem operar a conexão.

**Fechar o handle do Windows e reiniciar o alvo são acontecimentos diferentes.** A continuidade do protocolo é demonstrada pelas respostas; a localização exata do código em RAM e os detalhes internos da autenticação não foram medidos. O transporte USB físico e seus endpoints também não foram capturados na via COM bem-sucedida. Veja a [análise completa da sessão](docs/firehose-session.md), incluindo acesso exclusivo à COM e a correção sobre `PurgeComm`.

## 3. Por que as primeiras tentativas não comprovaram gravação

Os envios via UnlockTool chegavam a 100% e terminavam em `FAIL`, em aproximadamente 7,2 segundos. Duas tentativas COM diretas de envio de 8 MiB terminaram por timeout depois de **8.257.536 bytes contabilizados pelo cliente após chamadas write concluídas**, sem ACK final. Esse contador não mede a persistência na UFS nem inclui uma eventual transferência parcial da chamada que terminou com exceção. As leituras após novas sessões continuaram iguais à imagem modificada.

O teste de `PROGRAM` em blocos de 1 MiB finalmente capturou:

```text
ERROR: Start sector 188944 not allowed for LUN 0 through EDL Flash
<response value="NAK" rawmode="false" />
```

Esse retorno ocorreu **depois** de um ACK inicial com `rawmode=true`. O ACK inicial não garantia autorização final nem persistência. O cliente desse teste ainda transmitiu o primeiro MiB antes de consumir a recusa; surgiram erros de parsing XML posteriores. A releitura completa confirmou ausência de alteração. [Log integral sanitizado](evidence/results/fragmented_write_result.json).

Isso comprovava recusa de `PROGRAM` no endereço, e não bloqueio universal de escrita. A causa exata dos timeouts anteriores continua uma hipótese: não foi capturado neles um NAK equivalente.

## 4. Descoberta e validação de `PATCH`

O NOP anunciou `patch` entre as funções suportadas. A investigação testou a operação de maneira incremental:

1. **Valor já igual:** escrever os oito bytes `ANDROID!` existentes no início de `init_boot`. ACK e imagem inalterada demonstraram aceitação do comando, mas não escrita efetiva de dados diferentes.
2. **Uma palavra diferente:** restaurar oito bytes do original no offset 8, incluindo o tamanho do ramdisk. ACK e releitura dos 8 MiB confirmaram exatamente essa alteração e nenhuma outra.
3. **Lote de 64 palavras:** restaurar um conjunto limitado de diferenças e conferir o setor e a imagem completa.
4. **Restante:** aplicar 277.570 palavras originais, verificar cada setor modificado e reler a partição inteira.

O aviso `DEBUG: patch command is deprecated.` apareceu mesmo quando a escrita funcionou. A conclusão veio da comparação dos bytes relidos, e não do aviso nem do ACK isolado.

Exemplo histórico do segundo teste:

```xml
<data>
  <patch SECTOR_SIZE_IN_BYTES="4096" byte_offset="8" filename="DISK"
         physical_partition_number="0" size_in_bytes="8"
         start_sector="188944" value="7373724407824384" />
</data>
```

O valor é `int.from_bytes(bytes.fromhex("000000005d321a00"), "little")`. Não é um valor universal para outros arquivos.

## 5. Procedimento histórico que concluiu a recuperação

Os limites foram retirados da GPT atual e verificados antes de escrever:

| Parâmetro | Valor observado |
|---|---:|
| LUN | 0 |
| Bytes por setor | 4096 |
| Setor inicial de `init_boot` | 188944 |
| Setor final, inclusive | 190991 |
| Quantidade de setores | 2048 |
| Bytes da partição | 8388608 |

Para cada palavra diferente, alinhada em oito bytes:

```python
sector = 188944 + image_offset // 4096
byte_offset = image_offset % 4096
value = int.from_bytes(original[image_offset:image_offset + 8], "little")
```

O cliente histórico exigia os hashes fixos do original e do backup modificado, GPT válida, vbmeta raiz correspondente e validação AVB anterior. O estado atual precisava ser uma mistura verificável das palavras do original e do backup conhecido. Uma palavra desconhecida causaria interrupção.

O plano inteiro foi simulado em memória e precisava resultar exatamente no original. Cada `PATCH` era limitado a `init_boot`, com valor retirado da posição correspondente do original, tamanho de oito bytes e resposta ACK/`rawmode=false`. Após cada setor modificado, o cliente comparava um READ de 4096 bytes com o estado planejado. Finalmente comparava os 8 MiB completos.

Foram restauradas **277.635 palavras**: uma no teste efetivo, 64 no lote limitado e 277.570 na execução final. A execução final durou **386,247 segundos**, das 11:55:15 às 12:01:41, incluindo leituras e verificações. `patch_command_seconds=326.431` mede somente o tempo acumulado de comandos PATCH. Os horários dos artefatos têm offset UTC+02, compatível com Europe/Berlin nessa data.

Somente `init_boot` foi escrito pelos clientes de restauração. A intervenção anterior do proprietário em `gpt_main0` é documentada separadamente; não houve restauração de GPT por estes clientes.

## 6. Reprodução offline, sem aparelho

Requer Python **3.9 ou posterior**, apenas biblioteca padrão. Não precisa de pySerial, driver USB, UnlockTool, acesso administrativo nem firmware para verificar a consistência do arquivo de evidências.

```text
python -m unittest discover -s tests -v
python tools/verify_evidence.py
python tools/analyze_captures.py
python tools/verify_publication.py
```

Para reverificar os binários preservados localmente, forneça seus próprios caminhos. Os binários não estão no Git:

```text
python tools/verify_evidence.py --stock <ORIGINAL.img> --patched <BACKUP_MODIFICADO.img> --readback <LEITURA_FINAL.img> --vbmeta <VBMETA_RAIZ.bin> --gpt <GPT_ATUAL.bin> --output offline-output/verificacao.json
```

Esse comando recalcula os hashes, compara os bytes, verifica o descritor de hash e a assinatura interna RSA4096 do vbmeta, valida CRCs da GPT e simula o plano completo. A assinatura é validada contra a chave embutida, sem certificar sua origem Samsung. A opção de saída recusa o próprio arquivo de entrada.

Para estudar o plano, sem transmitir qualquer comando:

```text
python tools/build_patch_plan.py --stock <ORIGINAL.img> --current <IMAGEM_ATUAL_SALVA.img> --baseline <BACKUP_MODIFICADO.img>
```

O resultado é informação em memória/JSON. Não existe cliente de escrita executável nessa interface. Os [snapshots históricos](historical/scripts/restore_init_boot_patch.py.txt) permitem estudar a implementação real, mas dependiam do layout privado de arquivos, da sessão e do alvo específicos. A reprodução em outro aparelho não foi demonstrada.

## 7. Preservação e limites do registro

- Os originais locais foram mantidos e seus hashes conferidos após a exportação. As cópias aqui foram sanitizadas; seus hashes são registrados separadamente em [source_manifest.json](evidence/source_manifest.json).
- Firmware, loaders, dumps de GPT/partições, ramdisk e fotos não foram enviados ao repositório. [binary_manifest.json](evidence/binary_manifest.json) conserva tamanhos e hashes dos binários relevantes.
- Foram removidos caminhos pessoais e campos de hexadecimal bruto/processos. Logs HTML do UnlockTool viraram texto. Os números COM1/COM20 são rótulos efêmeros da sessão, mantidos por relevância técnica.
- Os arquivos `.py.txt` são **snapshots finais preservados**, não uma reconstrução exata de todas as versões executadas antes. Por exemplo, timeout e controles seriais mudaram ao longo dos testes; a primeira versão completa não foi retida separadamente.
- O cliente final manteve apenas os últimos 80 eventos e contadores agregados. Não existe aqui um transcript completo dos 277.570 ACKs ou captura USB bruta.
- A inicialização do Android é um relato do proprietário. A igualdade dos bytes e as verificações criptográficas têm evidências em arquivos e foram repetidas offline.
- Não se verificaram integralmente todas as partições, a GPT reserva, eFuses, Knox, anti-rollback ou a política interna do programmer.

Consulte [fatos e hipóteses](docs/findings-and-limits.md) antes de extrapolar o resultado. O caso demonstra uma diferença observada entre `PROGRAM` e `PATCH` nesse ambiente; não demonstra uma solução universal para Samsung nem identifica um CVE.
