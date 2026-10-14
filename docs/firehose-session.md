# Acesso ao Firehose carregado pelo UnlockTool

## O que foi demonstrado

A comunicação bem-sucedida foi **cliente Python → porta COM do Windows → driver Qualcomm → alvo em estado Firehose**. Não foi uma comunicação Python → UnlockTool → alvo.

As peças observáveis são:

1. [BOOT DEVICE, 10:15:55](../evidence/unlocktool/2026-10-14_10-15-55_BOOT%20DEVICE.txt): `Authenticating... OK`, `Writing flash programmer... OK`, configuração UFS, leitura da tabela e `Closing connection... OK`.
2. [NOP, 10:18:29](../evidence/results/firehose_nop_result.json): o cliente próprio abriu COM20 e recebeu uma resposta XML ACK/`rawmode=false`, a build `Jun 10 2026 @ 14:28:02` e uma lista de 15 funções.
3. [Leitura direta posterior](../evidence/results/current_read_post_fragmented.json): GPT com CRCs válidos, `init_boot` com hash conhecido e vbmeta raiz conhecido. Isso vincula o canal ao conjunto de dados do aparelho investigado.
4. [Primeiro PATCH com dados diferentes](../evidence/results/original_word_patch_result.json): a releitura de 8 MiB mudou exatamente a palavra prevista.
5. [Leitura final](../evidence/results/patch_restore_20261014_115515.json): hash do original e igualdade de bytes. O proprietário depois relatou a abertura do Android.

Não houve captura do binário que o UnlockTool carregou, do handshake completo Sahara ou da autenticação de servidor. O identificador de build recebido por NOP é uma string de diagnóstico, não um hash ou uma prova criptográfica da identidade do loader.

## Preparação pelo UnlockTool e transição de cliente

O proprietário executou BOOT DEVICE e aguardou a lista de partições. O log registra `Auth Flash`, recuperação de dados do servidor de aproximadamente 697,9 KiB, upload do programmer, conexão ao programmer e configuração UFS. A natureza completa daquele pacote e da autenticação não foi analisada. O cliente próprio não reutilizou credenciais nem enviou pedidos ao servidor.

O fechamento da conexão pelo UnlockTool liberou o recurso do host. A outra abertura do mesmo canal conseguiu conversar com o estado Firehose já existente. **A continuidade desse estado entre clientes é fato observado.** A explicação usual — programmer executando em memória do alvo até reinício — é consistente com a arquitetura EDL, mas sua localização/vida útil exata não foi instrumentada neste aparelho.

O [FLASH anterior de 20:49:00](../evidence/unlocktool/2026-10-13_20-49-00_FLASH.txt) também mostra um fallback: `Writing flash programmer... FAIL`, `[Sahara] Unknown command!`, seguido por tentativa de conexão Firehose e sucesso. Esse log isolado não comprova causa para toda falha Sahara, mas sustenta que **detecção de modo importa**: um alvo já em Firehose não deve ser tratado automaticamente como um novo handshake Sahara.

O UnlockTool podia ficar aberto como interface. Não se executavam operações nele enquanto o cliente Python detinha a COM. Não foram fechados handles à força, duplicados handles de outro processo ou instalados mecanismos de compartilhamento de USB.

## Transporte Windows

O log do UnlockTool identifica `qcusbser`, Qualcomm Incorporated, versão `2.1.1.0`. O cliente usou pySerial **3.5** e conferiu `VID=0x05C6`, `PID=0x9008` no registro da porta escolhida. COM20 foi usada antes; COM1 foi usada depois da reconexão. O nome COM é uma atribuição do host, não uma identidade permanente do telefone.

O backend Windows abre a COM com `CreateFile`, leitura/escrita, acesso exclusivo, `OPEN_EXISTING` e I/O overlapped. Outro processo que ainda detenha acesso incompatível pode impedir essa abertura. Isso explica a necessidade operacional de um único cliente ativo. Não é uma API do aplicativo preparador. [Contrato Win32 para recursos de comunicação](https://learn.microsoft.com/en-us/windows/win32/devio/communications-resource-handles).

A abertura COM bem-sucedida não prova que permissões de todos os comandos Firehose são iguais. A validação de endereço para `PROGRAM` ocorreu no alvo, depois que a COM já funcionava e READ tinha sucesso.

Também são categorias distintas uma falha de abertura no host e uma resposta NAK do alvo. As primeiras restrições de acesso encontradas no ambiente de execução não provaram que a COM estivesse ocupada. O acesso posteriormente permitido não é, por si, prova de necessidade de administrador do Windows ou de mudança no driver. Não se atribui a recuperação à desativação de proteções do sistema.

Os parâmetros finais do código histórico eram:

| Parâmetro | Valor |
|---|---|
| `baudrate` | 115200 |
| `timeout` | 0,2 segundo |
| `write_timeout` da base | 2 segundos |
| `xonxoff` | False |
| `rtscts` / `dsrdtr` | True / True na versão final |

Os primeiros probes utilizavam `rtscts=False`, `dsrdtr=False`. As tentativas grandes mudaram também os timeouts. Não se fez um experimento isolando o efeito de cada parâmetro. Portanto, não se atribui a recuperação aos controles seriais.

`115200` é o parâmetro solicitado ao driver. Não medimos uma UART física nem concluímos que os dados USB estavam limitados a essa taxa. A via COM não expôs ao nosso código os números dos endpoints USB. O texto de velocidade no log do UnlockTool não substitui uma captura do barramento.

## Correção: a intenção de preservar o buffer não se realizou como descrita

Nos scripts aparece:

```python
connection._reset_input_buffer = lambda: None
connection.open()
```

O comentário dizia preservar dados já enfileirados. A inspeção posterior do **backend Windows efetivamente instalado** mostrou que `open()` chama `win32.PurgeComm` diretamente. A função privada atribuída acima não é chamada naquele caminho. Assim, a atribuição **não desativa o purge de abertura no Windows**. [Implementação pySerial v3.5](https://github.com/pyserial/pyserial/blob/v3.5/serial/serialwin32.py).

O arquivo local inspecionado tinha SHA-256 `17681ea9a650120c71db1aae9b8881301a40d38c47b34bb0da050e3f5bfbbe00`. A inspeção foi feita offline, por leitura do módulo instalado, sem abrir portas.

O [resultado estruturado dessa inspeção](../evidence/reproduction/host_transport_inspection.json) registra presença de `CreateFile`, exclusividade, chamada direta a `PurgeComm` e ausência de uso do hook atribuído em `open()`.

Consequências para interpretar o caso:

- A ausência de bytes espontâneos no probe passivo não certifica o modo do alvo nem prova preservação de um Sahara Hello anterior.
- O que certificou estado XML acessível foi o **NOP solicitado e seu ACK**.
- A recuperação funcionou apesar da suposição incorreta sobre a limpeza de abertura.
- Não se apresenta esse monkey patch como técnica de acesso ao Firehose.

## Camada de protocolo: XML mais dados brutos

O protocolo observado é um fluxo de bytes. Uma leitura do host pode conter parte de um XML, vários documentos XML concatenados ou a resposta XML seguida de bytes da partição. O tamanho de uma chamada `read()` não delimita mensagens do protocolo.

O [cliente histórico](../historical/scripts/read_current_images.py.txt) conserva um `bytearray` entre chamadas, encontra o fechamento literal `</data>`, extrai um documento XML e mantém os bytes seguintes. Documentos com apenas `<log>` são consumidos até surgir `<response>`.

### NOP

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<data><nop /></data>
```

Os logs retornados incluíram `program`, `read`, `nop`, `patch`, `configure` e outras funções. A resposta de estado exigida foi:

```xml
<data><response value="ACK" rawmode="false" /></data>
```

A lista de funções não certifica que cada uma está autorizada para todos os endereços. O diagnóstico de chip retornou zero; dele não extraímos um HWID, serial de aparelho ou certificado Sahara confiável.

### READ

O fluxo bem-sucedido de leitura foi:

```text
host: XML <read ... num_partition_sectors="N" ... />
alvo: ACK, rawmode=true
alvo: exatamente N * 4096 bytes
alvo: ACK, rawmode=false
```

Enquanto lê bytes de firmware, o cliente usa **contagem exata**. Não procura strings XML dentro deles. Os bytes podem conter `</data>` sem que isso seja uma resposta. Só depois de consumir o tamanho anunciado ele volta à análise de XML.

O arquivo era considerado uma leitura confirmada apenas após receber o tamanho completo e o ACK final. Incompletos/sem confirmação eram preservados como `.partial` ou `.unconfirmed` quando o caminho de código correspondente era alcançado. Os arquivos binários permanecem locais.

### PROGRAM e a recusa assíncrona

No teste de 1 MiB, a ordem **capturada** foi:

```text
host: <program ... start_sector="188944" num_partition_sectors="256" />
alvo: INFO: Calling handler for program
alvo: ACK, rawmode=true
alvo: INFO: start_sector=188944, num_sectors=256
alvo: ERROR: Start sector 188944 not allowed for LUN 0 through EDL Flash
alvo: NAK, rawmode=false
```

O escritor antigo começou a enviar bytes após o primeiro ACK e só consumiu o restante dos logs ao final. Isso produziu mensagens de parsing XML posteriores à recusa. **Isso é uma limitação daquele cliente.** Ele não deve ser tomado como uma implementação geral robusta de streaming PROGRAM. A ordem do XML está no [registro](../evidence/results/fragmented_write_result.json); não se dispõe de captura USB simultânea que date cada byte de payload.

Para as duas tentativas grandes, só há ACK inicial, contador do host e timeout. A hipótese de que a mesma recusa causou seus timeouts é plausível, mas o NAK não foi capturado nelas.

### PATCH

PATCH envia endereço/deslocamento/tamanho/valor no XML e não enviou um payload bruto separado no caso observado. As palavras usaram `filename="DISK"`, tamanho 8 e valor decimal little-endian. Cada comando exigia ACK/`rawmode=false` antes do próximo. Uma releitura independente verificava a persistência.

O tamanho de oito bytes é uma operação lógica do protocolo. Não se mediram a granularidade física da escrita UFS, seu mecanismo interno de read-modify-write ou a atomicidade em caso de queda de energia.

A primeira prova efetiva mudou `00000000acdb2100` para `000000005d321a00` no offset 8. O corpo inteiro relido correspondeu exatamente à imagem anterior com essa única palavra substituída. O ACK sozinho não foi usado como prova.

**Observação estabelecida:** `PROGRAM` recusou aquele endereço e `PATCH` conseguiu escrever nele. **Não estabelecido:** quais condições internas, regras de proteção ou intenção de design produziram essa diferença. Não se modificou o programmer nem sua política em RAM.

## Otimização que tornou o envio viável

A primeira rotina XML chamava `read(4096)` mesmo para uma resposta pequena. Com timeout de 0,2 s, isso podia esperar para completar um buffer de 4096 bytes em cada comando. O cliente final passou a ler um byte quando nada estava enfileirado e a consumir apenas `in_waiting` quando havia dados.

Isso alterou a espera do **host**, preservando enquadramento e critérios de confirmação. O lote de 64 comandos teve `patch_command_seconds=0.094`; a execução final registrou `326.431` segundos de comandos. Esses são tempos do cliente, não uma medição isolada de latência da UFS.

Cada setor alterado foi relido. O último resultado persistiu contadores agregados e uma fila limitada aos últimos 80 eventos. Ele não persistiu cada resposta individual do envio completo.

## Sessões incertas e alternativa USB descartada

Após timeout com estado raw incerto, o cliente parava e não enviava novas consultas naquela sessão. O proprietário reiniciava fisicamente, retornava ao EDL e concluía BOOT DEVICE antes de continuar. Uma COM ainda enumerada não comprova que o protocolo esteja pronto para XML.

Uma alternativa com UsbDk/libusb foi investigada, mas não produziu a restauração. O log salvo [usb_debug_read.log](../evidence/transport/usb_debug_read.log) registra uma tentativa sem exatamente um dispositivo Qualcomm compatível e interrupção antes das operações de partição. Outros detalhes dessa fase vêm do registro narrativo da investigação, não de uma captura completa persistida. O erro temporário de enumeração USB/Code 43 não permite atribuir causa definitiva à biblioteca, ao cabo ou ao aparelho.

O sucesso final veio de **COM + pySerial + Firehose já preparado + PATCH**, não desse transporte alternativo.
