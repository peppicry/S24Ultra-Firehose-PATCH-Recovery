# Investigação complementar: Firehose PATCH no SM-S928B (BIT-6)

Data da investigação: **14/10/2026**. Este documento complementa a investigação
original; não substitui seus códigos, resultados ou conclusões documentadas.

Base examinada: commit `c85be59fd39e595a90199ec4e5e1e9adbe270608`, com 77 arquivos
e árvore `84ce75785315d960053fb06d12d5c0156bae779a`. As análises adicionais
utilizaram os textos publicados, os dumps preservados localmente e fontes
externas. Os binários privados continuam fora do repositório.

A investigação foi exclusivamente de leitura. Não houve novas operações no
aparelho, execução dos clientes históricos de COM/USB, modificação de firmware
ou alteração dos artefatos originais. Os cálculos adicionais foram feitos em
memória, sobre arquivos existentes.

## Critérios de evidência

| Categoria | Significado neste documento |
|---|---|
| **Comprovado no caso** | Sustentado por códigos, registros e bytes preservados; não implica auditoria independente do hardware. |
| **Informação de terceiros** | Observação, código, descompilação ou declaração publicada por outro autor; não reproduzida neste aparelho. |
| **Inferência** | Explicação compatível com as evidências e sua arquitetura, com limites explicitados. |
| **Hipótese** | Causa possível que não foi demonstrada. |
| **Desconhecido** | Informação para a qual faltam artefatos ou observações suficientes. |

Os logs do UnlockTool comprovam o que o aplicativo informou. Eles não são uma
captura da autenticação com o servidor ou do carregamento binário completo.
O boot do Android permanece um relato confirmado do proprietário.

## Resultado principal da pesquisa histórica

A escrita por Firehose `PATCH` como alternativa à escrita comum bloqueada
**já era conhecida antes deste caso**. A Hydra documentou em 2022 um método de
oito bytes por ciclo, condicionado à permissão do loader [R01]. A UMT anunciou
em dezembro de 2023 uma opção de escrita PATCH para reparar pequenas partições
danificadas em aparelhos protegidos [R02]; posteriormente explicou seu uso
quando a escrita comum estivesse bloqueada [R03].

Esses antecedentes sustentam a existência da técnica geral. Não identificam
o programmer do S24 Ultra nem comprovam seus predicados internos de autorização.
O resultado específico deste caso é uma restauração de 8 MiB verificada por
releitura completa, dentro das condições registradas. Não se atribui novidade
universal, CVE ou equivalência com todos os dispositivos Qualcomm.

## 1. PROGRAM recusado e PATCH permitido

### Comprovado no caso

O teste de PROGRAM em blocos solicitou LUN0, setor inicial 188944 e 256 setores
de 4096 bytes. Após um `ACK/rawmode=true`, o alvo informou:

```text
ERROR: Start sector 188944 not allowed for LUN 0 through EDL Flash
```

e retornou `NAK/rawmode=false`. O cliente já havia transmitido o primeiro MiB.
A releitura não correspondeu ao original; uma leitura completa posterior
continuou igual à imagem modificada. Evidências: [E01] e [E02].

PATCH alterou uma palavra diferente no mesmo setor inicial e, depois, outras
palavras de init_boot. As releituras confirmaram as alterações previstas [E03].
A restauração final correspondeu aos 8.388.608 bytes originais [E04].

| Aspecto | PROGRAM histórico | PATCH histórico |
|---|---|---|
| Endereço | LUN, setor inicial e quantidade de setores | LUN, setor, offset e tamanho da alteração |
| Dados | Fluxo binário depois do XML | Valor numérico dentro do XML |
| Extensão solicitada | Imagem de 8 MiB ou bloco de 1 MiB | Oito bytes por comando |
| Resultado | Recusa explícita de endereço | Alterações confirmadas por releitura |

A análise adicional da entrada GPT de init_boot encontrou atributos `0x0`,
sem o bit 60 de somente leitura. Esse atributo não explica a recusa observada.

### Informação de terceiros e inferência

A issue 737 do bkerler/edl, aberta em 31/12/2025, descreve loaders Samsung que
enviam ACK antes de verificações de faixas protegidas. A descompilação publicada
contém a mesma mensagem de recusa [R04]. Ela pertence a outro binário; não é
o código demonstrado do S24. O autor testou um loader e listou outros por
correspondência de strings.

A inferência mais consistente é uma restrição de endereço, estado ou autorização
no caminho PROGRAM que não impediu os PATCH realizados. Clientes públicos também
tratam os comandos separadamente [R05], [R06], mas código do host não comprova
como o programmer implementa suas permissões.

### Hipóteses e desconhecidos

Podem existir regras diferentes de faixa, permissões para operações pequenas
ou diferenças de estado/configuração entre sessões. Não foi demonstrado que
PATCH omitisse uma verificação específica, nem que essa diferença fosse um bug.

O PROGRAM fragmentado que recebeu NAK ocorreu na COM1, assim como os PATCH
bem-sucedidos. As tentativas diretas anteriores ocorreram na COM20.
A coincidência da porta COM não comprova estados internos idênticos entre
sessões. Os banners de build coincidiram, mas não houve hash do binário ativo
ou comparação controlada dos comandos na mesma sessão.
Também não foi testado PROGRAM de um único setor nesse endereço.

Somente valores do original foram enviados por PATCH. Não se demonstrou
autorização irrestrita para valores, endereços ou outros LUNs.

## 2. Identidade do Firehose carregado pelo UnlockTool

### Perfil comprovado pelos registros

| Característica | Valor observado |
|---|---|
| Aplicativo | UnlockTool 2026.09.23.0 |
| Modelo selecionado | SM-S928B, BIT-6 |
| Build anunciada | `Jun 10 2026 @ 14:28:02` |
| Armazenamento configurado | UFS, setores de 4096 bytes |
| Campos de negociação | `Version=1`, `MinVersionSupported=1` |
| Payload máximo suportado anunciado | 1.048.576 bytes |
| Payload negociado nas tentativas diretas | 16.384 bytes |
| Máximo XML anunciado | 4096 bytes |
| Funções anunciadas | 15; incluindo program, read, patch, erase e fixgpt |
| Serial e chip ID do diagnóstico | Zero |

Fontes: NOP [E05], CONFIGURE [E07] e BOOT DEVICE [E09].

O UnlockTool informou autenticação, recuperação de dados do servidor, envio do
programmer e configuração UFS. A quantidade anunciada de dados do servidor não
identifica o tamanho ou conteúdo exato do binário executado.

### Limite de identificação

Não foram preservados o arquivo ativo, seu hash, cadeia de certificados, revisão
do SDK ou conversa completa de carregamento/autorização. `Version=1` não basta
para identificar uma revisão binária. O banner de data não é uma identidade
criptográfica; sua coincidência entre sessões não prova igualdade dos binários.

O candidato público examinado tinha 675.734 bytes, começava com `.rtc` e não
apresentava a assinatura ELF. Não foi carregado [E08]. A ausência de certificados
encontrados naquela inspeção não prova ausência de assinatura em um conteúdo
possivelmente encapsulado. Não há prova de equivalência com o material do
UnlockTool.

**Desconhecido:** nome original, SHA-256, origem exata, revisão interna e eventuais
alterações feitas pelo fornecedor da ferramenta.

## 3. Timeouts após 8.257.536 bytes contabilizados

### Comprovado e cálculo adicional

| Medida | Valor |
|---|---:|
| Imagem completa | 8.388.608 bytes |
| Contador nas duas tentativas | 8.257.536 bytes |
| Diferença pelo contador | 131.072 bytes, ou 128 KiB |
| Payload por chamada | 16.384 bytes |
| Chamadas contabilizadas | 504 |
| Chamadas previstas | 512 |

O contador aumentava somente após retorno de `connection.write()`. A exceção
interrompeu uma chamada posterior. Portanto, o número não comprova quanto chegou
ao armazenamento. Uma chamada que terminou com exceção poderia ter transferido
uma quantidade parcial não contabilizada. Código e resultados: [C01], [E06], [E07].

No pySerial 3.5 para Windows, write utiliza WriteFile/GetOverlappedResult e
lança SerialTimeoutException quando a quantidade concluída é menor que a
solicitada [R07]. Essa conclusão do transporte não comprova persistência na UFS.

As durações calculadas entre os timestamps foram 11,309041 e 39,330392 segundos.
A diferença de 28,021351 segundos é compatível com o aumento de timeout de
dois para 30 segundos descrito no histórico. O segundo resultado registra 30
segundos; a primeira versão completa não foi preservada separadamente.

### Inferência, hipóteses e desconhecido

Aumentar a espera prolongou o bloqueio sem resolver sua causa. Os tamanhos
negociados não indicavam envio acima do máximo anunciado.

A hipótese principal é recusa ou interrupção do consumo pelo alvo enquanto o
cliente transmitia sem acompanhar respostas. O teste posterior de 1 MiB capturou
uma recusa após ACK, mas não existe NAK equivalente preservado nas tentativas
grandes. Problemas de transporte, enquadramento, fluxo ou processamento do
endpoint continuam possíveis.

Um caso externo de recuperação do SM-A525F relata falhas relacionadas a pacotes
XML e ao momento de preparação da recepção USB [R08]. É um contraponto à
inferência automática de proteção a partir de timeout; não explica diretamente
o S24, pois modelo, loader e regiões eram diferentes.

**Desconhecido:** por que o contador repetiu exatamente esse limite. Não se
demonstrou buffer de 128 KiB, proteção dos últimos setores AVB ou gravação
efetiva dos 8.257.536 bytes.

## 4. GPT após o ERASE relatado

### Comparação adicional dos binários preservados

Os dois arquivos tinham 20.480 bytes e hashes correspondentes ao manifesto [E10]:

```text
Antes:  70590d9277fc17c34272eb222b4ca561970ff176b860f0cd70aee5e328a986bf
Depois: 64e4f30f751564c52a96a0523246d2dae044364f52c81c0d6798f4a44858e680
```

| Região, offsets inclusivos | Bytes diferentes |
|---|---:|
| MBR, 0–7 | 8 |
| SizeInLBA da entrada protetora, 458–461 | 4 |
| Setor do header GPT, 4096–8191 | 0 |
| 52 entradas de 128 bytes, 8192–14847 | 0 |
| Área posterior às entradas, no setor 16384–20479 | 1.358 |
| Total | 1.370 |

Os CRCs do header e da matriz permaneceram válidos. A assinatura MBR `55 AA`,
o tipo protetor `0xEE` e o início LBA 1 permaneceram. O tamanho da entrada
protetora passou de **124.888.063 setores para zero**. Os seis dumps posteriores
examinados eram iguais ao arquivo de hash `64e4...e680`.

A UEFI define a cobertura da entrada protetora pelo tamanho do disco [R09].
O valor zero não oferece essa cobertura. Assim, a validade anteriormente
verificada é de header e entradas; não certifica todas as estruturas.
Os 1.358 bytes fora da matriz não são cobertos pelo CRC dessa matriz.

### Cobertura e interpretação

O header declara 52 entradas: 6656 bytes a partir de LBA 2. Os dumps cobrem
LBA 0–4. A reserva mínima da área de entradas, para blocos de 4096 bytes,
estende-se por quatro blocos e é compatível com FirstUsableLBA=6 [R10].
O trecho de LBA 5 e a GPT secundária não foram examinados.

A comparação demonstra uma mudança estável nos bytes devolvidos pelo alvo,
atingindo o MBR e uma região reservada, sem mudar o mapa observado.

Não existe o XML exato do ERASE com LUN, início, quantidade e resposta final.
Operação parcial, manutenção posterior de estruturas ou comportamento do
caminho de leitura são hipóteses, sem prioridade causal comprovada. Não se
afirma que toda a GPT foi apagada e reconstruída, nem que o ERASE não fez nada.
O boot posterior não certifica a integridade do MBR protetor.

### Relato posterior e estado atual

Após a recuperação por PATCH, o proprietário informou ter instalado o firmware
completo da **One UI 8.5 pelo Odin, com configurações padrão**. Trata-se de um
relato do proprietário, posterior aos dumps examinados nesta investigação.

**O estado atual do MBR protetor ainda não foi verificado.** Os resultados da
comparação acima descrevem os artefatos históricos; não demonstram o estado
posterior à instalação pelo Odin nem permitem concluir se ela corrigiu esse MBR.

### Reprodução offline da comparação

O trecho abaixo lê somente duas cópias locais. Não abre COM/USB, não importa
clientes históricos e não grava resultados. Os hashes fixos delimitam os
artefatos deste caso; nenhum binário é acrescentado ao repositório.

Salve ou execute o trecho em seu próprio ambiente offline, fornecendo primeiro
o backup e depois a cópia posterior. Esta inclusão documental não executa o código.

```python
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

paths = [Path(p) for p in sys.argv[1:]]
assert len(paths) == 2 and all(p.is_file() for p in paths)
before, after = [p.read_bytes() for p in paths]
assert len(before) == len(after) == 20480
assert hashlib.sha256(before).hexdigest() == '70590d9277fc17c34272eb222b4ca561970ff176b860f0cd70aee5e328a986bf'
assert hashlib.sha256(after).hexdigest() == '64e4f30f751564c52a96a0523246d2dae044364f52c81c0d6798f4a44858e680'

header = after[4096:8192]
assert header[:8] == b'EFI PART'
header_size, header_crc = struct.unpack_from('<II', header, 12)
entry_lba, count, entry_size, entry_crc = struct.unpack_from('<QIII', header, 72)
assert (header_size, entry_lba, count, entry_size) == (92, 2, 52, 128)
checked_header = bytearray(header[:header_size])
checked_header[16:20] = bytes(4)
assert zlib.crc32(checked_header) & 0xffffffff == header_crc
start = entry_lba * 4096
end = start + count * entry_size
entries = after[start:end]
assert len(entries) == count * entry_size
assert zlib.crc32(entries) & 0xffffffff == entry_crc
assert before[4096:8192] == after[4096:8192]
assert before[start:end] == entries

def differences(lo, hi):
    return sum(x != y for x, y in zip(before[lo:hi], after[lo:hi]))

result = {
    'different_bytes': differences(0, len(after)),
    'mbr_bytes_0_7': differences(0, 8),
    'protective_size_field': differences(458, 462),
    'after_entries': differences(end, len(after)),
    'protective_size_before': struct.unpack_from('<I', before, 458)[0],
    'protective_size_after': struct.unpack_from('<I', after, 458)[0],
}
for i in range(count):
    entry = entries[i * entry_size:(i + 1) * entry_size]
    name = entry[56:128].decode('utf-16le').rstrip(chr(0))
    if name == 'init_boot':
        result['init_boot_attributes'] = hex(struct.unpack_from('<Q', entry, 48)[0])
assert result.get('init_boot_attributes') == '0x0'
assert result['different_bytes'] == 1370
assert result['mbr_bytes_0_7'] == 8
assert result['protective_size_field'] == 4
assert result['after_entries'] == 1358
print(json.dumps(result, indent=2))
```

## 5. Continuidade depois do fechamento do UnlockTool

**Comprovado operacionalmente:** BOOT DEVICE de 10:15:55 informou fechamento da
conexão [E09]. Depois, outro cliente abriu a COM e recebeu NOP/READ/PATCH sem
upload de loader, negociação Sahara ou IPC com o UnlockTool [E05], [C02].

A abertura Windows usada pelo pySerial é exclusiva [R07], [R11]. O acesso
posterior é coerente com liberação do recurso pelo aplicativo. Fechar o handle
do host não equivale a demonstrar reset do alvo.

A inferência arquitetural é que o estado Firehose permaneceu atendendo comandos.
O QDL prevê manter o programmer ativo entre invocações quando não envia reset
[R12]; o bkerler/edl detecta um alvo já em Firehose por resposta XML/NOP [R13].

Devem ser distinguidos autenticação da ferramenta com o servidor, aceitação do
programmer no aparelho e autorização de seus comandos. O cliente próprio não
acrescentava credenciais aos comandos utilizados. Isso não demonstra transferência
de credencial, mecanismo de bypass ou uma flag interna específica.

**Desconhecidos:** localização exata do código em memória, estados de autorização
ativos e eventos que os invalidariam. Não houve inspeção de memória nem captura
do handshake original. Serial/chip ID zero e VID/PID não identificam o binário.

## 6. Antecedentes e alcance da comparação

| Fonte | O que documenta | Limite |
|---|---|---|
| Aleph Security, 2018 [R14] | PROGRAM e PATCH como operações de alteração de armazenamento | Não demonstra a mesma assimetria de permissão |
| Hydra, junho de 2022 [R01] | Escrita PATCH de oito bytes por ciclo, condicionada ao loader | Declaração do fornecedor; não é comparação pareada do S24 |
| UMT QcFire 9.1, dezembro de 2023 [R02] | PATCH para reparar pequenas partições em aparelhos protegidos | Sem código interno dos handlers |
| Resposta posterior da UMT [R03] | Uso de escrita PATCH quando a escrita comum está bloqueada | Sem identidade do programmer ou endereço do S24 |
| bkerler/edl, issue 737 [R04] | ACK antes de verificações e recusa de setores em loader Samsung | Outro binário; análise de terceiros |
| Recuperação do SM-A525F [R08] | Falhas de escrita associadas pelo autor ao transporte/protocolo | Modelo, loader e regiões diferentes |

A declaração da UMT é especialmente próxima da alternativa operacional usada.
Ela é informação primária do fornecedor, não uma reprodução independente de
PROGRAM e PATCH no mesmo endereço do nosso aparelho.

Não existe garantia de que todo Firehose autorize PATCH: o cliente OnePlus
acrescenta atributos de autenticação aos dois comandos quando determinadas
extensões são anunciadas [R15]. Isso demonstra adaptação do cliente ao OEM,
não a implementação interna de permissões de todos esses loaders.

**Conclusão:** a técnica geral e a possibilidade de diferenças de permissão
já eram conhecidas. Nesta pesquisa não foi identificada uma origem verificável
do binário ativo ou um caso anterior pareado desse SM-S928B BIT-6. Ausência de
um caso localizado não prova inexistência de casos anteriores.

Algumas páginas UMT do fórum recusaram acesso integral com HTTP 403; seus
trechos indexados foram consultados. O anúncio também aparece no canal público
do fornecedor [R16]. A entrada Hydra foi conferida no site oficial [R01].
As limitações de acesso e o nível de evidência impedem tratar anúncios como
prova de equivalência entre programmers.

## 7. Limitações dos clientes Python e correções conceituais

| Limitação observada | Correção conceitual, não implementada nesta etapa |
|---|---|
| Streaming PROGRAM sem acompanhar respostas após ACK inicial | Recepção durante o envio, com interrupção ao receber recusa |
| Contador incrementado após write | Separar contabilidade do transporte, conclusão do comando e persistência relida |
| Retorno após o primeiro response | Associar resposta ao comando ativo e impedir uso de respostas residuais |
| Enquadramento por busca de `</data>` | Tratar fragmentação, documentos concatenados e bytes excedentes |
| Mistura potencial de XML e binário | Estados explícitos; consumir o comprimento binário exato de READ |
| Deadline consultado somente antes de chamadas bloqueantes | Limitar cada chamada também pelo tempo restante da operação |
| READ após NAK com payload já transmitido | Considerar dados ainda em trânsito; rawmode=false não prova buffers vazios |
| Últimos 80 eventos e contadores agregados | Contexto, timestamps e checkpoints suficientes para auditar interrupções |

O atalho `_reset_input_buffer = lambda: None` não desativava o purge na abertura
Windows: serialwin32.open chama PurgeComm diretamente [R07]. O comentário
histórico não explica a recuperação. A inspeção do backend instalado também
foi preservada [E12].

O PATCH final usava in_waiting e leituras pequenas para evitar esperar o
timeout de 0,2 segundo até completar 4096 bytes para cada ACK curto [C03].
O comportamento de read com tamanho e timeout está documentado pelo pySerial
[R17]. Não se atribui a permissão de escrita a essa otimização.

O arquivo de parada era consultado entre comandos, seguido de verificação do
setor e da imagem parcial. KeyboardInterrupt não é capturado por except
Exception; uma interrupção abrupta não recebe necessariamente o mesmo registro
de uma parada planejada.

ACK perdido ou timeout não prova que a palavra deixou de ser escrita. A
retomada histórica aceitava somente palavras iguais ao original ou ao backup
conhecido, recusando estados desconhecidos. Oito bytes no XML não comprovam
atomicidade física de oito bytes; falha de energia poderia afetar uma unidade
maior. Não foi medido o caminho de escrita UFS.

As verificações por setor e da imagem completa são pontos fortes do caso.
Elas comprovam o estado relido, sem transformar os clientes em uma implementação
genérica de Firehose. Os snapshots finais também não reconstituem todas as
versões executadas antes. Nenhuma correção de código foi aplicada aqui.

## Perguntas ainda sem resposta

1. Qual era o arquivo ativo do programmer, seu hash e sua cadeia de certificados?
2. Qual predicado rejeitava PROGRAM e qual regra autorizava PATCH?
3. As sessões tinham exatamente a mesma configuração e estado de autorização?
4. Qual resposta ou condição USB ocorreu durante a chamada que terminou em timeout?
5. Qual intervalo, LUN e estado final correspondiam ao ERASE relatado?
6. O que produziu as mudanças do MBR e da área reservada?
7. Qual era o conteúdo da GPT secundária e da área reservada não capturada?

Essas lacunas exigem artefatos que não estão no conjunto examinado. Não foram
substituídas por suposições ou novos testes no aparelho recuperado.

## Evidências do caso e códigos preservados

[E01]: ../evidence/results/fragmented_write_result.json
[E02]: ../evidence/results/current_read_post_fragmented.json
[E03]: ../evidence/results/original_word_patch_result.json
[E04]: ../evidence/results/patch_restore_20261014_115515.json
[E05]: ../evidence/results/firehose_nop_result.json
[E06]: ../evidence/results/direct_write_attempt_1.json
[E07]: ../evidence/results/direct_write_attempt_2.json
[E08]: ../evidence/results/public_loader_offline_inspection.json
[E09]: ../evidence/unlocktool/2026-10-14_10-15-55_BOOT%20DEVICE.txt
[E10]: ../evidence/binary_manifest.json
[E11]: ../evidence/results/pre_write_validation.json
[E12]: ../evidence/reproduction/host_transport_inspection.json
[C01]: ../historical/scripts/restore_init_boot_direct.py.txt
[C02]: ../historical/scripts/read_current_images.py.txt
[C03]: ../historical/scripts/restore_init_boot_patch.py.txt

A contagem original das diferenças e a igualdade de header/entradas estão em
[E11]. A decomposição adicional por offsets neste documento foi recalculada
sobre os binários com hashes de [E10]. Nenhum novo dump foi adquirido.

## Referências externas verificáveis

As referências de código abaixo são fixadas por commit ou tag. Anúncios e
discussões podem mudar ou exigir autenticação; a data de consulta é 14/10/2026.

[R01]: https://www.hydradongle.com/download/software
[R02]: https://forum.gsmhosting.com/vbb/f970/17-12-23-umtv2-umtpro-qcfire-v9-1-samsung-a23-bugfixes-3239252/
[R03]: https://forum.gsmhosting.com/vbb/f970/22-12-23-umtv2-umtpro-qcfire-v9-2-samsung-z-fold5-z-flip-5-more-3240736-print/?pp=50
[R04]: https://github.com/bkerler/edl/issues/737
[R05]: https://github.com/bkerler/edl/blob/1cda1a616748d608667b2d13b73a28d3197ceb45/edlclient/Library/firehose.py#L427-L453
[R06]: https://github.com/linux-msm/qdl/blob/5fb4c342450f531aab311e0f5c2a4f48b91d17b7/src/firehose.c#L1423-L1464
[R07]: https://github.com/pyserial/pyserial/blob/v3.5/serial/serialwin32.py
[R08]: https://github.com/miromraz/a525f-edl-unbrick
[R09]: https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html
[R10]: https://uefi.org/sites/default/files/resources/2_4_Errata_A.pdf
[R11]: https://learn.microsoft.com/en-us/windows/win32/devio/communications-resource-handles
[R12]: https://github.com/linux-msm/qdl/blob/5fb4c342450f531aab311e0f5c2a4f48b91d17b7/src/qdl.c#L878-L883
[R13]: https://github.com/bkerler/edl/blob/1cda1a616748d608667b2d13b73a28d3197ceb45/edlclient/Library/sahara.py#L116-L140
[R14]: https://alephsecurity.com/2018/01/22/qualcomm-edl-2/
[R15]: https://github.com/bkerler/edl/blob/1cda1a616748d608667b2d13b73a28d3197ceb45/edlclient/Library/Modules/oneplus.py#L250-L260
[R16]: https://t.me/s/umtdongle?before=1236
[R17]: https://pyserial.readthedocs.io/en/latest/pyserial_api.html

- [R01]: entrada Hydra V1.0.3.39, 14/06/2022; método PATCH e oito bytes por ciclo.
- [R02], [R03], [R16]: anúncio UMT QcFire 9.1 e explicação posterior da alternativa.
- [R04]: relato e descompilação de terceiros; não pertencem ao binário do S24.
- [R05], [R06], [R12], [R13], [R15]: implementações de clientes do host, não do programmer.
- [R07], [R11], [R17]: contratos e implementação do transporte COM/pySerial.
- [R08]: relato independente do SM-A525F; sua causalidade não foi transferida ao S24.
- [R09], [R10]: formato GPT/MBR e reserva mínima da área de entradas.
- [R14]: antecedente de pesquisa sobre operações de armazenamento Firehose.
