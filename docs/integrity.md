# Integridade e reprodução dos resultados

## Identificação do conteúdo modificado

Em [comparison.json](../evidence/audit/comparison.json):

| Arquivo do ramdisk | Constatação |
|---|---|
| `init` | Original de 3.247.392 bytes substituído por outro de 606.912 bytes |
| `init.real` | Bytes iguais ao `init` original |
| `kernelsu.ko` | Módulo identificado como Android KernelSU |
| `ksu_config` | `bundled=1` |
| `stock_image.sha1` | `4b2728be4bb1a9e880168e5914d0cb63443ed375`, igual ao SHA-1 da referência |

O ramdisk foi inspecionado como Android boot header v4, LZ4 legacy e CPIO. Os códigos desse exame estão em [historical/audit](../historical/audit). Nenhum conteúdo executável extraído foi executado na investigação.

Os campos de versão do header e as propriedades de partições tinham informações diferentes. Não se inferiu a versão global do Android/One UI apenas do campo OS do header de init_boot. A build `S928BXXU6ZZI4` foi lida pelo UnlockTool nas informações de `super`.

## Hash da partição inteira e hash do descritor são diferentes

Os hashes SHA-256 de **8 MiB completos** foram:

| Imagem | SHA-256 |
|---|---|
| Inicial modificada | `f50885fc4354236e230d7d92d281300c903203fc91e6d67b5231c2568b2b11f4` |
| Após uma palavra original | `9d4e7d3468d85994123b521139a15740f629921138abcb33aac6e23c26ca9ca5` |
| Após o lote adicional de 64 | `16012cc9fca0cdac21b40233d385071ab1d6a0649cc81480f73e86c3b9ac9e41` |
| Original e leitura final | `f61c74bab1781862e48f8abc4a8b7865f0ba661658a3807431395edc1ce069c8` |

O descritor AVB raiz de `init_boot` tinha:

```text
algorithm  = sha256
image_size = 1724928
salt       = d7282f8f62d3c7fbc5a98842158e86e177017a5d7bb4309e3f4eed01ee634162
digest     = 8eae2f7ac061f2e012b494fa0bf51c5827bb127572210f737b97ba328a1f3571
```

O cálculo para esse descritor foi:

```python
sha256(salt + image[:1724928])
```

O original produziu o digest esperado. A imagem modificada produziu `ee8badac71af5afe1753a79f513e4fb18a52fe2b99e7ba718b42ad6b3cd2fb85`. Um hash do arquivo completo não deve ser comparado diretamente ao digest salgado de uma extensão menor. [Resultados históricos](../evidence/audit/actual_readback_verification.json).

## Vbmeta raiz e confiança na chave

O vbmeta raiz de 131.072 bytes tinha hash:

```text
07382ae3f7a655b4598f9f82c34dd07a18ff21ee76b235676a3697e882a2e3b4
```

O algoritmo era SHA256_RSA4096, com flags 0. A assinatura interna e o hash do bloco foram verificados. A chave pública embutida tinha SHA-256:

```text
15f66990b32b613508fa9979a5fc70aa37cb3c3d6043e82a998765716d6f5abd
```

Isso verifica consistência criptográfica contra a chave presente no arquivo. **Não verifica, de maneira independente, a origem dessa chave**, sua correspondência com eFuses ou o estado completo de confiança do bootloader.

O novo verificador offline implementa a operação pública RSA e compara exatamente a codificação PKCS#1 v1.5 SHA-256 do algoritmo observado. É específico para SHA256_RSA4096, não um substituto completo do libavb. As verificações originais usavam `cryptography`; a reverificação documental com biblioteca padrão confirmou os mesmos resultados sobre o binário preservado. [Resultado](../evidence/reproduction/offline_verification.json) e [código](../tools/integrity.py).

Não foi preciso alterar flags de vbmeta ou gerar outra assinatura: o procedimento recuperou **todos os bytes da imagem original**, incluindo footer e metadados já existentes nela.

## GPT: o que foi e não foi confirmado

Os dumps selecionados de GPT principal tinham 20.480 bytes. O header em LBA1 e a matriz de entradas apontada por ele passaram nas verificações CRC32. A entrada de init_boot tinha 188944..190991, inclusive, em LUN0/4096 bytes.

Após o ERASE relatado pelo proprietário, header e entradas eram idênticos ao backup anterior. O arquivo completo, porém, diferia em 1370 bytes, incluindo MBR e áreas fora da matriz. A origem dessas diferenças não foi determinada. Não se concluiu que o ERASE não fez nada, nem que apagou todas as estruturas. A GPT reserva não foi lida. [Validação anterior à escrita](../evidence/results/pre_write_validation.json).

O cliente final exigia também a posição conhecida de vbmeta: setores 4244736..4244767, 32 setores. Não gravou GPT nem utilizou ERASE para testar permissões.

## Plano de palavras originais

O plano compara palavras alinhadas de oito bytes. Para cada posição:

- Igual ao original: nenhuma escrita necessária.
- Diferente do original e igual ao backup modificado conhecido: pode entrar no plano do caso.
- Diferente de ambas: interromper, sem substituir silenciosamente dados desconhecidos.

Isso permite retomar o estado parcial conhecido. Não é uma autorização para aceitar imagens arbitrárias do mesmo modelo.

Sobre o backup inicial completo, há **277.635 palavras diferentes** distribuídas em **546 setores distintos**. Depois de restaurar a palavra do primeiro setor e executar o lote de 64, a execução final tinha 277.570 palavras em 545 setores. O lote de 64 e a execução final incluem o mesmo setor do início do ramdisk; os contadores de setores de execuções diferentes não devem ser somados como setores únicos.

O valor inteiro é little-endian e pode ter o bit mais alto definido. O plano offline inclui testes para `2**64-1`, offsets no início/fim de setor, dados desconhecidos, duplicidade e endereços fora da extensão do arquivo. A simulação completa produz exatamente o original.

## Níveis de verificação disponíveis

| Execução offline | Alcance |
|---|---|
| `python tools/verify_evidence.py` | Hashes das cópias sanitizadas e consistência das afirmações nos registros; não reverifica binários ausentes |
| Com `--stock --patched --readback` | SHA-256 reais, igualdade de bytes, descritor registrado e simulação do plano |
| Acrescentando `--vbmeta` | Hash/assinatura internos do binário raiz e comparação do descritor extraído |
| Acrescentando `--gpt` | CRCs reais e limites da entrada de init_boot |

O [manifesto binário](../evidence/binary_manifest.json) registra hashes e tamanhos, mas não contém as imagens. Para reverificação independente dos binários é necessário acesso local aos arquivos correspondentes. Testes com buffers sintéticos verificam propriedades do analisador; não substituem um teste de hardware.
