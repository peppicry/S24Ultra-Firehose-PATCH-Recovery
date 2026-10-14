"""Verify archived evidence and optional local images, offline only."""
import argparse
import json
import pathlib
import sys

try:
    from . import case, integrity
except ImportError:
    import case
    import integrity

REPO = pathlib.Path(__file__).resolve().parents[1]

def load(relative):
    return json.loads((REPO/relative).read_text(encoding='utf-8'))

def require(condition, message):
    if not condition:
        raise ValueError(message)

def verify_archived():
    manifest = load('evidence/source_manifest.json')
    count = 0
    for row in manifest['artifacts']:
        if row['export_path'] is None:
            continue
        target = (REPO/row['export_path']).resolve()
        require(REPO in target.parents, 'manifest path escapes repository')
        data = target.read_bytes()
        require(len(data)==row['export_bytes'] and integrity.sha256(data)==row['export_sha256'],
                'sanitized export changed: '+row['export_path'])
        count += 1
    final = load('evidence/results/patch_restore_20261014_115515.json')
    confirmation = load('evidence/results/restauracao_confirmada.json')
    first = load('evidence/results/original_word_patch_result.json')
    batch = load('evidence/results/patch_restore_20261014_115410.json')
    noop = load('evidence/results/init_boot_patch_probe_result.json')
    rejection = load('evidence/results/fragmented_write_result.json')
    avb = load('evidence/audit/actual_readback_verification.json')
    require(final['full_restoration_confirmed'] and final['readback_sha256']==case.STOCK_SHA256,
            'final readback is not the pinned original')
    require(confirmation['readback_equals_original_byte_for_byte'] and
            confirmation['readback_sha256']==case.STOCK_SHA256, 'final byte comparison missing')
    require(final['confirmed_patch_commands']==277570 and final['verified_sectors']==545,
            'final command/sector counts differ')
    require(batch['confirmed_patch_commands']==64 and batch['readback_matches_planned_state'],
            '64-word proof missing')
    require(first['only_expected_original_word_changed'] and first['changed_data_write_permission_proven'],
            'first changed-word proof missing')
    require(noop['full_image_unchanged'] and not noop['changed_data_write_permission_proven'],
            'identical-value probe incorrectly treated as changed-data proof')
    messages = '\n'.join(e.get('xml','') for e in rejection['events'])
    require('Start sector 188944 not allowed for LUN 0 through EDL Flash' in messages,
            'explicit PROGRAM rejection absent')
    require(rejection['blocks'][0]['final_response']['value']=='NAK', 'PROGRAM NAK absent')
    require(avb['root_vbmeta_signature_valid_against_embedded_key'], 'historical root signature check missing')
    return {'sanitized_exports_verified':count,'recorded_total_original_words':1+64+277570,
            'recorded_full_restoration':True,
            'recorded_android_boot':'owner_report_not_independent_screen_capture',
            'verification_level':'archived_records_only_not_binary_reverification'}

def verify_images(stock_path, patched_path, readback_path, vbmeta_path=None, gpt_path=None):
    stock, patched, readback = [pathlib.Path(p).read_bytes() for p in
                               (stock_path,patched_path,readback_path)]
    require(len(stock)==len(patched)==len(readback)==case.IMAGE_SIZE,'unexpected image size')
    require(integrity.sha256(stock)==case.STOCK_SHA256,'original hash mismatch')
    require(integrity.sha256(patched)==case.PATCHED_SHA256,'patched baseline hash mismatch')
    require(readback==stock,'readback is not byte-identical to original')
    plan=integrity.plan_original_words(stock,patched,patched,case.START_SECTOR)
    require(len(plan)==277635,'unexpected full-baseline word count')
    require(integrity.simulate(patched,plan,case.START_SECTOR)==stock,'offline restoration simulation differs')
    descriptor={'algorithm':'sha256','image_size':case.INIT_DESCRIPTOR_SIZE,
                'salt':case.INIT_SALT,'digest':case.INIT_DIGEST}
    original_check=integrity.verify_image_descriptor(stock,descriptor)
    patched_check=integrity.verify_image_descriptor(patched,descriptor)
    require(original_check['matches'] and not patched_check['matches'], 'descriptor checks differ')
    result={'verification_level':'local_original_binary_inputs',
            'image_bytes':len(readback),'original_sha256':integrity.sha256(stock),
            'patched_sha256':integrity.sha256(patched),'readback_sha256':integrity.sha256(readback),
            'readback_byte_identical_to_original':True,'full_plan_original_words':len(plan),
            'original_matches_recorded_root_descriptor':original_check,
            'patched_matches_recorded_root_descriptor':patched_check,
            'device_access':False,'image_files_modified':False}
    if vbmeta_path:
        root=integrity.inspect_root_vbmeta(pathlib.Path(vbmeta_path).read_bytes())
        require(root['sha256']==case.ROOT_SHA256 and root['hash_valid'] and
            root['signature_valid_against_embedded_key'] and root['embedded_key_sha256']==case.PUBLIC_KEY_SHA256,
            'root vbmeta integrity differs')
        target=[d for d in root['hash_descriptors'] if d['partition']=='init_boot']
        require(len(target)==1 and target[0]['image_size']==case.INIT_DESCRIPTOR_SIZE and
            target[0]['salt']==case.INIT_SALT and target[0]['digest']==case.INIT_DIGEST,
            'actual root init_boot descriptor differs from archived values')
        result['actual_root_vbmeta']={k:v for k,v in root.items() if k!='hash_descriptors'}
        result['independent_samsung_key_authentication']=False
    if gpt_path:
        partitions=integrity.parse_gpt(pathlib.Path(gpt_path).read_bytes())
        require(partitions.get('init_boot')=={'start_sector':case.START_SECTOR,
            'end_sector':case.START_SECTOR+case.SECTOR_COUNT-1,'sector_count':case.SECTOR_COUNT},'GPT target bounds differ')
        result['gpt_header_and_entries_crc_valid']=True
        result['gpt_init_boot']=partitions['init_boot']
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock',type=pathlib.Path)
    p.add_argument('--patched',type=pathlib.Path)
    p.add_argument('--readback',type=pathlib.Path)
    p.add_argument('--vbmeta',type=pathlib.Path)
    p.add_argument('--gpt',type=pathlib.Path)
    p.add_argument('--output',type=pathlib.Path)
    args=p.parse_args()
    supplied=(args.stock,args.patched,args.readback)
    if any(supplied) and not all(supplied):
        p.error('--stock, --patched and --readback must be supplied together')
    if (args.vbmeta or args.gpt) and not all(supplied):
        p.error('--vbmeta/--gpt require the three image arguments')
    try:
        integrity.require_separate_output(args.output,(*supplied,args.vbmeta,args.gpt))
        result={'archived_evidence':verify_archived()}
        if all(supplied):
            result['local_images']=verify_images(*supplied,args.vbmeta,args.gpt)
        text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
        if args.output:
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(text,encoding='utf-8')
        print(text,end='')
        return 0
    except (ValueError,OSError) as error:
        print('Verification failed: '+str(error),file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
