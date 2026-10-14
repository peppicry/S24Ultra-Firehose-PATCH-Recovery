"""Build an offline data-only word plan. No commands are sent to a device."""
import argparse
import json
import pathlib
try:
    from . import case, integrity
except ImportError:
    import case
    import integrity

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock',type=pathlib.Path,required=True)
    p.add_argument('--current',type=pathlib.Path,required=True)
    p.add_argument('--baseline',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path)
    args=p.parse_args()
    integrity.require_separate_output(args.output,(args.stock,args.current,args.baseline))
    stock,current,baseline=[path.read_bytes() for path in (args.stock,args.current,args.baseline)]
    if len(stock)!=case.IMAGE_SIZE or integrity.sha256(stock)!=case.STOCK_SHA256 or integrity.sha256(baseline)!=case.PATCHED_SHA256:
        p.error('inputs do not match the original and baseline from this case')
    plan=integrity.plan_original_words(stock,current,baseline,case.START_SECTOR)
    if integrity.simulate(current,plan,case.START_SECTOR)!=stock:
        p.error('planned state does not equal the original')
    summary={'offline_only':True,'word_count':len(plan),
        'modified_sector_count':len({r['start_sector'] for r in plan}),
        'result_sha256':case.STOCK_SHA256,'result_byte_identical_to_original':True,
        'first_word':plan[0] if plan else None,'last_word':plan[-1] if plan else None}
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps({'summary':summary,'words':plan},indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
