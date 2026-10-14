"""Verify the published text snapshot, offline only."""
import hashlib
import json
import pathlib

def main():
    root=pathlib.Path(__file__).resolve().parents[1]
    manifest=json.loads((root/'evidence/publication_manifest.json').read_text(encoding='utf-8'))
    for row in manifest['files']:
        path=(root/row['path']).resolve()
        if root not in path.parents:
            raise ValueError('manifest path outside repository')
        data=path.read_bytes()
        if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:
            raise ValueError('published file changed: '+row['path'])
    print(json.dumps({'offline_only':True,'publication_files_verified':len(manifest['files'])},indent=2))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
