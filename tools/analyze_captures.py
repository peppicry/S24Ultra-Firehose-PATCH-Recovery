"""Summarize saved XML log fields. Does not open COM or USB devices."""
import json
import pathlib
try:
    from .protocol import extract_xml
except ImportError:
    from protocol import extract_xml

def main():
    root=pathlib.Path(__file__).resolve().parents[1]/'evidence/results'
    result=[]
    for path in sorted(root.glob('*.json')):
        data=json.loads(path.read_text(encoding='utf-8'))
        fields=[e['xml'] for key in ('events','last_events') for e in data.get(key,[]) if 'xml' in e]
        if 'received_text' in data:
            fields.append(data['received_text'])
        responses=[]; errors=[]
        for field in fields:
            for xml in extract_xml(field):
                responses.extend(dict(r.attrib) for r in xml.iter('response'))
                errors.extend(node.attrib.get('value','') for node in xml.iter('log')
                    if node.attrib.get('value','').startswith('ERROR:'))
        result.append({'file':path.name,'recorded_status':data.get('status'),
                       'captured_response_count':len(responses),
                       'captured_nak_count':sum(r.get('value')=='NAK' for r in responses),
                       'unique_captured_errors':list(dict.fromkeys(errors)),
                       'responses_are_only_the_persisted_capture_subset':True})
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
