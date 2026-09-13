"""Package only the completed v4 experiment, docs, reproducible code and report."""
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/v4'
DATA=ROOT/'results/v4'


def package():
    meta=json.loads((DATA/'metadata.json').read_text())
    audit=json.loads((DATA/'verification.json').read_text())
    tests=json.loads((DATA/'tests.json').read_text())
    report=json.loads((OUT/'report-data.json').read_text())
    analysis=json.loads((OUT/'analysis.json').read_text())
    if not (meta['status']=='complete' and audit['status']=='PASS' and audit['full_replay'] and
            audit['total_rows_checked']==meta['total_trials'] and tests['status']=='PASS' and
            report['total_trials']==meta['total_trials'] and report['verification']==audit and
            report['tests']==tests and report['version']==meta['version']):
        raise ValueError('Incomplete or stale validation')
    for name,value in meta['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=value: raise ValueError('Source drift: '+name)
    for name,value in analysis['input_sha256'].items():
        if hashlib.sha256((DATA/name).read_bytes()).hexdigest()!=value: raise ValueError('Analysis drift: '+name)
    paths=[ROOT/'LICENSE',ROOT/'pyproject.toml',ROOT/'docs/V4_EXPERIMENT_SPEC.md',ROOT/'docs/V4_VALIDATION.md']
    paths.extend(p for directory in (ROOT/'src',ROOT/'tests') for p in directory.rglob('*.py'))
    paths.extend(ROOT/'scripts'/name for name in ('run_budget_study.py','verify_budget_results.py',
        'analyze_budget_results.py','build_budget_brief.py','package_budget_artifact.py','run_checks.py','verify_results.py'))
    paths.extend(p for p in DATA.iterdir() if p.is_file())
    paths.extend(OUT/name for name in ('README.md','GoblinTrap-v4-technical-brief.pdf','technical-notes.md',
        'budget-comparison.svg','fixed-signal-effects.csv','budget-signal-effects.csv','analysis.json','report-data.json'))
    mapping={p.relative_to(ROOT).as_posix():p for p in paths}
    mapping['README.md']=OUT/'README.md'
    entries=[dict(path=name,bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
             for name,p in sorted(mapping.items())]
    manifest=dict(version=meta['version'],files=entries,note='Consistency manifest only; no authenticity or independent trust claim.')
    manifest_bytes=(json.dumps(manifest,indent=2)+'\n').encode()
    (OUT/'MANIFEST.json').write_bytes(manifest_bytes)
    target=OUT/'GoblinTrap-v4-research-package.zip'
    with ZipFile(target,'w',ZIP_DEFLATED,compresslevel=9) as z:
        for name,p in sorted(mapping.items()): z.write(p,name)
        z.writestr('MANIFEST.json',manifest_bytes)
    with ZipFile(target) as z:
        if z.testzip() is not None: raise ValueError('ZIP CRC failure')
        for entry in entries:
            if hashlib.sha256(z.read(entry['path'])).hexdigest()!=entry['sha256']: raise ValueError('ZIP hash mismatch')
        if set(z.namelist())!=set(mapping)|{'MANIFEST.json'}: raise ValueError('ZIP file list mismatch')
    receipt=dict(zip=target.name,files=len(entries)+1,bytes=target.stat().st_size,
                 sha256=hashlib.sha256(target.read_bytes()).hexdigest(),verified=True)
    (OUT/'package-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__': package()
