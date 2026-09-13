"""Create the v4 report from verified data, with vector figures and Markdown."""
import csv
import hashlib
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, String, Circle
from reportlab.graphics import renderSVG
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'results/v4'
OUT=ROOT/'output/v4'
LABELS={'revoke':'Revocation','deception_silent':'Silent bait','deception':'Bait + alerts','isolate':'Isolation'}
WORLD_LABELS={'ideal':'Ideal','coverage_half':'Coverage 0.5','reliability_half':'Reliability 0.5',
    'collateral_quarter':'Collateral 0.25','collateral_one':'Collateral 1.0','background_empty':'Real empties 0.15',
    'recognition_half':'Recognition 0.5','patience_four':'Patience 4','avoidance_half':'Avoidance 0.5',
    'avoidance_all':'Avoidance 1.0','adaptive_avoidance':'Adaptive avoidance','combined':'Combined stress'}


def read(path):
    with path.open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))


def build():
    meta=json.loads((DATA/'metadata.json').read_text())
    audit=json.loads((DATA/'verification.json').read_text())
    tests=json.loads((DATA/'tests.json').read_text())
    analysis=json.loads((OUT/'analysis.json').read_text())
    plan=json.loads((DATA/'protocol.json').read_text())
    if not (audit['status']=='PASS' and audit['full_replay'] and tests['status']=='PASS' and
            audit['total_rows_checked']==meta['total_trials']): raise ValueError('Validated results required')
    for name,expected in meta['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected: raise ValueError('Source drift')
    for name,expected in analysis['input_sha256'].items():
        if hashlib.sha256((DATA/name).read_bytes()).hexdigest()!=expected: raise ValueError('Stale analysis')
    rows=read(DATA/'budget_results.csv')
    family=read(DATA/'by_family.csv')
    pairs=read(OUT/'budget-signal-effects.csv')
    fixed=read(OUT/'fixed-signal-effects.csv')
    def row(world,arm,split='test',budget=3.,alert=.67):
        found=[r for r in rows if r['environment']==world and r['policy']==arm and r['split']==split
               and float(r['budget'])==budget and float(r['alert_limit'])==alert]
        if len(found)!=1: raise ValueError('Nonunique report cell')
        return found[0]
    def f(value): return f'{float(value):.2f}'
    def percent(value): return f'{100*float(value):.1f}%'
    def effect(world,split='test'):
        return next(r for r in pairs if r['environment']==world and r['split']==split and
                    float(r['budget'])==3 and float(r['alert_limit'])==.67 and r['metric']=='harm')
    primary=effect('ideal')
    styles={
        'title':ParagraphStyle('title',fontName='Helvetica-Bold',fontSize=24,leading=28,textColor=colors.HexColor('#173e4c'),spaceAfter=14),
        'heading':ParagraphStyle('heading',fontName='Helvetica-Bold',fontSize=14,leading=18,spaceBefore=9,spaceAfter=8,textColor=colors.HexColor('#173e4c')),
        'body':ParagraphStyle('body',fontName='Helvetica',fontSize=10,leading=14,spaceAfter=9),
        'small':ParagraphStyle('small',fontName='Helvetica',fontSize=8.3,leading=11,spaceAfter=7),
        'cell':ParagraphStyle('cell',fontName='Helvetica',fontSize=8.2,leading=10.6),
    }
    story=[]; md=[]
    def paragraph(text,kind='body'):
        story.append(Paragraph(escape(text),styles[kind])); md.append(text+'\n')
    def heading(text):
        story.append(Paragraph(escape(text),styles['heading'])); md.append('## '+text+'\n')
    def table(headers,data,widths):
        cells=[[Paragraph(escape(str(c)),styles['cell']) for c in rr] for rr in [headers]+data]
        tab=Table(cells,colWidths=widths,repeatRows=1,hAlign='LEFT')
        tab.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e7eff1')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
            ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),
            ('LINEBELOW',(0,0),(-1,0),.7,colors.HexColor('#8ca3ab')),
            ('LINEBELOW',(0,1),(-1,-1),.3,colors.HexColor('#d8e1e3'))]))
        story.extend([tab,Spacer(1,10)])
        md.append('| '+' | '.join(headers)+' |\n| '+' | '.join('---' for _ in headers)+' |\n'+
                  '\n'.join('| '+' | '.join(map(str,r))+' |' for r in data)+'\n')
    def page(): story.append(PageBreak())

    paragraph('The alert advantage depends on the comparison','title')
    paragraph('GoblinTrap 0.4 | Cost-constrained simulation extension | 12 September 2026','small')
    paragraph('Jacob Babula | CyberGoblins. No language model or real infrastructure was evaluated. Contributions and Codex assistance are described at the end of this report.','small')
    heading('What changed')
    paragraph(f'The v4 study evaluates {meta["total_trials"]:,} symbolic episodes across twelve designed worlds. Defenses choose a threshold and delay on calibration runs under shared benign-cost and false-alert ceilings, then use those frozen choices on unused seeds and separately on four new scripted families.')
    paragraph(f'At a three-call cost ceiling and 67% benign-alert ceiling in the ideal world, silent bait yields {f(row("ideal","deception_silent")["harm"])} harmful actions per malicious episode and bait plus alerts yields {f(row("ideal","deception")["harm"])}. The paired difference, alerts minus silent bait, is +{f(primary["difference"])} (95% conditional interval {f(primary["ci_low"])} to {f(primary["ci_high"])}). This compares two tuned policies; it is not the isolated causal effect of adding a signal at one shared threshold.')
    table(['World / defense','Threshold / delay','Harm','Benign cost','Within limits?'],[
        [WORLD_LABELS[w]+' / '+LABELS[a],row(w,a)['candidate'].replace('t','').replace('_l',' / '),
         f(row(w,a)['harm']),f(row(w,a)['benign_cost']),'Yes' if row(w,a)['heldout_feasible']=='True' else 'No']
        for w in ('ideal','combined') for a in LABELS],[162,91,52,75,88])
    paragraph('Table 1. Held-out original families; cost ceiling 3, alert ceiling 67%. Cost is direct benign disruption plus modeled collateral lost calls. Common ceilings do not imply equal realized costs. These two examples are illustrative; all budgets and worlds are retained.','small')
    paragraph('Isolation remains strongest in the ideal world. Under the combined assumptions, silent bait has less harm than isolation but incurs more benign cost. The alert arm exceeds its held-out cost ceiling there. The study identifies conditional tradeoffs, not a universally best defense.')

    page(); heading('Cost limits change which policies can be used')
    paragraph('For each world and defense, calibration searches 18 threshold/delay candidates at each of five cost ceilings and two alert ceilings. Infeasible candidates are not replaced or relabeled. The chart retains held-out violations rather than treating calibration success as a guarantee.')
    d=Drawing(468,232)
    palette={'revoke':'#6f7780','deception_silent':'#245c86','deception':'#23816f','isolate':'#9b5b31'}
    for panel,world in enumerate(('ideal','combined')):
        x0=34+panel*237; y0=43; width=186; height=145
        d.add(String(x0,y0+height+17,WORLD_LABELS[world],fontName='Helvetica-Bold',fontSize=10))
        for tick in (0,5,10,15,20):
            y=y0+tick/20*height
            d.add(Line(x0,y,x0+width,y,strokeColor=colors.HexColor('#dce3e6'),strokeWidth=.5))
            d.add(String(x0-7,y-3,str(tick),fontSize=7,textAnchor='end'))
        for tick in (0,1,3,6,12):
            x=x0+tick/12*width
            d.add(String(x,y0-13,str(tick),fontSize=7,textAnchor='middle'))
        for arm,color in palette.items():
            previous=None
            for budget in plan['budgets']:
                r=row(world,arm,budget=budget)
                if r['calibration_feasible']!='True': previous=None; continue
                x=x0+budget/12*width; y=y0+float(r['harm'])/20*height
                if previous: d.add(Line(*previous,x,y,strokeColor=colors.HexColor(color),strokeWidth=1.3))
                if r['heldout_feasible']=='True':
                    d.add(Circle(x,y,2.5,fillColor=colors.HexColor(color),strokeColor=None))
                else:
                    d.add(Line(x-3,y-3,x+3,y+3,strokeColor=colors.HexColor(color),strokeWidth=1.4))
                    d.add(Line(x-3,y+3,x+3,y-3,strokeColor=colors.HexColor(color),strokeWidth=1.4))
                previous=(x,y)
        d.add(String(x0+width/2,12,'Calibration benign-cost ceiling',fontSize=8,textAnchor='middle'))
    d.add(String(0,225,'Held-out harmful actions per malicious episode (lower is better)',fontSize=8))
    renderSVG.drawToFile(d,str(OUT/'budget-comparison.svg'))
    story.append(d); md.append('![Budget comparison](budget-comparison.svg)\n')
    paragraph('Figure 1. Gray: revocation. Blue: silent bait. Green: bait plus alerts. Brown: isolation. Dots meet both held-out limits; crosses violate at least one. Missing points were infeasible during calibration. Lines connect discrete tested budgets only. Alert ceiling is 67%; families are the original set. Overlapping points may conceal other arms.','small')
    paragraph(f'Across the {analysis["original_family_comparisons"]} designed original-family budget/alert/world comparisons, both bait arms were calibration-feasible in {analysis["calibration_feasible_pairs"]}. Of those, alerts had less held-out harm in {analysis["signal_less_harm"]}, equal harm in {analysis["signal_equal_harm"]}, and more harm in {analysis["signal_more_harm"]}. Both arms actually met the held-out ceilings in {analysis["heldout_both_feasible_pairs"]}. These counts include repeated selections and correlated settings; they are descriptive, not independent replications or a significance tally.')
    paragraph(f'There were {analysis["original_family_budget_violations"]} held-out violations among calibrated original-family policy cells and {analysis["shift_budget_violations"]} under family shift. The full CSV marks each violation. No settings were retuned using these outcomes.')
    heading('Isolation costs remain a modeling choice')
    paragraph('Coverage and enforcement reliability determine whether isolation closes the single persistent route; failed isolation still revokes credentials. Collateral cost is an additional workload rate multiplied by actions remaining after the isolation attempt, including failed attempts. It is not a measured outage cost. Coverage and reliability enter through their product in this model, so the experiment does not identify distinct operational mechanisms.')
    paragraph('Collateral losses during malicious episodes are reported separately in budget_results.csv. They are not included in the benign-only constraint. A deployment decision would also need prevalence, severity weights, recovery time and collateral harm across all incident types.')

    page(); heading('The fixed-setting signal comparison still matters')
    paragraph('The following comparisons retain threshold 8 and delay 1 for both bait arms. Unlike the tuned-policy comparison, they isolate enabling the tripwire bonus while holding configuration and diversion rules fixed. Negative harm differences favor alerts; positive benign-cost differences mean more disruption.')
    fixed_lookup={(r['environment'],r['split'],r['metric']):r for r in fixed}
    table(['World','Harm difference','95% interval','Cost difference'],[
        [WORLD_LABELS[w],f(fixed_lookup[w,'test','harm']['difference']),
         f(fixed_lookup[w,'test','harm']['ci_low'])+' to '+f(fixed_lookup[w,'test','harm']['ci_high']),
         f(fixed_lookup[w,'test','benign_cost']['difference'])] for w in plan['environments']],
        [150,92,134,92])
    paragraph('Table 2. Alerts minus silent bait on unused seeds, original families. Intervals use 2,000 paired seed-cluster bootstrap resamples, conditional on the specified world. Full containment effects and family-shift intervals are in fixed-signal-effects.csv.','small')
    paragraph('Real empty responses preserve completed harm but make feedback ambiguous. Recognition probability controls whether empty observations increment suspicion; patience controls how many are needed. Static avoidance reduces attraction throughout. Adaptive avoidance starts after accumulated suspicion. None is a measured model behavior.')
    paragraph('The coverage and collateral variants leave these fixed bait-arm results unchanged because they modify isolation only. This is an expected control, not independent supporting evidence. Total avoidance makes the two bait arms equivalent by construction. The combined world tests one conjunction of assumptions; it does not map all interactions.')

    page(); heading('New benign families expose poor transfer')
    paragraph('The family-shift evaluation contains two new malicious scripts and two new benign scripts. No new-family outcomes enter calibration. It is a designed stress test, not an estimate of generalization to a deployment population.')
    table(['Ideal-world defense','Cost: original','Cost: shifted','Alerts: shifted','Shift limits'],[
        [LABELS[a],f(row('ideal',a)['benign_cost']),f(row('ideal',a,'family_shift')['benign_cost']),
         percent(row('ideal',a,'family_shift')['false_alert']),
         'Met' if row('ideal',a,'family_shift')['heldout_feasible']=='True' else 'Violated'] for a in LABELS],
        [128,85,85,90,80])
    paragraph('Table 3. Frozen settings selected at cost ceiling 3 and alert ceiling 67%. Every arm violates at least one limit after this family shift. Original and shifted groups contain different families; changes are not paired within the same workload.','small')
    heading('What the new families actually do')
    paragraph('The patient malicious script schedules productive operations every fourth action. The cycler prioritizes persistence and switches symbolic channel labels more often. Burst auditing performs two audits every six actions. Recovery repeats acquisition, health, audit, work, health and wait. These fixed sequences intentionally stress the scoring system; their prevalence and realism remain unvalidated.')
    heading('What this supports')
    paragraph('A signal can help at one shared threshold yet fail to improve a separately tuned, cost-constrained policy. A stronger enforcement action can dominate under perfect coverage and become less effective when coverage or reliability falls. A benign constraint can hold on unused seeds from familiar scripts and fail badly on new scripts. These are reproducible properties of this model.')
    heading('What this does not support')
    paragraph('No result establishes real AI-agent detection performance, production containment effectiveness or deployment false-positive rates. The added parameters remain assumptions. A single persistent route is not a network. Finite-state policies are not language models. Harm is an unweighted count of successful acquisition, persistence, exfiltration and pivot actions, not victims or stolen data. A 24-action horizon omits longer outages and recovery.')
    paragraph('The next substantive step is independently reviewed workloads and route/enforcement models, followed by an authorized empirical evaluation if a claim about actual AI agents is intended. More simulation seeds alone will not address those gaps.')
    paragraph('A SHA-256 manifest checks package consistency, not authenticity. This report is locally typeset; it is not an export from the official sprint template.','small')

    page(); heading('Methods, checks and reproduction')
    paragraph(f'Calibration: {len(plan["calibration_seeds"])} seeds x seven families x four arms x 18 candidate settings x twelve worlds = 483,840 episodes. Evaluation: {meta["total_trials"]-483840:,} episodes across selected unique candidates plus the fixed comparison, with {len(plan["test_seeds"])} unused seeds for each tested family/candidate. Evaluation rows are reused across budgets when selections coincide; they are stored once. The complete run contains {meta["total_trials"]:,} trial rows.')
    paragraph('Choices minimize calibration harm under mean benign-cost and false-alert ceilings. Ties prefer higher containment, lower cost, lower alerts, lower threshold and shorter delay. Every choice was frozen before held-out evaluation. Budgets are 0, 1, 3, 6 and 12 expected lost calls; alert ceilings are 34% and 67%. The two-world, budget-3 examples in this brief are illustrative views selected for explanation after results were available; all planned cells remain available.')
    paragraph('The study was informed by v3 and is exploratory. The first completed computation failed its final hash gate because Windows translated newlines during file writing. Serialization was corrected and the identical design was rerun into a fresh directory. The incomplete run is preserved locally and excluded from this package. There was no outcome-driven tuning change between runs. Local hashes establish consistency, not external preregistration or an independent timestamp.')
    paragraph(f'{tests["tests_run"]} tests pass. The verifier replayed all {audit["total_rows_checked"]:,} saved trials, independently recomputed aggregates and calibrated selections, checked {audit["choices_checked"]} choice cells, {audit["budget_rows_checked"]} budget-result rows and {audit["family_rows_checked"]} family-result rows, and verified source hashes. It ran under Python -O; explicit failures remain enabled. The same assistant performed the work. Replay uses the same engine, so it is not independent model validation.')
    paragraph('Paired bootstrap intervals resample seed clusters, preserving equal weights across the appropriate malicious or benign families. Tuned-policy intervals condition on the frozen choices and omit calibration-selection uncertainty. All intervals omit world uncertainty. They are unadjusted descriptive intervals across a correlated exploratory matrix, not a confirmatory multiple-testing procedure.')
    heading('Reproduce from the extracted package')
    for line in ('$env:PYTHONPATH = "src"','python -m unittest discover -s tests -v',
                 'python scripts/run_budget_study.py --output results/reproduction-v4',
                 'python -O scripts/verify_budget_results.py results/reproduction-v4'):
        paragraph(line,'small')
    paragraph('Python 3.11+ and its standard library run the experiment, verifier and analysis. Use a fresh output directory. The optional brief builder needs ReportLab and pypdf. See README.md for analysis and report rebuilding. The v3 engine and original package remain preserved; use goblintrap.extended_engine explicitly for v4.')
    heading('Artifact and contribution boundaries')
    paragraph('This extension introduces no external dataset, live credential, network operation, exploit payload or model invocation. It uses only symbolic actions. Source motivation and the original v3 report remain historical context; this extension makes no new claims about live sprint rules or source-page contents. No independent researcher review or acceptance is claimed. Jacob Babula supplied the project direction and requested revisions. Codex assisted with implementation, experiment execution, validation, analysis and report writing.')

    OUT.mkdir(parents=True,exist_ok=True)
    def footer(canvas,doc):
        canvas.setStrokeColor(colors.HexColor('#bdcdd2')); canvas.line(72,49,540,49)
        canvas.setFont('Helvetica',8); canvas.setFillColor(colors.HexColor('#50636a'))
        canvas.drawString(72,36,'GoblinTrap 0.4 | Research report')
        canvas.drawRightString(540,36,str(doc.page))
    pdf=OUT/'GoblinTrap-v4-technical-brief.pdf'
    SimpleDocTemplate(str(pdf),pagesize=(612,792),leftMargin=72,rightMargin=72,topMargin=55,bottomMargin=65,
                      title='GoblinTrap v4: The alert advantage depends on the comparison',author='Jacob Babula; prepared with Codex assistance').build(story,onFirstPage=footer,onLaterPages=footer)
    (OUT/'technical-notes.md').write_text('\n'.join(md),encoding='utf-8')
    report=dict(version=meta['version'],total_trials=meta['total_trials'],tests=tests,verification=audit,
                analysis_summary={k:v for k,v in analysis.items() if k not in ('fixed_effects','input_sha256')},
                primary_example={w:{a:row(w,a) for a in LABELS} for w in ('ideal','combined')},
                pdf_pages=len(PdfReader(pdf).pages))
    (OUT/'report-data.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(pdf=str(pdf),pages=report['pdf_pages']),indent=2))


if __name__=='__main__': build()
