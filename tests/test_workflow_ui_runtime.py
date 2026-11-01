"""Execute shared guards, write handling and history race protection in Node."""
import shutil
import subprocess
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]


def node_test(code):
    node=shutil.which('node')
    if not node:pytest.skip('Node required for UI runtime tests')
    result = subprocess.run([node,'-e',code,str(ROOT)],capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shared_dirty_guard_cancel_and_refresh_recovery():
    node_test(r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const handlers={},elements={};
function el(){return {children:[],textContent:'',append(x){this.children.push(x);},prepend(x){elements[x.id]=x;},replaceChildren(){this.children=[];},setAttribute(){}};}
const body=el(),root={getAttribute(){return null;},setAttribute(){},removeAttribute(){}};
let allowed=false;
const s={URL,Map,Date,setTimeout(){},localStorage:{getItem(){return null;}},location:{href:'http://test/rules',pathname:'/rules',search:'',origin:'http://test'},
 window:{confirm(){return allowed;},addEventListener(k,fn){handlers[k]=fn;}},
 document:{documentElement:root,body,addEventListener(k,fn){handlers[k]=fn;},getElementById(id){return elements[id];},createElement:el,querySelector(){return body;}}};
vm.runInNewContext(fs.readFileSync(process.argv[1]+'/static/app.js','utf8'),s);
const MS=s.window.MS;let dirty=true;MS.guardDraft(()=>dirty);
const event=()=>({prevented:false,preventDefault(){this.prevented=true;},stopImmediatePropagation(){this.stopped=true;}});
let e=event();handlers.beforeunload(e);assert.equal(e.prevented,true);
const link={href:'http://test/alerts',target:'',hasAttribute(){return false;}};
e={...event(),target:{closest(){return link;}}};handlers.click(e);assert.equal(e.prevented,true);
assert.equal(MS.confirmDiscard(true),false);allowed=true;assert.equal(MS.confirmDiscard(true),true);
dirty=false;e=event();handlers.beforeunload(e);assert.equal(e.prevented,false);
(async()=>{s.fetch=async()=>({ok:true,json:async()=>({rows:[1]})});assert.equal((await MS.read('Logs','/logs')).rows.length,1);
s.fetch=async()=>({ok:false,status:503});await assert.rejects(MS.read('Logs','/logs',undefined,()=>{}));assert.match(elements.refreshProblems.children[0].textContent,/Keeping the last displayed data/);
s.fetch=async()=>({ok:true,json:async()=>({rows:[2]})});await MS.read('Logs','/logs');assert.equal(elements.refreshProblems.children.length,0);})().catch(e=>{console.error(e);process.exitCode=1;});
''')


def test_ai_off_draft_failed_write_and_read_only_controls():
    node_test(r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(process.argv[1]+'/templates/ai.html','utf8');
const code=html.slice(html.indexOf('const $ ='),html.indexOf('// ---- alerts for triage ----'));
function context(role){
 const elements={},calls=[];
 const $=id=>elements[id]||(elements[id]={value:'',checked:false,disabled:false,dataset:{},style:{},handlers:{},addEventListener(k,fn){this.handlers[k]=fn;}});
 $('aiApp').dataset={canConfigure:role==='admin'?'yes':'no',canAnalyze:role==='viewer'?'no':'yes'};
 const cfg={ai_enabled:false,ai_base_url:'http://127.0.0.1:1234/v1',ai_model:'saved',ai_mode:'local',ai_api_style:'auto',ai_auto_triage:true};
 let failSave=true;
 const s={document:{getElementById:$,querySelectorAll(){return Object.entries(elements).filter(([id])=>id!=='aiApp').map(([,v])=>v);}},window:{},MS:{read:async()=>cfg},loadAlerts:async()=>{},
 fetch:async(url,options)=>{calls.push({url,body:JSON.parse(options.body)});return {ok:!(failSave&&url==='/api/ai/config'),status:500,json:async()=>failSave&&url==='/api/ai/config'?{error:'synthetic failure'}:{ok:true,detail:'synthetic test'}};}};
 vm.runInNewContext(code,s);return {s,$,calls,setFail(v){failSave=v;}};
}
(async()=>{
 const c=context('admin');await c.s.loadCfg();c.$('model').value='draft';c.$('apiKey').value='synthetic-key';
 await c.$('saveCfg').handlers.click();assert.equal(c.$('apiKey').value,'synthetic-key');assert.match(c.$('cfgStatus').textContent,/synthetic failure/);
 await c.$('masterToggle').handlers.click();assert.equal(c.$('stateBadge').textContent,'OFF');
 await c.$('testCfg').handlers.click();const test=c.calls.find(x=>x.url==='/api/ai/test');assert.equal(test.body.ai_model,'draft');assert.equal(test.body.ai_api_key,'synthetic-key');assert.equal(c.$('stateBadge').textContent,'OFF');
 c.setFail(false);await c.$('saveCfg').handlers.click();assert.equal(c.$('apiKey').value,'');await c.$('masterToggle').handlers.click();assert.equal(c.$('stateBadge').textContent,'ON');
 const v=context('viewer');await v.s.loadCfg();await v.$('testCfg').handlers.click();assert.equal(v.calls.length,0);assert.equal(v.$('testCfg').disabled,true);
})().catch(e=>{console.error(e);process.exitCode=1;});
''')


def test_log_history_append_races_and_failed_refresh_keep_data():
    node_test(r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const src=fs.readFileSync(process.argv[1]+'/templates/index.html','utf8');
let code=src.slice(src.indexOf('let _logsLoaded = false'),src.indexOf('  renderXColumns();  // redraw header'))+'return rows;\n}';
const elements={},el=id=>elements[id]||(elements[id]={classList:{toggle(){},remove(){}},textContent:''});
let pending=null,requests=0,fail=false;
const page=ids=>({items:ids.map(id=>({id})),next_offset:200,snapshot:999,has_more:true});
const s={URLSearchParams,document:{getElementById:el},currentFilterParams:()=>new URLSearchParams(),logsHeldReason:()=>'',_logsMaxId:0,_syncUrl(){},MS:{read:async()=>{requests++;if(fail)throw new Error('offline');return pending?await pending:page([3,2]);},toast(){}}};
vm.runInNewContext(code,s);
(async()=>{assert.equal((await s.loadLogs()).length,2);let resolve;pending=new Promise(r=>resolve=r);const append=s.loadLogs({append:true});const count=requests;await s.loadLogs({background:true});assert.equal(requests,count);resolve(page([2,1]));assert.equal((await append).length,3);
pending=null;fail=true;assert.equal(await s.loadLogs(),false);fail=false;pending=Promise.resolve(page([0]));const rows=await s.loadLogs({append:true});assert.equal(rows.length,4);assert.deepEqual(Array.from(rows,x=>x.id),[3,2,1,0]);})().catch(e=>{console.error(e);process.exitCode=1;});
''')


def test_alert_draft_cancel_pending_save_and_failure_keep_form():
    node_test(r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const src=fs.readFileSync(process.argv[1]+'/static/alerts.js','utf8');
const code=src.slice(src.indexOf('  async function open(id)'),src.indexOf('  function save('));
const controls=[{disabled:false},{disabled:false}],handlers={};
const form={status:{value:'acknowledged'},assignee:{value:'draft-owner'},note:{value:'draft-note'},addEventListener(k,fn){handlers[k]=fn;},querySelectorAll(){return controls;}};
const elements={aqForm:form,aqClose:{},aqDrawer:{hidden:true,innerHTML:''},aqWrap:{classList:{add(){},remove(){}}}};
let allow=false,rejectSave=null;
const s={openId:null,drawerDirty:false,saving:false,canTriage:true,PINNED:[],NEXT:{new:['acknowledged']},
 $:id=>elements[id],syncUrl(){},esc:v=>String(v??''),status:a=>a.workflow_status||'new',occurrences:()=>1,
 MS:{confirmDiscard:dirty=>!dirty||allow,label:x=>x,alertSeverity:x=>x,timeHTML:()=>'',fmtTime:()=>'',toast(){}},load:async()=>{},
 api:async url=>url.endsWith('/workflow')?{alert:{id:1,severity:'warning',rule_name:'test',workflow_status:'new'},events:[]}:{alert:{id:1},events:[]},
 save:()=>new Promise((resolve,reject)=>{rejectSave=reject;})};
vm.runInNewContext(code,s);
(async()=>{await s.open(1);handlers.input();assert.equal(s.drawerDirty,true);const html=elements.aqDrawer.innerHTML;
await s.open(2);assert.equal(s.openId,1);s.close();assert.equal(elements.aqDrawer.hidden,false);assert.equal(elements.aqDrawer.innerHTML,html);
const save=form.onsubmit({preventDefault(){},target:form});assert.equal(s.saving,true);assert.equal(controls[0].disabled,true);s.close();await s.open(2);assert.equal(s.openId,1);
rejectSave(new Error('synthetic write failure'));await save;assert.equal(s.saving,false);assert.equal(controls[0].disabled,false);assert.equal(form.note.value,'draft-note');assert.equal(s.drawerDirty,true);
allow=true;s.close();assert.equal(elements.aqDrawer.hidden,true);assert.equal(s.drawerDirty,false);
})().catch(e=>{console.error(e);process.exitCode=1;});
''')
