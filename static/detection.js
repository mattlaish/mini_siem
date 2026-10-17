(() => {
  'use strict';
  const $ = id => document.getElementById(id), root=$('detectionApp'), editable=root.dataset.edit==='yes';
  let config, editingRule, editingObject;
  const csv=s=>s.split(',').map(v=>v.trim()).filter(Boolean);
  const text=(tag,value)=>{const e=document.createElement(tag);e.textContent=value;return e;};
  const status=(value,error=false)=>{$('detectStatus').textContent=value;$('detectStatus').className=error?'detect-error':'';};
  async function api(url, options={}) {
    const r=await fetch(url,options);let d;
    try {d=await r.json();} catch {throw new Error(`Request failed (${r.status})`);}
    if(!r.ok) throw new Error(d.error||`Request failed (${r.status})`);
    return d;
  }
  function button(label,action,parent,write=false){const b=text('button',label);b.type='button';b.disabled=write&&!editable;b.onclick=action;parent.append(b);return b;}
  function draft(){status(`Unsaved draft · based on revision ${config.revision}. Save configuration to activate.`);render();}
  function input(parent,key,label,value,type='text',options=null){
    const wrap=text('label',label),el=document.createElement(options?'select':'input');el.name=key;
    if(options)options.forEach(v=>{const o=text('option',v);o.value=v;el.append(o);});else el.type=type;
    if(type==='checkbox')el.checked=Boolean(value);else el.value=Array.isArray(value)?value.join(', '):(value??'');
    if(type==='number'){el.min='1';el.max=key==='threshold'?'10000':'86400';}
    el.disabled=!editable;wrap.append(el);parent.append(wrap);return el;
  }
  const value=(form,key)=>form.elements.namedItem(key).value.trim();
  function renderRules(){
    const body=$('ruleRows');if(!body)return;body.replaceChildren();
    config.rules.forEach((r,i)=>{
      const tr=document.createElement('tr');[r.name,r.kind==='match'?`match · ${r.scope==='all'?'all events':'Windows process/script'}`:r.kind,r.severity].forEach(v=>tr.append(text('td',v)));
      const enabled=document.createElement('td'),box=document.createElement('input');box.type='checkbox';box.checked=r.enabled;box.disabled=!editable;box.setAttribute('aria-label',`Enable ${r.name}`);box.onchange=()=>{r.enabled=box.checked;draft();};enabled.append(box);tr.append(enabled);
      const controls=document.createElement('td');button('Edit',()=>editRule(i),controls,true);
      if(r.kind==='match')button('Delete draft rule',()=>{config.rules.splice(i,1);draft();},controls,true);
      tr.append(controls);body.append(tr);
    });
  }
  function condition(c={field:'process.name',op:'equals',value:'cmd.exe'}){
    const row=document.createElement('div');row.className='detect-condition';
    const field=document.createElement('input');field.dataset.key='field';field.value=c.field;field.required=true;field.maxLength=70;field.setAttribute('list','conditionFieldList');field.setAttribute('aria-label','Field (listed field or field.<name>)');row.append(field);
    const op=document.createElement('select');op.dataset.key='op';['equals','contains','glob'].forEach(v=>{const o=text('option',v);o.value=v;op.append(o);});op.value=c.op;op.setAttribute('aria-label','Operator');row.append(op);
    const val=document.createElement('input');val.value=c.value;val.required=true;val.maxLength=1024;val.dataset.key='value';val.setAttribute('aria-label','Condition value');row.append(val);button('Remove',()=>row.remove(),row,true);$('conditionRows').append(row);
  }
  function editRule(i,isNew=false){
    editingRule={i,isNew};const r=config.rules[i],p=$('ruleFields');p.replaceChildren();$('conditionRows').replaceChildren();
    input(p,'id','Stable rule ID',r.id).disabled=true;input(p,'name','Name',r.name);
    const severity=input(p,'severity',r.id==='nxlog_severity_event'?'Severity (source-event severity is preserved)':'Severity',r.severity,'text',['critical','error','warning','notice','informational']);
    if(r.id==='web_server_shell'||r.id==='nxlog_severity_event')severity.disabled=true;
    if('threshold'in r){input(p,'threshold','Threshold',r.threshold,'number');input(p,'window_seconds','Window (seconds)',r.window_seconds,'number');}
    if(r.kind==='web_shell'){const mode=input(p,'child_match','Alert on',r.child_match||'listed','text',['any','listed']);mode.options[0].textContent='Any child process except excluded (recommended)';mode.options[1].textContent='Only the listed child processes';}
    ['parents','scoped_parents','required_role','excluded_children','children'].forEach(k=>{if(k in r)input(p,k,({excluded_children:'Excluded (legitimate) children',children:'Listed children (used only in listed mode)'}[k]||k.replaceAll('_',' '))+' (comma-separated)',r[k]);});
    if(r.kind==='match'){const scope=input(p,'scope','Applies to',r.scope||'windows','text',['windows','all']);scope.options[0].textContent='Windows process/script events only';scope.options[1].textContent='All events (syslog, firewall, API, JSON)';}
    $('addCondition').hidden=r.kind!=='match';
    if(r.kind==='match')r.conditions.forEach(condition);
    $('ruleEditor').hidden=false;$('ruleEditor').scrollIntoView({behavior:'smooth'});
  }
  function renderObjects(){
    [['hosts','hostRows'],['schedules','scheduleRows'],['exceptions','exceptionRows']].forEach(([section,id])=>{
      if(!$(id))return;$(id).replaceChildren();
      config[section].forEach((row,i)=>{
        const p=document.createElement('p');p.append(text('strong',row.name||row.hostname||row.id));
        const detail=section==='schedules'?` · ${row.start}–${row.end} ${row.timezone} · days ${row.weekdays.join(',')}`:section==='hosts'?` · ${row.timezone} · groups ${(row.groups||[]).join(', ')} · telemetry ${row.telemetry_enabled?'enabled':'off'}`:` · rule ${row.rule_id} · expires ${row.expires_at} · ${row.ticket}`;
        p.append(document.createTextNode(detail));button('Edit',()=>editObject(section,i),p,true);button('Delete from draft',()=>{config[section].splice(i,1);draft();},p,true);$(id).append(p);
      });
    });
  }
  const objectSchema={
    hosts:[['hostname','Hostname (short name or FQDN)'],['timezone','IANA timezone'],['groups','Groups (comma-separated)','list'],['roles','Roles (comma-separated)','list'],['telemetry_enabled','Monitor expected telemetry','bool'],['max_silence_seconds','Maximum silence (seconds)','number'],['expected_sources','Expected sources: security_4688, sysmon_1, powershell_4104','list']],
    schedules:[['id','Stable ID'],['name','Name'],['timezone','IANA timezone'],['hosts','Hostnames, short or FQDN (comma-separated)','list'],['groups','Groups (comma-separated)','list'],['weekdays','Weekdays: Monday=0 … Sunday=6','ints'],['start','Start (HH:MM)','time'],['end','End, exclusive (HH:MM)','time'],['dates','Additional approved dates YYYY-MM-DD','list'],['exclude_dates','Excluded dates / holidays YYYY-MM-DD','list'],['exception_only','Only for a scoped exception (does not approve other shells)','bool']],
    exceptions:[['id','Stable ID'],['rule_id','Specific rule ID'],['hosts','Exact hostnames','list'],['groups','Groups','list'],['process_path','Full executable path'],['parent_path','Full parent path'],['command_glob','Approved command line glob'],['user','Exact user / service account'],['schedule_id','Approved window ID'],['expires_at','Expiry with UTC offset (ISO 8601)'],['ticket','Approval / change ticket']]
  };
  function editObject(section,i,isNew=false){
    editingObject={section,i,isNew};const row=config[section][i],p=$('objectFields');p.replaceChildren();$('objectTitle').textContent=`Edit ${section}`;
    objectSchema[section].forEach(([k,label,type])=>input(p,k,label,row[k],type==='bool'?'checkbox':type==='number'?'number':type==='time'?'time':'text'));
    $('objectEditor').hidden=false;$('objectEditor').scrollIntoView({behavior:'smooth'});
  }
  function render(){renderRules();renderObjects();}
  async function load(){
    config=await api('/api/detection/config');const warning=config.load_warning;delete config.load_warning;render();
    if(warning)status(warning,true);else status(`Saved revision ${config.revision}${config.updated_by?' · '+config.updated_by+' · '+config.updated_at:''}`);
  }
  async function unprofiled(){
    const box=$('unprofiledRows');if(!box)return;const rows=await api('/api/detection/unprofiled-hosts');box.replaceChildren();
    if(!rows.length){box.append(text('p','Every Windows host recently sending process/script events has a profile.'));return;}
    box.append(text('p',`${rows.length} Windows host(s) sent process/script events without a profile. Their timezone, roles, schedules and exceptions do not apply until one is added:`));
    rows.forEach(h=>{const p=document.createElement('p');p.append(text('strong',h.hostname));p.append(document.createTextNode(` · last seen ${h.last_seen} · ${(h.sources||[]).join(', ')}`));
      button('Add profile',()=>{config.hosts.push({hostname:h.hostname,timezone:'Asia/Taipei',groups:[],roles:[],telemetry_enabled:false,max_silence_seconds:3600,expected_sources:['security_4688']});draft();editObject('hosts',config.hosts.length-1,true);},p,true);box.append(p);});
  }
  async function telemetry(){
    const d=await api('/api/detection/telemetry');$('telemetryRows').replaceChildren();
    if(!Object.keys(d).length)$('telemetryRows').append(text('p','No monitor observations yet. Check configured expectations and listener status.'));
    Object.entries(d).forEach(([key,v])=>$('telemetryRows').append(text('p',`${key}: ${v.status} · last receipt ${v.last_received_at||'not yet received'} · checked ${v.checked_at}`)));
  }
  async function alerts(){
    const rows=await api('/api/detection/alerts'),body=$('detectionAlertRows');body.replaceChildren();
    rows.forEach(a=>{
      const tr=document.createElement('tr'),e=a.detection_evidence;
      [a.created_at+' / '+(e?.fields?.['host.name']||a.source_ip),a.rule_name+' / '+a.severity,a.description,e?.occurrences||1].forEach(v=>tr.append(text('td',v)));
      const flow=document.createElement('td');flow.append(text('span',a.workflow_status||'new'));
      button('Update',async()=>{const next=prompt('State: acknowledged, investigating, resolved, closed, or new',a.workflow_status||'new');if(!next)return;const note=prompt('Resolution / investigation note','');if(note===null)return;try{await api(`/api/alerts/${a.id}/workflow`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:next,note})});await alerts();}catch(e){status(e.message,true);}},flow);
      tr.append(flow);const control=document.createElement('td');button('Open',async()=>{try{const d=await api(`/api/detection/alerts/${a.id}/evidence`);$('evidencePanel').hidden=false;$('alertEvidence').textContent=JSON.stringify(d.alert,null,2);$('rawEvidence').textContent=d.events.map(e=>`#${e.id} · received ${e.received_at}\n${e.raw}`).join('\n\n');$('evidenceNote').textContent=d.note;$('evidencePanel').scrollIntoView({behavior:'smooth'});}catch(e){status(e.message,true);}},control);tr.append(control);body.append(tr);
    });
    if(!rows.length){const tr=document.createElement('tr'),td=text('td','No recent detection alerts.');td.colSpan=6;tr.append(td);body.append(tr);}
  }
  if($('saveDetection'))$('saveDetection').onclick=async()=>{try{config=await api('/api/detection/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)});render();status(`Saved revision ${config.revision}; active within five seconds.`);}catch(e){status(e.message,true);}};
  if($('reloadDetection'))$('reloadDetection').onclick=()=>load().catch(e=>status(e.message,true));
  if($('newRule')){
    $('newRule').disabled=!editable;$('newRule').onclick=()=>{config.rules.push({id:'custom_'+Date.now(),name:'New process rule',kind:'match',scope:'windows',enabled:true,severity:'warning',conditions:[{field:'process.name',op:'equals',value:'cmd.exe'}]});draft();editRule(config.rules.length-1,true);};
    $('addCondition').onclick=()=>condition();$('cancelRule').onclick=()=>{if(editingRule.isNew){config.rules.splice(editingRule.i,1);draft();}$('ruleEditor').hidden=true;};
    $('ruleForm').onsubmit=e=>{e.preventDefault();const r=config.rules[editingRule.i],f=e.target;r.name=value(f,'name');r.severity=value(f,'severity');['threshold','window_seconds'].forEach(k=>{if(k in r)r[k]=Number(value(f,k));});['children','parents','scoped_parents','excluded_children'].forEach(k=>{if(k in r)r[k]=csv(value(f,k));});if(r.kind==='web_shell')r.child_match=value(f,'child_match');if('required_role'in r)r.required_role=value(f,'required_role');if(r.kind==='match')r.scope=value(f,'scope');if(r.kind==='match')r.conditions=[...$('conditionRows').children].map(row=>Object.fromEntries([...row.querySelectorAll('[data-key]')].map(el=>[el.dataset.key,el.value])));$('ruleEditor').hidden=true;draft();};
    $('simulationEvent').value=JSON.stringify({EventID:4688,Channel:'Security',SourceName:'Microsoft-Windows-Security-Auditing',Hostname:'HMSWEB1',EventTime:'2026-10-15T22:56:35+08:00',NewProcessName:'C:\\Windows\\System32\\cmd.exe',ParentProcessName:'C:\\Tomcat\\tomcat7.exe',NewProcessId:'0x2bc',ProcessId:'0xe74',CommandLine:'cmd.exe /c whoami',SubjectUserName:'SYSTEM'},null,2);
    $('simulateRule').onclick=async()=>{try{const d=await api('/api/detection/simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify((()=>{const t=$('simulationEvent').value;let parsed=null;try{parsed=JSON.parse(t);}catch{}return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?{event:parsed,config}:{raw:t,config};})())});$('simulationResult').textContent=JSON.stringify(d,null,2);}catch(e){$('simulationResult').textContent=e.message;}};
  }
  if($('newHost')){
    const add=(section,row)=>{config[section].push(row);draft();editObject(section,config[section].length-1,true);};
    ['newHost','newSchedule','newException'].forEach(id=>$(id).disabled=!editable);
    $('newHost').onclick=()=>add('hosts',{hostname:'NEW-HOST',timezone:'Asia/Taipei',groups:[],roles:[],telemetry_enabled:false,max_silence_seconds:3600,expected_sources:['security_4688']});
    $('newSchedule').onclick=()=>add('schedules',{id:'window_'+Date.now(),name:'Business hours',timezone:'Asia/Taipei',hosts:[],groups:[],weekdays:[0,1,2,3,4],start:'09:00',end:'18:00',dates:[],exclude_dates:[]});
    $('newException').onclick=()=>add('exceptions',{id:'exception_'+Date.now(),rule_id:'out_of_hours_shell',hosts:[],groups:[],process_path:'',parent_path:'',command_glob:'',user:'',schedule_id:'',expires_at:'',approved_by:'recorded on save',ticket:''});
    $('cancelObject').onclick=()=>{if(editingObject.isNew){config[editingObject.section].splice(editingObject.i,1);draft();}$('objectEditor').hidden=true;};
    $('objectForm').onsubmit=e=>{e.preventDefault();const {section,i}=editingObject,row=config[section][i];objectSchema[section].forEach(([k,label,type])=>{row[k]=type==='bool'?e.target.elements.namedItem(k).checked:type==='number'?Number(value(e.target,k)):type==='ints'?csv(value(e.target,k)).map(Number):type==='list'?csv(value(e.target,k)):value(e.target,k);});$('objectEditor').hidden=true;draft();};
    $('refreshTelemetry').onclick=()=>Promise.all([telemetry(),unprofiled()]).catch(e=>status(e.message,true));
  }
  if($('refreshDetectionAlerts'))$('refreshDetectionAlerts').onclick=()=>alerts().catch(e=>status(e.message,true));
  load().then(()=>{if($('telemetryRows'))return Promise.all([telemetry(),unprofiled()]);if($('detectionAlertRows'))return alerts();}).catch(e=>status(e.message,true));
})();
