(() => {
  'use strict';
  const $ = id => document.getElementById(id), root=$('detectionApp'), editable=root.dataset.edit==='yes';
  let config, editingRule, editingObject, dirty=false;
  const csv=s=>s.split(',').map(v=>v.trim()).filter(Boolean);
  const DAYS=['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
  const ruleName=rule=>rule.name===rule.id.split('_').map(word=>word.charAt(0).toUpperCase()+word.slice(1)).join(' ')?MS.label(rule.id):rule.name;
  function choices(parent,key,label,selected,options){
    const group=document.createElement('fieldset'),legend=document.createElement('legend');
    legend.textContent=label;group.append(legend);group.disabled=!editable;
    options.forEach(([value,name])=>{const wrap=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.name=key;box.value=value;box.checked=(selected||[]).map(String).includes(String(value));wrap.style.cssText='display:flex;flex-direction:row;align-items:center;gap:8px';wrap.append(box,document.createTextNode(name));group.append(wrap);});
    parent.append(group);
  }
  function objectValue(form,key,type){
    if(key==='weekdays'||key==='expected_sources')return [...form.querySelectorAll('[name="'+key+'"]:checked')].map(el=>key==='weekdays'?Number(el.value):el.value);
    return type==='bool'?form.elements.namedItem(key).checked:type==='number'?Number(value(form,key)):type==='ints'?csv(value(form,key)).map(Number):type==='list'?csv(value(form,key)):value(form,key);
  }
  const text=(tag,value)=>{const e=document.createElement(tag);e.textContent=value;return e;};
  const status=(value,error=false)=>{$('detectStatus').textContent=value;$('detectStatus').className=error?'detect-error':'';};
  async function api(url, options={}) {
    const r=await fetch(url,options);let d;
    try {d=await r.json();} catch {throw new Error(`Request failed (${r.status})`);}
    if(!r.ok) throw new Error(MS.settingError(d.error||`Request failed (${r.status})`));
    return d;
  }
  function button(label,action,parent,write=false){const b=text('button',label);b.type='button';b.disabled=write&&!editable;b.onclick=action;parent.append(b);return b;}
  function draft(){dirty=true;status(`Unsaved changes. Choose Save changes to apply them.`);render();}
  function input(parent,key,label,value,type='text',options=null){
    const wrap=text('label',label),el=document.createElement(options?'select':'input');el.name=key;
    if(options)options.forEach(v=>{const o=text('option',typeof v==='object'?v.label:MS.label(v));o.value=typeof v==='object'?v.value:v;el.append(o);});else el.type=type;
    if(type==='checkbox')el.checked=Boolean(value);else el.value=Array.isArray(value)?value.join(', '):(value??'');
    if(type==='number'){el.min='1';el.max=key==='threshold'?'10000':'86400';}
    el.disabled=!editable;wrap.append(el);parent.append(wrap);return el;
  }
  const value=(form,key)=>form.elements.namedItem(key).value.trim();
  function renderRules(){
    const body=$('ruleRows');if(!body)return;body.replaceChildren();
    config.rules.forEach((r,i)=>{
      const tr=document.createElement('tr');[ruleName(r),r.kind==='match'?`Custom · ${r.scope==='all'?'all log sources':'Windows activity'}`:MS.label(r.kind),MS.alertSeverity(r.severity)].forEach(v=>tr.append(text('td',v)));
      const enabled=document.createElement('td'),box=document.createElement('input');box.type='checkbox';box.checked=r.enabled;box.disabled=!editable;box.setAttribute('aria-label',`Enable ${r.name}`);box.onchange=()=>{r.enabled=box.checked;draft();};enabled.append(box);tr.append(enabled);
      const controls=document.createElement('td');button('Edit',()=>editRule(i),controls,true);
      if(r.kind==='match')button('Delete draft rule',()=>{config.rules.splice(i,1);draft();},controls,true);
      tr.append(controls);body.append(tr);
    });
  }
  function condition(c={field:'process.name',op:'equals',value:'cmd.exe'}){
    const row=document.createElement('div');row.className='detect-condition';
    const field=document.createElement('input');field.dataset.key='field';field.value=c.field;field.required=true;field.maxLength=70;field.setAttribute('list','conditionFieldList');field.setAttribute('aria-label','Log field to check; use field.name for a source-specific field');row.append(field);
    const op=document.createElement('select');op.dataset.key='op';['equals','contains','glob'].forEach(v=>{const o=text('option',({equals:'is exactly',contains:'contains',glob:'matches a pattern (* or ?)'}[v]));o.value=v;op.append(o);});op.value=c.op;op.setAttribute('aria-label','How to match');row.append(op);
    const val=document.createElement('input');val.value=c.value;val.required=true;val.maxLength=1024;val.dataset.key='value';val.setAttribute('aria-label','Condition value');row.append(val);button('Remove',()=>row.remove(),row,true);$('conditionRows').append(row);
  }
  function editRule(i,isNew=false){
    editingRule={i,isNew};const r=config.rules[i],p=$('ruleFields');p.replaceChildren();$('conditionRows').replaceChildren();
    const reference=input(p,'id','Rule reference',r.id,'hidden');reference.parentElement.hidden=true;input(p,'name','Name',r.name);
    const severity=input(p,'severity',r.id==='nxlog_severity_event'?'Severity (source-event severity is preserved)':'Severity',r.severity,'text',['critical','error','warning','notice','informational']);
    [...severity.options].forEach(option=>{option.textContent=MS.alertSeverity(option.value);});
    if(r.id==='web_server_shell'||r.id==='nxlog_severity_event')severity.disabled=true;
    if('threshold'in r){input(p,'threshold','Number of matching events',r.threshold,'number');input(p,'window_seconds','Within this many seconds',r.window_seconds,'number');}
    if(r.kind==='web_shell'){const mode=input(p,'child_match','Alert on',r.child_match||'listed','text',['any','listed']);mode.options[0].textContent='Any program except approved exclusions (recommended)';mode.options[1].textContent='Only the programs listed below';}
    ['parents','scoped_parents','required_role','excluded_children','children'].forEach(k=>{if(k in r)input(p,k,({parents:'Web server programs',scoped_parents:'Programs that require a host role',required_role:'Required host role',excluded_children:'Approved programs to exclude',children:'Programs to watch (listed mode only)'}[k]||k.replaceAll('_',' '))+' (comma-separated)',r[k]);});
    if(r.kind==='match'){const scope=input(p,'scope','Applies to',r.scope||'windows','text',['windows','all']);scope.options[0].textContent='Windows program and script activity';scope.options[1].textContent='All log sources';}
    $('addCondition').hidden=r.kind!=='match';
    if(r.kind==='match')r.conditions.forEach(condition);
    $('ruleEditor').hidden=false;$('ruleEditor').scrollIntoView({behavior:'smooth'});
  }
  function renderObjects(){
    [['hosts','hostRows'],['schedules','scheduleRows'],['exceptions','exceptionRows']].forEach(([section,id])=>{
      if(!$(id))return;$(id).replaceChildren();
      config[section].forEach((row,i)=>{
        const p=document.createElement('p');p.append(text('strong',row.name||row.hostname||row.id));
        const detail=section==='schedules'?` · ${row.start}–${row.end} ${row.timezone} · days ${row.weekdays.map(day=>DAYS[day]).join(', ')}`:section==='hosts'?` · ${row.timezone} · groups ${(row.groups||[]).join(', ')} · log monitoring ${row.telemetry_enabled?'enabled':'off'}`:` · rule ${MS.label(row.rule_id)} · expires ${row.expires_at} · ${row.ticket}`;
        p.append(document.createTextNode(detail));button('Edit',()=>editObject(section,i),p,true);button('Delete from draft',()=>{config[section].splice(i,1);draft();},p,true);$(id).append(p);
      });
    });
  }
  const objectSchema={
    hosts:[['hostname','Host name (with or without its domain)'],['timezone','Time zone (for example Asia/Taipei)'],['groups','Groups (comma-separated)','list'],['roles','Roles (comma-separated)','list'],['telemetry_enabled','Warn if expected logs stop arriving','bool'],['max_silence_seconds','Warn after no logs for (seconds)','number'],['expected_sources','Expected Windows activity','list']],
    schedules:[['id','Reference (unique name)'],['name','Name'],['timezone','Time zone (for example Asia/Taipei)'],['hosts','Host names (separate with commas)','list'],['groups','Groups (comma-separated)','list'],['weekdays','Days of the week','ints'],['start','Start (HH:MM)','time'],['end','End time (activity at this time is outside the window)','time'],['dates','Additional approved dates YYYY-MM-DD','list'],['exclude_dates','Excluded dates / holidays YYYY-MM-DD','list'],['exception_only','Only for a scoped exception (does not approve other shells)','bool']],
    exceptions:[['id','Reference (unique name)'],['rule_id','Rule this exception applies to'],['hosts','Exact hostnames','list'],['groups','Groups','list'],['process_path','Full executable path'],['parent_path','Full parent path'],['command_glob','Approved command pattern (* matches any text; ? matches one character)'],['user','Exact user / service account'],['schedule_id','Approved hours'],['expires_at','Expires at (include time zone, for example 2026-12-31T23:59:00+08:00)'],['ticket','Approval / change ticket']]
  };
  function editObject(section,i,isNew=false){
    editingObject={section,i,isNew};const row=config[section][i],p=$('objectFields');p.replaceChildren();$('objectTitle').textContent={hosts:'Edit host settings',schedules:'Edit approved hours',exceptions:'Edit approved exception'}[section];
    objectSchema[section].forEach(([k,label,type])=>{
      if(k==='weekdays'){choices(p,k,label,row[k],DAYS.map((name,day)=>[day,name]));return;}
      if(k==='expected_sources'){const options=[...new Set(['security_4688','sysmon_1','powershell_4104',...(row[k]||[])])];choices(p,k,label,row[k],options.map(source=>[source,MS.label(source)]));return;}
      let options=null;
      if(k==='id'){const ref=input(p,k,label,row[k],'hidden');ref.parentElement.hidden=true;return;}
      if(k==='rule_id')options=[{value:'',label:'Choose a rule'},...config.rules.filter(rule=>['out_of_hours_shell','nxlog_severity_event','high_severity_event'].includes(rule.id)||(rule.kind==='match'&&(rule.scope||'windows')==='windows')).map(rule=>({value:rule.id,label:rule.name}))];
      if(k==='schedule_id')options=[{value:'',label:'Choose approved hours'},...config.schedules.map(schedule=>({value:schedule.id,label:schedule.name||schedule.id}))];
      if(options&&row[k]&&!options.some(option=>option.value===row[k]))options.push({value:row[k],label:row[k]+' (not found — choose a replacement)'});
      input(p,k,label,row[k],type==='bool'?'checkbox':type==='number'?'number':type==='time'?'time':'text',options);
    });
    $('objectEditor').hidden=false;$('objectEditor').scrollIntoView({behavior:'smooth'});
  }
  function render(){renderRules();renderObjects();}
  async function load(){
    config=await api('/api/detection/config');dirty=false;const warning=config.load_warning;delete config.load_warning;render();
    if(warning)status(warning,true);else status(`Settings saved${config.updated_by?' · '+config.updated_by+' · '+config.updated_at:''}`);
  }
  async function unprofiled(){
    const box=$('unprofiledRows');if(!box)return;const rows=await api('/api/detection/unprofiled-hosts');box.replaceChildren();
    if(!rows.length){box.append(text('p','Every Windows host recently sending process/script events has a profile.'));return;}
    box.append(text('p',`${rows.length} Windows host(s) sent process/script events without a profile. Their timezone, roles, schedules and exceptions do not apply until one is added:`));
    rows.forEach(h=>{const p=document.createElement('p');p.append(text('strong',h.hostname));p.append(document.createTextNode(` · last seen ${MS.fmtTime(h.last_seen)} (${MS.fmtAgo(h.last_seen)}) · ${(h.sources||[]).join(', ')}`));
      button('Add profile',()=>{config.hosts.push({hostname:h.hostname,timezone:'Asia/Taipei',groups:[],roles:[],telemetry_enabled:false,max_silence_seconds:3600,expected_sources:['security_4688']});draft();editObject('hosts',config.hosts.length-1,true);},p,true);box.append(p);});
  }
  async function telemetry(){
    const d=await api('/api/detection/telemetry');$('telemetryRows').replaceChildren();
    if(!Object.keys(d).length)$('telemetryRows').append(text('p','No log delivery checks yet. Enable monitoring for a host above, then check the log collection service in System Health.'));
    Object.entries(d).forEach(([key,v])=>$('telemetryRows').append(text('p',`${key.split('|').map(part=>MS.label(part)).join(' · ')}: ${MS.label(v.status)} · last receipt ${v.last_received_at?MS.fmtTime(v.last_received_at)+' ('+MS.fmtAgo(v.last_received_at)+')':'not yet received'} · checked ${MS.fmtTime(v.checked_at)}`)));
  }
  if($('saveDetection'))$('saveDetection').onclick=async()=>{try{config=await api('/api/detection/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)});dirty=false;render();status(`Changes saved. Detection updates within five seconds.`);}catch(e){status(e.message,true);}};
  if($('reloadDetection'))$('reloadDetection').onclick=()=>{if(dirty&&!confirm('Discard unsaved changes and reload the saved settings?'))return;load().catch(e=>status(e.message,true));};
  if($('newRule')){
    $('newRule').disabled=!editable;$('newRule').onclick=()=>{config.rules.push({id:'custom_'+Date.now(),name:'New detection rule',kind:'match',scope:'windows',enabled:true,severity:'warning',conditions:[{field:'process.name',op:'equals',value:'cmd.exe'}]});draft();editRule(config.rules.length-1,true);};
    $('addCondition').onclick=()=>condition();$('cancelRule').onclick=()=>{if(editingRule.isNew){config.rules.splice(editingRule.i,1);draft();}$('ruleEditor').hidden=true;};
    $('ruleForm').onsubmit=e=>{e.preventDefault();const r=config.rules[editingRule.i],f=e.target;r.name=value(f,'name');r.severity=value(f,'severity');['threshold','window_seconds'].forEach(k=>{if(k in r)r[k]=Number(value(f,k));});['children','parents','scoped_parents','excluded_children'].forEach(k=>{if(k in r)r[k]=csv(value(f,k));});if(r.kind==='web_shell')r.child_match=value(f,'child_match');if('required_role'in r)r.required_role=value(f,'required_role');if(r.kind==='match')r.scope=value(f,'scope');if(r.kind==='match')r.conditions=[...$('conditionRows').children].map(row=>Object.fromEntries([...row.querySelectorAll('[data-key]')].map(el=>[el.dataset.key,el.value])));$('ruleEditor').hidden=true;draft();};
    $('simulationEvent').value=JSON.stringify({EventID:4688,Channel:'Security',SourceName:'Microsoft-Windows-Security-Auditing',Hostname:'HMSWEB1',EventTime:'2026-10-15T22:56:35+08:00',NewProcessName:'C:\\Windows\\System32\\cmd.exe',ParentProcessName:'C:\\Tomcat\\tomcat7.exe',NewProcessId:'0x2bc',ProcessId:'0xe74',CommandLine:'cmd.exe /c whoami',SubjectUserName:'SYSTEM'},null,2);
    $('simulateRule').onclick=async()=>{try{const d=await api('/api/detection/simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify((()=>{const t=$('simulationEvent').value;let parsed=null;try{parsed=JSON.parse(t);}catch{}return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?{event:parsed,config}:{raw:t,config};})())});const summary=$('simulationSummary');summary.replaceChildren();
      summary.append(text('strong',d.findings.length?`${d.findings.length} alert rule(s) matched`:'No alert rules matched this sample'));
      d.findings.forEach(finding=>summary.append(text('p',MS.label(finding.rule_id)+' · '+MS.alertSeverity(finding.severity))));
      if(d.time_status&&d.time_status!=='valid')summary.append(text('p','Time-based rules could not be checked. Include a time zone in the event or set the host time zone.'));
      summary.append(text('p','Preview only. No events or alerts were saved. Repeated-activity rules are not tested with a single sample.'));
      $('simulationResult').textContent=JSON.stringify(d,null,2);}catch(e){$('simulationSummary').textContent='The sample could not be tested. Check the event and rule settings below.';$('simulationResult').textContent=e.message;}};
  }
  if($('newHost')){
    const add=(section,row)=>{config[section].push(row);draft();editObject(section,config[section].length-1,true);};
    ['newHost','newSchedule','newException'].forEach(id=>$(id).disabled=!editable);
    $('newHost').onclick=()=>add('hosts',{hostname:'NEW-HOST',timezone:'Asia/Taipei',groups:[],roles:[],telemetry_enabled:false,max_silence_seconds:3600,expected_sources:['security_4688']});
    $('newSchedule').onclick=()=>add('schedules',{id:'window_'+Date.now(),name:'Business hours',timezone:'Asia/Taipei',hosts:[],groups:[],weekdays:[0,1,2,3,4],start:'09:00',end:'18:00',dates:[],exclude_dates:[]});
    $('newException').onclick=()=>add('exceptions',{id:'exception_'+Date.now(),rule_id:'out_of_hours_shell',hosts:[],groups:[],process_path:'',parent_path:'',command_glob:'',user:'',schedule_id:'',expires_at:'',approved_by:'recorded on save',ticket:''});
    $('cancelObject').onclick=()=>{if(editingObject.isNew){config[editingObject.section].splice(editingObject.i,1);draft();}$('objectEditor').hidden=true;};
    $('objectForm').onsubmit=e=>{e.preventDefault();const {section,i}=editingObject,row=config[section][i];objectSchema[section].forEach(([k,label,type])=>{row[k]=objectValue(e.target,k,type);});$('objectEditor').hidden=true;draft();};
    $('refreshTelemetry').onclick=()=>Promise.all([telemetry(),unprofiled()]).catch(e=>status(e.message,true));
  }
  load().then(()=>{if($('telemetryRows'))return Promise.all([telemetry(),unprofiled()]);}).catch(e=>status(e.message,true));
})();
