"""Run real renderers with inert hostile text, then parse output without executing it."""
import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]


class Markup(HTMLParser):
    def __init__(self,html):
        super().__init__(convert_charrefs=True);self.tags=[];self.attrs=[];self.text=[];self.feed(html)
    def handle_starttag(self,tag,attrs):self.tags.append(tag);self.attrs.append(dict(attrs))
    def handle_data(self,value):self.text.append(value)


def run(code):
    node=shutil.which('node')
    if not node:pytest.skip('Node required for UI runtime validation')
    return subprocess.run([node,'-e',code,str(ROOT)],check=True,capture_output=True,text=True).stdout


def test_fields_chips_columns_and_filters_are_text_with_exact_round_trip():
    data=json.loads(run(r'''
const fs=require('node:fs'),vm=require('node:vm');
const src=fs.readFileSync(process.argv[1]+'/templates/index.html','utf8');
const esc=src.match(/function _esc\(v\)[^\n]*/)[0];
const row=src.slice(src.indexOf('function fieldRow([k,v])'),src.indexOf("      body.querySelectorAll('.fieldpick')"));
const chips=src.slice(src.indexOf('function renderFieldChips()'),src.indexOf('\nfunction ',src.indexOf('function renderFieldChips()')+1));
const columns=src.slice(src.indexOf('function renderXColumns()'),src.indexOf('\nfunction currentFilterParams()'));
const key='<img src=x onerror="void(0)">',value='&quot;><svg onload="void(0)">\'&';
const el=()=>({style:{},innerHTML:'',querySelectorAll(){return [];},addEventListener(){}});
const elements={fieldChips:el(),logsHead:el(),xfilterBar:el()};
const s={xCols:[key],fieldChips:[{field:key,value}],fieldChipOp:'and',baseSort:'',baseDir:'asc',xSort:'',xDir:'asc',document:{getElementById(id){return elements[id];}},loadLogs(){}};
vm.runInNewContext(esc+'\n'+row+'\n'+chips+'\n'+columns,s);
const field=s.fieldRow([key,value]);s.renderFieldChips();s.renderXColumns();
console.log(JSON.stringify({key,value,field,chips:elements.fieldChips.innerHTML,columns:elements.logsHead.innerHTML,filters:elements.xfilterBar.innerHTML}));
'''))
    for key in ('field','chips','columns','filters'):
        parsed=Markup(data[key])
        assert not set(parsed.tags)&{'img','svg','script','iframe'},key
        assert all(not name.lower().startswith('on') for attrs in parsed.attrs for name in attrs),key
    fields=[a for a in Markup(data['field']).attrs if 'data-field' in a]
    assert len(fields)==2 and all(a['data-field']==data['key'] and a['data-value']==data['value'] for a in fields)


def test_account_names_never_become_inline_javascript():
    data=json.loads(run(r'''
const fs=require('node:fs'),vm=require('node:vm');
const src=fs.readFileSync(process.argv[1]+'/templates/setup.html','utf8');
const esc=src.match(/function esc\(s\)[^\n]*/)[0];
const load=src.slice(src.indexOf('async function loadUsers()'),src.indexOf('\nasync function delUser('));
const key='name\');void(0);//"<img src=x>&quot;',body={innerHTML:''};
const s={IS_ADMIN:true,window:{_role:'admin'},document:{getElementById(){return body;}},MS:{getJSON:async()=>[{username:key,role:'viewer',auth_source:'oauth'}]}};
vm.runInNewContext(esc+'\n'+load,s);
s.loadUsers().then(()=>console.log(JSON.stringify({key,html:body.innerHTML}))).catch(e=>{console.error(e);process.exitCode=1;});
'''))
    parsed=Markup(data['html'])
    assert not set(parsed.tags)&{'img','script'}
    assert all(not name.lower().startswith('on') for attrs in parsed.attrs for name in attrs)
    assert any(a.get('data-username')==data['key'] for a in parsed.attrs)
    source=(ROOT/'templates/setup.html').read_text(encoding='utf-8')
    assert 'onclick="deleteFw(' not in source and 'onclick="delApiKey(' not in source
