import argparse 
import json 
import os 
import re 
import sys 
from pathlib import Path 
from typing import Dict ,List ,Optional 

try :
	import pandas as pd 
except Exception :
	pd =None 

from run_openrouter_security_analysis import (
build_contracts_report ,
default_prompt_template ,
compose_prompt ,
call_openrouter ,
sanitize_filename ,
)


def require_pandas ()->None :
	if pd is None :
		raise SystemExit (' pandas  Excel/CSV: pip install pandas openpyxl')


def normalize_header (name :str )->str :
	return re .sub ('\\s+','',name .strip ().lower ())


def resolve_columns (headers :List [str ])->Dict [str ,str ]:
	cands :Dict [str ,List [str ]]={
	'event':['event','name','','','',''],
	'trace_path':['trace','trace_path','tracejson','trace_json','','',''],
	}
	normalized ={normalize_header (h ):h for h in headers }
	mapping :Dict [str ,str ]={}
	for key ,names in cands .items ():
		for n in names :
			nn =normalize_header (n )
			if nn in normalized :
				mapping [key ]=normalized [nn ]
				break 
	for req in ('event',):
		if req not in mapping :
			raise SystemExit (f": {req }")
	return mapping 


def load_rows (table_path :Path ,sheet :Optional [str ])->List [Dict [str ,str ]]:
	require_pandas ()
	if table_path .suffix .lower ()=='.csv':
		df =pd .read_csv (table_path )
	else :
		df =pd .read_excel (table_path ,sheet_name =sheet )if sheet else pd .read_excel (table_path )
	if df .empty :
		raise SystemExit ('')
	mapping =resolve_columns ([str (c )for c in df .columns ])
	rows :List [Dict [str ,str ]]=[]
	for _ ,r in df .iterrows ():
		try :
			event =str (r [mapping ['event']]).strip ()
			trace_path =str (r [mapping .get ('trace_path','')]).strip ()if 'trace_path'in mapping else ''
			rows .append ({'event':event ,'trace_path':trace_path })
		except Exception :
			continue 
	return rows 


def main ()->None :
	p =argparse .ArgumentParser (description =' trace JSON  OpenRouter')
	p .add_argument ('--table',required =False ,help ='Excel/CSV  traces ')
	p .add_argument ('--sheet',default =None ,help ='Excel sheet ')
	p .add_argument ('--contracts-dir',default ='/home/os/yuehuang/Contract_analysis_llm/contracts')
	p .add_argument ('--mythril-dir',default ='/home/os/zhuoer/mythril')
	p .add_argument ('--api-base',default ='https://openrouter.ai/api/v1')
	p .add_argument ('--model',default ='google/gemini-2.0-flash-001')
	p .add_argument ('--api-key',default =os .getenv ('OPENROUTER_API_KEY',''))
	p .add_argument ('--referer',default =os .getenv ('OPENROUTER_REFERER',''))
	p .add_argument ('--title',default =os .getenv ('OPENROUTER_TITLE',''))
	p .add_argument ('--max-chars-report',type =int ,default =None )
	p .add_argument ('--max-chars-trace',type =int ,default =None )
	p .add_argument ('--traces-dir',default =str ((Path .cwd ()/'traces').absolute ()))
	p .add_argument ('--out-analysis-dir',default =str ((Path .cwd ()/'analysis_outputs').absolute ()))
	p .add_argument ('--events',nargs ='*',default =[],help ='')
	args =p .parse_args ()

	if not args .api_key :
		raise SystemExit (' OpenRouter API Key--api-key  OPENROUTER_API_KEY')

	traces_dir =Path (args .traces_dir ).expanduser ()
	out_analysis_dir =Path (args .out_analysis_dir ).expanduser ()
	out_analysis_dir .mkdir (parents =True ,exist_ok =True )

	rows :List [Dict [str ,str ]]=[]
	if args .table :
		rows =load_rows (Path (args .table ).expanduser (),args .sheet )
	else :

		for p in traces_dir .glob ('*.json'):
			rows .append ({'event':p .stem ,'trace_path':str (p )})

	contracts_dir =Path (args .contracts_dir ).expanduser ()
	mythril_dir =Path (args .mythril_dir ).expanduser ()


	if args .events :
		rows =[]
		for ev in args .events :
			trace_file =traces_dir /f"{sanitize_filename (ev )}.json"
			rows .append ({'event':ev ,'trace_path':str (trace_file )})

	print (f" {len (rows )} ")
	for i ,it in enumerate (rows ,start =1 ):
		try :
			event =it ['event']
			trace_path =it .get ('trace_path')or str ((traces_dir /f"{sanitize_filename (event )}.json").absolute ())
			trace_file =Path (trace_path ).expanduser ()
			if not trace_file .exists ():
				raise RuntimeError (f"trace JSON : {trace_file }")

			trace_text =trace_file .read_text (encoding ='utf-8',errors ='ignore')
			if args .max_chars_trace is not None and len (trace_text )>args .max_chars_trace :
				trace_text =trace_text [:args .max_chars_trace ]+'\n\n...[truncated]...\n'
			try :
				trace_obj =json .loads (trace_file .read_text (encoding ='utf-8',errors ='ignore'))
			except Exception :
				trace_obj ={}
			attacker_addr =trace_obj .get ('attacker')if isinstance (trace_obj ,dict )else None 

			contracts_report =build_contracts_report (contracts_dir ,mythril_dir ,event ,max_chars_each =args .max_chars_report )
			template =default_prompt_template ()
			prompt =compose_prompt (template ,transaction_trace =trace_text ,contracts_report =contracts_report ,target_contract =attacker_addr )

			analysis_md =call_openrouter (
			api_base =args .api_base ,
			api_key =args .api_key ,
			model =args .model ,
			prompt =prompt ,
			temperature =0.3 ,
			max_tokens =None ,
			referer =args .referer or None ,
			title =args .title or None ,
			)

			out_path =out_analysis_dir /f"{sanitize_filename (event )}.md"
			out_path .write_text (analysis_md ,encoding ='utf-8')
			print (f"[{i }/{len (rows )}] : {out_path }")
		except Exception as exc :
			print (f"[{i }/{len (rows )}] : {it .get ('event','?')} | {exc }",file =sys .stderr )
			continue 

	print ('')


if __name__ =='__main__':
	main ()