import argparse 
import json 
import os 
import re 
import sys 
from pathlib import Path 
from typing import Optional ,Tuple 

import requests 


def read_text_file (path :Path ,max_chars :Optional [int ]=None )->str :
	if not path .exists ():
		raise FileNotFoundError (f"File not found: {path }")
	text =path .read_text (encoding ='utf-8',errors ='ignore')
	if max_chars is not None and len (text )>max_chars :
		return text [:max_chars ]+'\n\n...[truncated]...\n'
	return text 


def normalize_event_name (name :str )->str :

	s =name .strip ().lower ()
	s =re .sub ('[\\s\\-_]+',' ',s )
	s =re .sub ('[^a-z0-9()\\. ]+','',s )
	s =s .strip ()
	return s 


def find_event_file (base_dir :Path ,event_name :str ,prefer_exts :Tuple [str ,...])->Optional [Path ]:

	if not base_dir .exists ():
		return None 

	normalized_target =normalize_event_name (event_name )
	candidates =[]
	for p in base_dir .iterdir ():
		if not p .is_file ():
			continue 
		if prefer_exts and p .suffix .lower ()not in tuple (ext .lower ()for ext in prefer_exts ):
			continue 
		base =p .stem 
		norm_base =normalize_event_name (base )
		candidates .append ((norm_base ,base ,p ))


	for norm_base ,_base ,p in candidates :
		if norm_base ==normalized_target :
			return p 


	for _norm_base ,base ,p in candidates :
		if base .lower ()==event_name .lower ():
			return p 


	for norm_base ,_base ,p in candidates :
		if norm_base .startswith (normalized_target ):
			return p 

	return None 


def build_contracts_report (
contracts_dir :Path ,
mythril_dir :Path ,
event_name :str ,
max_chars_each :Optional [int ]=None ,
)->str :
	contracts_path =find_event_file (contracts_dir ,event_name ,prefer_exts =('.md','.txt'))
	mythril_path =find_event_file (mythril_dir ,event_name ,prefer_exts =('.md','.txt'))

	sections =[]
	if mythril_path is not None :
		sections .append (f"--- Mythril Report ({mythril_path .name }) ---\n\n"+read_text_file (mythril_path ,max_chars_each ))
	else :
		sections .append ('--- Mythril Report ---\n\n[]\n')

	if contracts_path is not None :
		sections .append (f"--- Contract Report ({contracts_path .name }) ---\n\n"+read_text_file (contracts_path ,max_chars_each ))
	else :
		sections .append ('--- Contract Report ---\n\n[]\n')

	return '\n\n'.join (sections )


def load_transaction_trace (trace_json_path :Path ,max_chars :Optional [int ]=None )->Tuple [str ,Optional [str ]]:
	if not trace_json_path .exists ():
		raise FileNotFoundError (f"Trace JSON not found: {trace_json_path }")
	text =trace_json_path .read_text (encoding ='utf-8',errors ='ignore')
	if max_chars is not None and len (text )>max_chars :
		text_display =text [:max_chars ]+'\n\n...[truncated]...\n'
	else :
		text_display =text 

	attacker_addr :Optional [str ]=None 
	try :
		j =json .loads (text )
		if isinstance (j ,dict )and isinstance (j .get ('attacker'),str ):
			attacker_addr =j .get ('attacker')
	except Exception :
		attacker_addr =None 
	return text_display ,attacker_addr 


def compose_prompt (template_base :str ,transaction_trace :str ,contracts_report :str ,target_contract :Optional [str ])->str :
	prompt =template_base .replace ('{transaction_trace}',transaction_trace )
	prompt =prompt .replace ('{contracts_report}',contracts_report )
	if target_contract :
		prompt =prompt .replace ('{target_contract}',target_contract )
	else :
		prompt =prompt .replace ('{target_contract}','[UNKNOWN_ATTACKER_CONTRACT]')
	return prompt 


def call_openrouter (
api_base :str ,
api_key :str ,
model :str ,
prompt :str ,
temperature :float =0.3 ,
max_tokens :Optional [int ]=None ,
referer :Optional [str ]=None ,
title :Optional [str ]=None ,
timeout_sec :float =120.0 ,
)->str :
	headers ={
	'Authorization':f"Bearer {api_key }",
	'Content-Type':'application/json',
	}
	if referer :
		headers ['HTTP-Referer']=referer 
	if title :
		headers ['X-Title']=title 

	payload ={
	'model':model ,
	'messages':[
	{'role':'user','content':prompt },
	],
	'temperature':temperature ,
	}
	if max_tokens is not None :
		payload ['max_tokens']=max_tokens 

	url =f"{api_base .rstrip ('/')}/chat/completions"
	resp =requests .post (url ,headers =headers ,json =payload ,timeout =timeout_sec )
	if resp .status_code !=200 :
		raise RuntimeError (f"OpenRouter HTTP {resp .status_code }: {resp .text }")
	data =resp .json ()
	try :
		return data ['choices'][0 ]['message']['content']
	except Exception as exc :
		raise RuntimeError (f"Unexpected OpenRouter response: {data }")from exc 


def default_prompt_template ()->str :
	return (
	'Based on the provided victim contract report and transaction trace, generate a definitive security analysis report:\n'
	'# Transaction Results\n'
	'{transaction_trace}\n\n'
	'# Victim Contract Report\n'
	'{contracts_report}\n\n'
	'## CRITICAL ANALYSIS REQUIREMENTS\n\n'
	'1. **IDENTIFY THE VICTIM CONTRACT** - The target address provided is the attacker/exploit contract, NOT the victim. You must first analyze the call graph to determine which contract was actually exploited. The victim is typically a protocol or service contract that lost assets, not a basic token contract.\n\n'
	'2. **IDENTIFY EXPLOITATION PATTERN** - After identifying the victim contract, analyze its code to find the specific vulnerable function(s). Quote the exact vulnerable code segments.\n\n'
	'4. **PRECISE ATTACK RECONSTRUCTION** - Document the exact attack sequence with specific function calls and transaction evidence. Avoid speculation.\n\n'
	'5. **RUGPULL DETECTION** - Specifically check for signs of a rugpull attack, including:\n'
	'- Contract owner/creator suddenly removing significant liquidity from pools\n'
	'- Suspicious privilege functions (unlimited minting, freezing transfers, changing fees)\n'
	'- Backdoor functions allowing creators to bypass safety mechanisms\n'
	'- Sudden large transfers of tokens to exchanges\n'
	'- Suspicious timing of privileged operations (e.g., modifying contract then draining funds)\n\n'
	'## Output Format\n\n'
	'# Security Incident Analysis Report\n\n'
	'## Attack Overview\n'
	'[Brief overview identifying the attack type (including rugpull if applicable) and affected protocol/contract]\n\n'
	'## Contract Identification\n'
	'- Attacker Contract: `{target_contract}` [Brief analysis]\n'
	'- Victim Contract: [Identified vulnerable contract address with explanation of how you determined this is the victim]\n'
	'- Helper Contracts: [Any contracts created by the attacker that participated in the exploit]\n\n'
	'## Vulnerability Analysis\n'
	'[Analysis of the specific vulnerability in the victim contract with exact function and code references]\n\n'
	'## Exploitation Mechanism\n'
	'[Technical explanation of how the vulnerability was exploited, referencing both victim and attacker code]\n\n'
	)


def sanitize_filename (name :str )->str :
	name =name .strip ().replace ('/','_')
	name =re .sub ('[^a-zA-Z0-9._\\-() ]+','',name )
	name =name .replace (' ','_')
	return name or 'analysis_report'


def main ()->None :
	parser =argparse .ArgumentParser (description ='Run OpenRouter-based security analysis for a given event.')
	parser .add_argument ('--event',required =True ,help =" 'Zunami Protocol'")
	parser .add_argument ('--trace-json',required =True ,help =' JSON attacker_trace_cli.py ')
	parser .add_argument ('--contracts-dir',default ='/home/os/yuehuang/Contract_analysis_llm/contracts',help ='contracts .md/.txt')
	parser .add_argument ('--mythril-dir',default ='/home/os/zhuoer/mythril',help ='mythril .md/.txt')
	parser .add_argument ('--api-base',default ='https://openrouter.ai/api/v1',help ='OpenRouter API Base URL')
	parser .add_argument ('--model',default ='google/gemini-2.0-flash-001',help ='')
	parser .add_argument ('--api-key',default =os .getenv ('OPENROUTER_API_KEY',''),help ='OpenRouter API Key OPENROUTER_API_KEY')
	parser .add_argument ('--referer',default =os .getenv ('OPENROUTER_REFERER',''),help ='HTTP-Referer ')
	parser .add_argument ('--title',default =os .getenv ('OPENROUTER_TITLE',''),help ='X-Title ')
	parser .add_argument ('--temperature',type =float ,default =0.3 ,help ='')
	parser .add_argument ('--max-tokens',type =int ,default =None ,help =' tokens')
	parser .add_argument ('--max-chars-report',type =int ,default =None ,help ='')
	parser .add_argument ('--max-chars-trace',type =int ,default =None ,help =' trace JSON ')
	parser .add_argument ('--output',default ='',help =' Markdown  ./analysis_outputs/<event>.md')

	args =parser .parse_args ()

	if not args .api_key :
		raise SystemExit (' API Key--api-key  OPENROUTER_API_KEY')

	contracts_dir =Path (args .contracts_dir ).expanduser ()
	mythril_dir =Path (args .mythril_dir ).expanduser ()
	trace_path =Path (args .trace_json ).expanduser ()


	contracts_report =build_contracts_report (contracts_dir ,mythril_dir ,args .event ,max_chars_each =args .max_chars_report )
	trace_text ,target_attacker =load_transaction_trace (trace_path ,max_chars =args .max_chars_trace )


	template =default_prompt_template ()
	full_prompt =compose_prompt (template ,transaction_trace =trace_text ,contracts_report =contracts_report ,target_contract =target_attacker )


	analysis_markdown =call_openrouter (
	api_base =args .api_base ,
	api_key =args .api_key ,
	model =args .model ,
	prompt =full_prompt ,
	temperature =args .temperature ,
	max_tokens =args .max_tokens ,
	referer =args .referer or None ,
	title =args .title or None ,
	)


	output_path :Path 
	if args .output :
		output_path =Path (args .output ).expanduser ()
	else :
		out_dir =Path .cwd ()/'analysis_outputs'
		out_dir .mkdir (parents =True ,exist_ok =True )
		output_path =out_dir /f"{sanitize_filename (args .event )}.md"

	output_path .parent .mkdir (parents =True ,exist_ok =True )
	output_path .write_text (analysis_markdown ,encoding ='utf-8')
	print (f": {output_path }")


if __name__ =='__main__':
	main ()