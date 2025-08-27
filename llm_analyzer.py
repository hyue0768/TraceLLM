



import os 
import sys 
import json 
import time 
import requests 
from typing import Dict ,List ,Tuple ,Any ,Optional 
from datetime import datetime 
import logging 


sys .path .append ('/home/os/shuzheng/whole_pipeline/src')
from config .settings import Settings 

logger =logging .getLogger (__name__ )


class LLMAnalyzer :


    def __init__ (self ):

        self .settings =Settings ()


        self .api_key =self .settings .APIKEY 
        self .base_url =self .settings .BASEURL 
        self .model_name =self .settings .MODELNAME 

        if not self .api_key or not self .base_url or not self .model_name :
            raise ValueError ('LLM APIKEY, BASEURL, MODELNAME')


        if not self .base_url .endswith ('/'):
            self .base_url +='/'
        if not self .base_url .endswith ('v1/'):
            self .base_url +='v1/'

        logger .info (f"LLM")
        logger .info (f"  - : {self .model_name }")
        logger .info (f"  - : {self .base_url }")

    def build_attacker_victim_prompt (self ,contexts :List [Dict [str ,Any ]],
    event_name :str ,k_neighbors :int )->str :

        prompt_parts =[]


        prompt_parts .append ('Top-30K\n\n⚠️ \n\n\n1. ATTACKER ADDRESS - \n2. VICTIM ADDRESS - \n\n\n- /\n- \n- \n- \n- \n\n')


        prompt_parts .append (f"===  ===\n")
        prompt_parts .append (f": {event_name }\n")
        prompt_parts .append (f": K={k_neighbors }\n")
        prompt_parts .append (f": {len (contexts )}\n")
        if k_neighbors >0 :
            prompt_parts .append (f": K={k_neighbors }{k_neighbors }\n")
        else :
            prompt_parts .append (f": K=0\n")
        prompt_parts .append ('\n')


        all_addresses =set ()
        for i ,context in enumerate (contexts ,1 ):
            prompt_parts .append (f"===  {i } () ===\n")


            target_path_id =context .get ('target_path_id',context .get ('path_id','unknown'))
            prompt_parts .append (f"ID: {target_path_id }\n")
            prompt_parts .append (f"Hash: {context .get ('tx_hash','unknown')}\n")
            prompt_parts .append (f": {context .get ('source_file','unknown')}\n")


            layer_stats =context .get ('layer_statistics',{})
            prompt_parts .append (f":\n")
            prompt_parts .append (f"  - : K={layer_stats .get ('expansion_layers',k_neighbors )}\n")
            prompt_parts .append (f"  - : {layer_stats .get ('total_paths',1 )}\n")
            prompt_parts .append (f"  - : {layer_stats .get ('total_nodes',0 )}\n")
            prompt_parts .append (f"  - : {layer_stats .get ('target_path_length',0 )}\n")


            related_paths =context .get ('related_paths',{})
            path_details =context .get ('path_details',{})

            if related_paths :
                prompt_parts .append (f"\n ({len (related_paths )}):\n")

                for j ,(path_id ,node_ids )in enumerate (related_paths .items (),1 ):
                    path_detail =path_details .get (path_id ,{})
                    is_target =path_detail .get ('is_target',False )
                    methods =path_detail .get ('methods',[])

                    path_type ='🎯'if is_target else f"🔗"
                    prompt_parts .append (f"  {j }. {path_type } (ID: {path_id }):\n")

                    if methods :
                        path_sequence =' → '.join (methods )
                        prompt_parts .append (f"     : {path_sequence }\n")
                    else :
                        prompt_parts .append (f"     : {' → '.join (map (str ,node_ids ))}\n")


            node_details =context .get ('node_details',{})
            if node_details :
                target_nodes =related_paths .get (target_path_id ,[])
                expansion_nodes =[]
                for pid ,nodes in related_paths .items ():
                    if pid !=target_path_id :
                        expansion_nodes .extend (nodes )

                prompt_parts .append (f"\n🎯:\n")
                for node_id in target_nodes [:10 ]:
                    if node_id in node_details :
                        detail =node_details [node_id ]
                        method =detail .get ('method','unknown')
                        depth =detail .get ('depth',0 )
                        is_suspicious =detail .get ('is_suspicious',False )

                        sus_mark =' [🚨]'if is_suspicious else ''
                        prompt_parts .append (f"  - {method } (:{depth }){sus_mark }\n")

                if k_neighbors >0 and expansion_nodes :
                    prompt_parts .append (f"\n🔗 (K={k_neighbors }, {len (expansion_nodes )}):\n")
                    unique_expansion_nodes =list (set (expansion_nodes ))[:15 ]
                    for node_id in unique_expansion_nodes :
                        if node_id in node_details :
                            detail =node_details [node_id ]
                            method =detail .get ('method','unknown')
                            depth =detail .get ('depth',0 )
                            is_suspicious =detail .get ('is_suspicious',False )

                            sus_mark =' [🚨]'if is_suspicious else ''
                            prompt_parts .append (f"  - {method } (:{depth }){sus_mark }\n")

                    if len (expansion_nodes )>15 :
                        prompt_parts .append (f"  ...  {len (expansion_nodes )-15 } \n")

            prompt_parts .append ('\n'+'-'*60 +'\n\n')


        prompt_parts .append ('===  ===\n⚠️ Top-30\n\n\n\n1. ATTACKER ADDRESS:\n   - \n   - \n   - \n   - \n\n2. VICTIM ADDRESS:\n   - \n   - \n   - \n   - \n\n\n- \n- \n- \n- K\n\nJSON\n```json\n{\n  "analysis": {\n    "summary": "",\n    "attack_pattern": "",\n    "suspicious_indicators": ""\n  },\n  "attacker_address": "0x...",\n  "victim_address": "0x...",\n  "confidence": {\n    "attacker": "HIGH/MEDIUM/LOW",\n    "victim": "HIGH/MEDIUM/LOW"\n  },\n  "reasoning": {\n    "attacker": "",\n    "victim": ""\n  },\n  "path_evidence": {\n    "key_suspicious_paths": "ID",\n    "attack_flow": ""\n  }\n}\n```\n\n\n- \n- \n- \n')

        return ''.join (prompt_parts )

    def call_llm (self ,prompt :str ,max_retries :int =3 )->Dict [str ,Any ]:

        headers ={
        'Authorization':f"Bearer {self .api_key }",
        'Content-Type':'application/json'
        }

        data ={
        'model':self .model_name ,
        'messages':[
        {
        'role':'system',
        'content':'traceTop 30'
        },
        {
        'role':'user',
        'content':prompt 
        }
        ],
        'temperature':0.1 ,
        'max_tokens':4000 
        }

        for attempt in range (max_retries ):
            try :
                response =requests .post (
                f"{self .base_url }chat/completions",
                headers =headers ,
                json =data ,
                timeout =300 
                )

                if response .status_code ==200 :
                    result =response .json ()


                    content =result ['choices'][0 ]['message']['content']
                    usage =result .get ('usage',{})

                    return {
                    'success':True ,
                    'content':content ,
                    'prompt_tokens':usage .get ('prompt_tokens',0 ),
                    'completion_tokens':usage .get ('completion_tokens',0 ),
                    'total_tokens':usage .get ('total_tokens',0 ),
                    'model':self .model_name ,
                    'timestamp':datetime .now ().isoformat ()
                    }
                else :
                    logger .warning (f"LLM API ( {attempt +1 }/{max_retries }): "
                    f" {response .status_code }, : {response .text }")

            except requests .exceptions .Timeout :
                logger .warning (f"LLM API ( {attempt +1 }/{max_retries })")

            except Exception as e :
                logger .warning (f"LLM API ( {attempt +1 }/{max_retries }): {str (e )}")

            if attempt <max_retries -1 :
                time .sleep (2 **attempt )

        return {
        'success':False ,
        'error':'LLM API',
        'prompt_tokens':0 ,
        'completion_tokens':0 ,
        'total_tokens':0 
        }

    def parse_llm_response (self ,response_content :str )->Dict [str ,Any ]:

        try :

            start_idx =response_content .find ('{')
            end_idx =response_content .rfind ('}')

            if start_idx !=-1 and end_idx !=-1 :
                json_str =response_content [start_idx :end_idx +1 ]
                parsed =json .loads (json_str )


                required_fields =['attacker_address','victim_address']
                for field in required_fields :
                    if field not in parsed :
                        parsed [field ]='UNKNOWN'

                return {
                'success':True ,
                'parsed_result':parsed ,
                'raw_response':response_content 
                }
            else :

                return {
                'success':False ,
                'error':'No valid JSON found in response',
                'raw_response':response_content ,
                'parsed_result':{
                'attacker_address':'UNKNOWN',
                'victim_address':'UNKNOWN',
                'analysis':{'summary':response_content [:200 ]+'...'}
                }
                }

        except json .JSONDecodeError as e :
            logger .warning (f"JSON: {str (e )}")
            return {
            'success':False ,
            'error':f'JSON parsing failed: {str (e )}',
            'raw_response':response_content ,
            'parsed_result':{
            'attacker_address':'UNKNOWN',
            'victim_address':'UNKNOWN',
            'analysis':{'summary':response_content [:200 ]+'...'}
            }
            }

    def analyze_event_contexts (self ,event_contexts :Dict [str ,Any ],
    k_neighbors :int )->Dict [str ,Any ]:

        if not event_contexts :
            return {
            'success':False ,
            'error':'No contexts provided',
            'k_neighbors':k_neighbors 
            }


        first_context =list (event_contexts .values ())[0 ]


        event_name ='Unknown Event'
        if 'source_file'in first_context :

            source_file =first_context ['source_file']
            if 'event_'in source_file :
                parts =source_file .split ('_')
                if len (parts )>=3 :
                    event_name ='_'.join (parts [1 :4 ])


        node_details =first_context .get ('node_details',{})
        for node_id ,detail in node_details .items ():
            path_info =detail .get ('path_info')
            if path_info and isinstance (path_info ,dict ):
                if 'event_name'in path_info :
                    event_name =path_info ['event_name']
                    break 

        logger .info (f": {event_name }, K={k_neighbors }, : {len (event_contexts )}")


        contexts_list =list (event_contexts .values ())
        prompt =self .build_attacker_victim_prompt (contexts_list ,event_name ,k_neighbors )


        llm_result =self .call_llm (prompt )

        if not llm_result ['success']:
            return {
            'success':False ,
            'error':llm_result .get ('error','LLM call failed'),
            'k_neighbors':k_neighbors ,
            'event_name':event_name ,
            'prompt_length':len (prompt ),
            'token_usage':{
            'prompt_tokens':0 ,
            'completion_tokens':0 ,
            'total_tokens':0 
            }
            }


        parsed_result =self .parse_llm_response (llm_result ['content'])


        result ={
        'success':True ,
        'event_name':event_name ,
        'k_neighbors':k_neighbors ,
        'num_paths':len (event_contexts ),
        'prompt_length':len (prompt ),
        'token_usage':{
        'prompt_tokens':llm_result ['prompt_tokens'],
        'completion_tokens':llm_result ['completion_tokens'],
        'total_tokens':llm_result ['total_tokens']
        },
        'llm_response':{
        'raw_content':llm_result ['content'],
        'parsing_success':parsed_result ['success'],
        'parsed_data':parsed_result ['parsed_result']
        },
        'identified_addresses':{
        'attacker':parsed_result ['parsed_result'].get ('attacker_address','UNKNOWN'),
        'victim':parsed_result ['parsed_result'].get ('victim_address','UNKNOWN')
        },
        'analysis_timestamp':datetime .now ().isoformat ()
        }

        logger .info (f"✅  {event_name } ")
        logger .info (f"  - Token: {result ['token_usage']['total_tokens']}")
        logger .info (f"  - : {result ['identified_addresses']['attacker']}")
        logger .info (f"  - : {result ['identified_addresses']['victim']}")

        return result 


if __name__ =='__main__':

    logging .basicConfig (level =logging .INFO ,format ='%(asctime)s - %(levelname)s - %(message)s')

    try :
        analyzer =LLMAnalyzer ()
        print (f"LLM")
        print (f": {analyzer .model_name }")
        print (f": {analyzer .base_url }")

    except Exception as e :
        print (f": {e }")
        import traceback 
        traceback .print_exc ()