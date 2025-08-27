



import os 
import json 
import pandas as pd 
from typing import Dict ,List ,Any 
from datetime import datetime 
import logging 

from contextual_path_analyzer import ContextualPathAnalyzer 
from llm_analyzer import LLMAnalyzer 

logger =logging .getLogger (__name__ )


class KValueComparisonAnalyzer :


    def __init__ (self ,k_paths :int =30 ,k_range :List [int ]=None ):

        self .k_paths =k_paths 
        self .k_range =k_range or [0 ,1 ,2 ,3 ,4 ,5 ]


        self .llm_analyzer =LLMAnalyzer ()

        logger .info (f"K")
        logger .info (f"  - Top-K: {k_paths }")
        logger .info (f"  - K: {self .k_range }")





    def run_full_comparison (self ,input_dir :str ,output_dir :str )->Dict [str ,Any ]:

        logger .info ('='*80 )
        logger .info ('K')
        logger .info ('='*80 )


        all_k_path_results ={}

        for k in self .k_range :
            logger .info (f"K={k }...")

            path_analyzer =ContextualPathAnalyzer (
            k_paths =self .k_paths ,
            k_neighbors =k 
            )


            k_path_results =path_analyzer .analyze_with_context (input_dir )
            all_k_path_results [k ]=k_path_results 

            if k_path_results ['path_contexts']:
                total_contexts =sum (len (contexts )for contexts in k_path_results ['path_contexts'].values ())
                logger .info (f"  K={k }:  {total_contexts } ")
            else :
                logger .warning (f"  K={k }: ")

        logger .info (f"✅ K")


        base_events =list (all_k_path_results [0 ]['path_contexts'].keys ())if 0 in all_k_path_results else []


        event_results ={}
        total_tokens_by_k ={k :0 for k in self .k_range }

        for event_name in base_events :
            logger .info (f"\n📊 : {event_name }")


            event_k_contexts ={}
            for k in self .k_range :
                if k in all_k_path_results and event_name in all_k_path_results [k ]['path_contexts']:
                    event_k_contexts [k ]=all_k_path_results [k ]['path_contexts'][event_name ]
                else :
                    logger .warning (f" {event_name } K={k }")
                    event_k_contexts [k ]={}


            k_results ={}
            for k in self .k_range :
                if event_k_contexts [k ]:
                    logger .info (f"  K={k }...")
                    try :
                        analysis_result =self .llm_analyzer .analyze_event_contexts (event_k_contexts [k ],k )
                        k_results [k ]=analysis_result 

                        if analysis_result ['success']:
                            tokens =analysis_result ['token_usage']['total_tokens']
                            attacker =analysis_result ['identified_addresses']['attacker']
                            victim =analysis_result ['identified_addresses']['victim']
                            logger .info (f"    ✅ K={k }: Tokens={tokens }, ={attacker [:10 ]}..., ={victim [:10 ]}...")
                            total_tokens_by_k [k ]+=tokens 
                        else :
                            logger .error (f"    ❌ K={k }: {analysis_result .get ('error','Unknown error')}")
                    except Exception as e :
                        logger .error (f"    ❌ K={k } : {str (e )}")
                        k_results [k ]={
                        'success':False ,
                        'error':str (e ),
                        'k_neighbors':k ,
                        'event_name':event_name 
                        }
                else :
                    logger .warning (f"  K={k }")
                    k_results [k ]={
                    'success':False ,
                    'error':'No context data',
                    'k_neighbors':k ,
                    'event_name':event_name 
                    }

            event_results [event_name ]=k_results 


        final_results ={
        'analysis_config':{
        'k_paths':self .k_paths ,
        'k_range':self .k_range ,
        'input_dir':input_dir ,
        'timestamp':datetime .now ().isoformat ()
        },
        'all_k_path_results':all_k_path_results ,
        'event_analysis_results':event_results ,
        'global_statistics':{
        'total_events':len (event_results ),
        'successful_events_by_k':{},
        'total_tokens_by_k':total_tokens_by_k ,
        'avg_tokens_by_k':{}
        }
        }


        for k in self .k_range :
            successful_count =sum (
            1 for event_results in event_results .values ()
            if k in event_results and event_results [k ].get ('success',False )
            )
            final_results ['global_statistics']['successful_events_by_k'][k ]=successful_count 

            if successful_count >0 :
                avg_tokens =total_tokens_by_k [k ]/successful_count 
                final_results ['global_statistics']['avg_tokens_by_k'][k ]=avg_tokens 
            else :
                final_results ['global_statistics']['avg_tokens_by_k'][k ]=0 


        saved_files =self ._save_comparison_results (final_results ,output_dir )


        self ._save_individual_event_reports (final_results ,output_dir )


        self ._print_comparison_summary (final_results )

        logger .info (f"\n📁 : {output_dir }")
        for file_type ,file_path in saved_files .items ():
            logger .info (f"  - {file_type }: {os .path .basename (file_path )}")

        return final_results 

    def _save_comparison_results (self ,results :Dict [str ,Any ],output_dir :str )->Dict [str ,str ]:

        os .makedirs (output_dir ,exist_ok =True )
        timestamp =datetime .now ().strftime ('%Y%m%d_%H%M%S')
        saved_files ={}


        full_file =os .path .join (output_dir ,f"k_value_comparison_full_{timestamp }.json")
        with open (full_file ,'w',encoding ='utf-8')as f :
            json .dump (results ,f ,indent =2 ,ensure_ascii =False ,default =str )
        saved_files ['full_results']=full_file 


        event_summary =[]
        for event_name ,k_results in results ['event_analysis_results'].items ():
            for k ,result in k_results .items ():
                if result .get ('success',False ):
                    event_summary .append ({
                    'event_name':event_name ,
                    'k_neighbors':k ,
                    'total_tokens':result ['token_usage']['total_tokens'],
                    'prompt_tokens':result ['token_usage']['prompt_tokens'],
                    'completion_tokens':result ['token_usage']['completion_tokens'],
                    'attacker_address':result ['identified_addresses']['attacker'],
                    'victim_address':result ['identified_addresses']['victim'],
                    'num_paths':result ['num_paths'],
                    'prompt_length':result ['prompt_length']
                    })

        if event_summary :
            summary_df =pd .DataFrame (event_summary )
            summary_file =os .path .join (output_dir ,f"k_value_event_summary_{timestamp }.csv")
            summary_df .to_csv (summary_file ,index =False )
            saved_files ['event_summary']=summary_file 


        k_stats =[]
        for k in results ['analysis_config']['k_range']:
            stats =results ['global_statistics']
            k_stats .append ({
            'k_neighbors':k ,
            'successful_events':stats ['successful_events_by_k'][k ],
            'total_tokens':stats ['total_tokens_by_k'][k ],
            'avg_tokens_per_event':stats ['avg_tokens_by_k'][k ],
            'total_events':stats ['total_events']
            })

        k_stats_df =pd .DataFrame (k_stats )
        k_stats_file =os .path .join (output_dir ,f"k_value_statistics_{timestamp }.csv")
        k_stats_df .to_csv (k_stats_file ,index =False )
        saved_files ['k_statistics']=k_stats_file 


        address_comparison =[]
        for event_name ,k_results in results ['event_analysis_results'].items ():
            event_data ={'event_name':event_name }

            for k in results ['analysis_config']['k_range']:
                if k in k_results and k_results [k ].get ('success',False ):
                    result =k_results [k ]
                    event_data [f'attacker_k{k }']=result ['identified_addresses']['attacker']
                    event_data [f'victim_k{k }']=result ['identified_addresses']['victim']
                    event_data [f'tokens_k{k }']=result ['token_usage']['total_tokens']
                else :
                    event_data [f'attacker_k{k }']='FAILED'
                    event_data [f'victim_k{k }']='FAILED'
                    event_data [f'tokens_k{k }']=0 

            address_comparison .append (event_data )

        if address_comparison :
            addr_df =pd .DataFrame (address_comparison )
            addr_file =os .path .join (output_dir ,f"address_identification_comparison_{timestamp }.csv")
            addr_df .to_csv (addr_file ,index =False )
            saved_files ['address_comparison']=addr_file 

        return saved_files 

    def _save_individual_event_reports (self ,results :Dict [str ,Any ],output_dir :str ):

        timestamp =datetime .now ().strftime ('%Y%m%d_%H%M%S')
        reports_dir =os .path .join (output_dir ,'individual_event_reports')
        os .makedirs (reports_dir ,exist_ok =True )

        for event_name ,k_results in results ['event_analysis_results'].items ():

            safe_event_name =''.join (c for c in event_name if c .isalnum ()or c in ('_','-')).strip ()
            safe_event_name =safe_event_name [:50 ]


            event_report ={
            'event_name':event_name ,
            'analysis_timestamp':timestamp ,
            'k_value_results':{}
            }


            for k ,result in k_results .items ():
                if result .get ('success',False ):
                    event_report ['k_value_results'][f'k_{k }']={
                    'k_neighbors':k ,
                    'token_usage':result ['token_usage'],
                    'identified_addresses':result ['identified_addresses'],
                    'llm_analysis':{
                    'raw_response':result ['llm_response']['raw_content'],
                    'parsed_data':result ['llm_response']['parsed_data']
                    },
                    'prompt_length':result ['prompt_length'],
                    'num_paths':result ['num_paths']
                    }
                else :
                    event_report ['k_value_results'][f'k_{k }']={
                    'k_neighbors':k ,
                    'error':result .get ('error','Unknown error'),
                    'success':False 
                    }


            json_file =os .path .join (reports_dir ,f"{safe_event_name }_{timestamp }.json")
            with open (json_file ,'w',encoding ='utf-8')as f :
                json .dump (event_report ,f ,indent =2 ,ensure_ascii =False ,default =str )


            txt_file =os .path .join (reports_dir ,f"{safe_event_name }_{timestamp }.txt")
            with open (txt_file ,'w',encoding ='utf-8')as f :
                f .write (f": {event_name }\n")
                f .write ('='*80 +'\n\n')
                f .write (f": {timestamp }\n")
                f .write (f"K: {list (k_results .keys ())}\n\n")

                for k in sorted (k_results .keys ()):
                    result =k_results [k ]
                    f .write (f"--- K={k }  ---\n")

                    if result .get ('success',False ):
                        tokens =result ['token_usage']
                        addresses =result ['identified_addresses']

                        f .write (f": ✅ \n")
                        f .write (f"Token: {tokens ['total_tokens']} (:{tokens ['prompt_tokens']}, :{tokens ['completion_tokens']})\n")
                        f .write (f": {addresses ['attacker']}\n")
                        f .write (f": {addresses ['victim']}\n")
                        f .write (f": {result ['num_paths']}\n")
                        f .write (f"Prompt: {result ['prompt_length']} \n\n")


                        llm_content =result ['llm_response']['raw_content']
                        f .write (f"LLM500:\n")
                        f .write ('-'*40 +'\n')
                        f .write (f"{llm_content [:500 ]}...\n")
                        f .write ('-'*40 +'\n\n')
                    else :
                        f .write (f": ❌ \n")
                        f .write (f": {result .get ('error','Unknown error')}\n\n")

        logger .info (f"✅  {len (results ['event_analysis_results'])} : {reports_dir }")

    def _print_comparison_summary (self ,results :Dict [str ,Any ]):

        logger .info ('\n'+'='*80 )
        logger .info ('K')
        logger .info ('='*80 )

        stats =results ['global_statistics']
        total_events =stats ['total_events']

        logger .info (f": {total_events }")
        logger .info (f"K: {results ['analysis_config']['k_range']}")

        logger .info (f"\n📊 K:")
        for k in results ['analysis_config']['k_range']:
            successful =stats ['successful_events_by_k'][k ]
            total_tokens =stats ['total_tokens_by_k'][k ]
            avg_tokens =stats ['avg_tokens_by_k'][k ]

            logger .info (f"  K={k }: ={successful }/{total_events }, "
            f"Tokens={total_tokens :,}, Tokens={avg_tokens :.1f}")

        logger .info (f"\n📋 :")
        logger .info (f"  : {max (stats ['successful_events_by_k'].values ())}/{total_events }")
        logger .info (f"  Token: {sum (stats ['total_tokens_by_k'].values ()):,}")


        logger .info (f"\n📊 K:")
        for event_name ,k_results in results ['event_analysis_results'].items ():
            successful_k_values =[k for k ,result in k_results .items ()if result .get ('success',False )]
            if successful_k_values :
                logger .info (f"  {event_name }: K {successful_k_values }")
            else :
                logger .info (f"  {event_name }: ❌ K")


if __name__ =='__main__':

    logging .basicConfig (
    level =logging .INFO ,
    format ='%(asctime)s - %(levelname)s - %(message)s'
    )

    input_dir ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled'
    output_dir ='/home/os/shuzheng/whole_pipeline/RQ3/k_comparison_results'

    try :

        analyzer =KValueComparisonAnalyzer (
        k_paths =30 ,
        k_range =[0 ,1 ,2 ,3 ,4 ,5 ]
        )


        results =analyzer .run_full_comparison (input_dir ,output_dir )

        print ('\n🎉 K!')

    except Exception as e :
        logger .error (f"❌ K: {e }")
        import traceback 
        traceback .print_exc ()