



import os 
import json 
import pandas as pd 
import numpy as np 
from typing import Dict ,List ,Tuple ,Any ,Optional 
from datetime import datetime 
import logging 

from logistic_regression_analyzer import LogisticRegressionAnalyzer 
from call_tree_builder import CallTreeBuilder ,format_path_context_for_display 

logger =logging .getLogger (__name__ )


class ContextualPathAnalyzer :


    def __init__ (self ,
    k_paths :int =30 ,
    k_neighbors :int =3 ,
    suspicious_methods :Optional [List [str ]]=None ,
    random_state :int =42 ):

        self .k_paths =k_paths 
        self .k_neighbors =k_neighbors 
        self .random_state =random_state 


        self .lr_analyzer =LogisticRegressionAnalyzer (
        k =k_paths ,
        suspicious_methods =suspicious_methods ,
        random_state =random_state 
        )

        self .tree_builder =CallTreeBuilder ()

        logger .info (f"")
        logger .info (f"  - Top-K: {k_paths }")
        logger .info (f"  - K: {k_neighbors }")

    def analyze_with_context (self ,input_dir :str )->Dict [str ,Any ]:

        logger .info ('='*60 )
        logger .info ('')
        logger .info ('='*60 )


        logger .info ('1: Logistic Regression...')
        lr_results =self .lr_analyzer .analyze_all_files (input_dir )

        if not lr_results ['per_file_results']:
            raise ValueError ('Logistic Regression')


        suspicious_paths ={}
        all_df_data ={}

        for file_name ,result in lr_results ['per_file_results'].items ():
            if 'top_k_path_ids'in result :
                suspicious_paths [file_name ]=result ['top_k_path_ids']

                all_df_data [file_name ]=result ['test_df_with_scores']

        total_suspicious =sum (len (paths )for paths in suspicious_paths .values ())
        logger .info (f"✅  {total_suspicious }  {len (suspicious_paths )} ")


        logger .info ('2: ...')
        all_dfs =[]
        for file_name ,df in all_df_data .items ():
            df =df .copy ()
            df ['source_file']=file_name 
            all_dfs .append (df )

        if not all_dfs :
            raise ValueError ('DataFrame')

        combined_df =pd .concat (all_dfs ,ignore_index =True )
        tx_trees =self .tree_builder .build_transaction_trees (combined_df )


        logger .info (f"3: K={self .k_neighbors }...")
        path_contexts =self .tree_builder .extract_path_contexts (
        suspicious_paths ,self .k_neighbors 
        )


        logger .info ('4: ...')
        final_results ={
        'analysis_config':{
        'k_paths':self .k_paths ,
        'k_neighbors':self .k_neighbors ,
        'input_dir':input_dir ,
        'timestamp':datetime .now ().isoformat ()
        },
        'lr_analysis':lr_results ,
        'suspicious_paths':suspicious_paths ,
        'path_contexts':path_contexts ,
        'tree_statistics':self .tree_builder .get_global_statistics (),
        'summary':self ._generate_summary (lr_results ,path_contexts )
        }

        logger .info ('✅ ')
        return final_results 

    def _generate_summary (self ,lr_results :Dict ,path_contexts :Dict )->Dict [str ,Any ]:

        total_files =lr_results .get ('total_files',0 )
        successful_files =lr_results .get ('successful_files',0 )

        total_suspicious_paths =sum (
        len (contexts )for contexts in path_contexts .values ()
        )


        context_stats ={
        'total_contexts':total_suspicious_paths ,
        'avg_context_nodes':0 ,
        'avg_neighbors':0 ,
        'max_context_size':0 
        }

        if total_suspicious_paths >0 :
            context_node_counts =[]
            neighbor_counts =[]

            for file_contexts in path_contexts .values ():
                for context in file_contexts .values ():
                    context_size =len (context .get ('context_nodes',[]))
                    path_size =len (context .get ('path_nodes',[]))
                    neighbors =context_size -path_size 

                    context_node_counts .append (context_size )
                    neighbor_counts .append (neighbors )

            if context_node_counts :
                context_stats .update ({
                'avg_context_nodes':np .mean (context_node_counts ),
                'avg_neighbors':np .mean (neighbor_counts ),
                'max_context_size':np .max (context_node_counts )
                })


        lr_metrics =lr_results .get ('global_metrics',{})

        return {
        'files_processed':f"{successful_files }/{total_files }",
        'total_suspicious_paths':total_suspicious_paths ,
        'lr_performance':{
        'macro_attack_hit_rate':lr_metrics .get ('macro_attack_hit_rate',0 ),
        'macro_f1':lr_metrics .get ('macro_f1',0 ),
        'micro_f1':lr_metrics .get ('micro_f1',0 )
        },
        'context_statistics':context_stats 
        }

    def save_results (self ,results :Dict [str ,Any ],output_dir :str )->Dict [str ,str ]:

        os .makedirs (output_dir ,exist_ok =True )
        timestamp =datetime .now ().strftime ('%Y%m%d_%H%M%S')
        saved_files ={}


        full_results_file =os .path .join (output_dir ,f"contextual_analysis_full_{timestamp }.json")
        with open (full_results_file ,'w',encoding ='utf-8')as f :
            json .dump (results ,f ,indent =2 ,ensure_ascii =False ,default =str )
        saved_files ['full_results']=full_results_file 


        summary_data =[]
        for file_name ,contexts in results ['path_contexts'].items ():
            for path_id ,context in contexts .items ():
                node_details =context .get ('node_details',{})
                leaf_node_id =context ['path_nodes'][-1 ]if context ['path_nodes']else None 
                leaf_info =node_details .get (leaf_node_id ,{}).get ('path_info',{})if leaf_node_id else {}

                summary_data .append ({
                'source_file':file_name ,
                'path_id':path_id ,
                'tx_hash':context .get ('tx_hash','unknown'),
                'path_length':len (context ['path_nodes']),
                'context_size':len (context ['context_nodes']),
                'neighbor_count':len (context ['context_nodes'])-len (context ['path_nodes']),
                'label':leaf_info .get ('label',0 ),
                'event_name':leaf_info .get ('event_name','unknown'),
                'attacker_address':leaf_info .get ('attacker_address','unknown')
                })

        if summary_data :
            summary_df =pd .DataFrame (summary_data )
            summary_file =os .path .join (output_dir ,f"suspicious_paths_summary_{timestamp }.csv")
            summary_df .to_csv (summary_file ,index =False )
            saved_files ['summary']=summary_file 


        contexts_file =os .path .join (output_dir ,f"path_contexts_{timestamp }.json")
        with open (contexts_file ,'w',encoding ='utf-8')as f :
            json .dump (results ['path_contexts'],f ,indent =2 ,ensure_ascii =False ,default =str )
        saved_files ['contexts']=contexts_file 


        report_file =os .path .join (output_dir ,f"context_report_{timestamp }.txt")
        with open (report_file ,'w',encoding ='utf-8')as f :
            f .write ('\n')
            f .write ('='*50 +'\n\n')


            summary =results ['summary']
            f .write (f":\n")
            f .write (f"  - Top-K: {results ['analysis_config']['k_paths']}\n")
            f .write (f"  - K: {results ['analysis_config']['k_neighbors']}\n")
            f .write (f"  - : {results ['analysis_config']['input_dir']}\n\n")

            f .write (f":\n")
            f .write (f"  - : {summary ['files_processed']}\n")
            f .write (f"  - : {summary ['total_suspicious_paths']}\n")
            f .write (f"  - LR: {summary ['lr_performance']['macro_attack_hit_rate']:.3f}\n")
            f .write (f"  - LRF1: {summary ['lr_performance']['macro_f1']:.3f}\n\n")


            f .write (':\n')
            f .write ('-'*30 +'\n\n')

            for file_name ,contexts in results ['path_contexts'].items ():
                f .write (f": {file_name }\n")
                f .write (f": {len (contexts )}\n\n")

                for i ,(path_id ,context )in enumerate (contexts .items (),1 ):
                    f .write (f"  {i }. {format_path_context_for_display (context ,show_neighbors =False )}\n\n")

                f .write ('-'*30 +'\n\n')

        saved_files ['report']=report_file 

        logger .info (f" {output_dir }")
        for file_type ,file_path in saved_files .items ():
            logger .info (f"  - {file_type }: {os .path .basename (file_path )}")

        return saved_files 

    def get_contexts_for_llm (self ,results :Dict [str ,Any ])->Dict [str ,List [Dict ]]:

        llm_contexts ={}

        for file_name ,contexts in results ['path_contexts'].items ():
            file_contexts =[]

            for path_id ,context in contexts .items ():

                node_details =context .get ('node_details',{})
                path_nodes =context .get ('path_nodes',[])
                context_nodes =context .get ('context_nodes',[])


                path_sequence =[]
                for node_id in path_nodes :
                    if node_id in node_details :
                        method =node_details [node_id ]['method']
                        path_sequence .append ({
                        'node_id':node_id ,
                        'method':method ,
                        'depth':node_details [node_id ]['depth'],
                        'is_suspicious':node_details [node_id ]['is_suspicious']
                        })


                neighbor_nodes =[nid for nid in context_nodes if nid not in path_nodes ]
                neighbors_info =[]
                for node_id in neighbor_nodes :
                    if node_id in node_details :
                        detail =node_details [node_id ]
                        neighbors_info .append ({
                        'node_id':node_id ,
                        'method':detail ['method'],
                        'depth':detail ['depth'],
                        'fanout':detail ['fanout'],
                        'is_suspicious':detail ['is_suspicious'],
                        'related_paths':detail ['related_paths']
                        })


                leaf_node_id =path_nodes [-1 ]if path_nodes else None 
                leaf_info =node_details .get (leaf_node_id ,{}).get ('path_info',{})if leaf_node_id else {}

                formatted_context ={
                'path_id':path_id ,
                'tx_hash':context .get ('tx_hash','unknown'),
                'source_file':file_name ,
                'path_sequence':path_sequence ,
                'neighbors':neighbors_info ,
                'path_metadata':{
                'label':leaf_info .get ('label',0 ),
                'event_name':leaf_info .get ('event_name','unknown'),
                'attacker_address':leaf_info .get ('attacker_address','unknown'),
                'path_length':leaf_info .get ('path_length',0 ),
                'contains_transfer':leaf_info .get ('contains_transfer',False ),
                'contains_swap':leaf_info .get ('contains_swap',False ),
                'total_value':leaf_info .get ('total_value',0 )
                },
                'context_statistics':{
                'total_nodes':len (context_nodes ),
                'path_nodes':len (path_nodes ),
                'neighbor_nodes':len (neighbor_nodes ),
                'edges':len (context .get ('context_edges',[]))
                }
                }

                file_contexts .append (formatted_context )

            if file_contexts :
                llm_contexts [file_name ]=file_contexts 

        return llm_contexts 


if __name__ =='__main__':

    logging .basicConfig (
    level =logging .INFO ,
    format ='%(asctime)s - %(levelname)s - %(message)s'
    )

    input_dir ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled'
    output_dir ='/home/os/shuzheng/whole_pipeline/RQ3/results'

    try :

        analyzer =ContextualPathAnalyzer (
        k_paths =30 ,
        k_neighbors =3 
        )


        results =analyzer .analyze_with_context (input_dir )


        saved_files =analyzer .save_results (results ,output_dir )


        summary =results ['summary']
        print ('\n'+'='*60 )
        print ('')
        print ('='*60 )
        print (f": {summary ['files_processed']}")
        print (f": {summary ['total_suspicious_paths']}")
        print (f"LR: {summary ['lr_performance']['macro_attack_hit_rate']:.3f}")
        print (f": {summary ['context_statistics']['avg_context_nodes']:.1f}")
        print (f": {summary ['context_statistics']['avg_neighbors']:.1f}")
        print (f": {output_dir }")

    except Exception as e :
        logger .error (f": {e }")
        import traceback 
        traceback .print_exc ()