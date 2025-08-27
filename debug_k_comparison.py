



import os 
import sys 
import logging 
from datetime import datetime 
from k_value_comparison import KValueComparisonAnalyzer 
from llm_analyzer import LLMAnalyzer 


logging .basicConfig (
level =logging .INFO ,
format ='%(asctime)s - %(levelname)s - %(message)s'
)
logger =logging .getLogger (__name__ )


def debug_k_value_differences ():


    input_dir ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled'

    try :
        logger .info ('🔍 K...')


        analyzer =KValueComparisonAnalyzer (k_paths =5 ,k_range =[0 ,1 ,2 ,3 ])


        from contextual_path_analyzer import ContextualPathAnalyzer 
        path_analyzer =ContextualPathAnalyzer (k_paths =5 ,k_neighbors =3 )
        results =path_analyzer .analyze_with_context (input_dir )

        if not results ['path_contexts']:
            logger .error ('❌ ')
            return 


        first_event =list (results ['path_contexts'].keys ())[0 ]
        event_contexts =results ['path_contexts'][first_event ]

        logger .info (f"✅ : {first_event }")
        logger .info (f"   : {len (event_contexts )}")


        llm_analyzer =LLMAnalyzer ()
        k_values =[0 ,1 ,2 ,3 ]

        for k in k_values :
            logger .info (f"\n--- K={k } ---")


            k_contexts =analyzer ._prepare_contexts_for_k (event_contexts ,k )


            total_neighbors =0 
            total_context_nodes =0 

            for path_id ,context in k_contexts .items ():
                neighbors_count =len (context .get ('neighbors',[]))
                context_nodes_count =len (context .get ('context_nodes',[]))
                total_neighbors +=neighbors_count 
                total_context_nodes +=context_nodes_count 

                logger .debug (f"   {path_id }: ={neighbors_count }, ={context_nodes_count }")

            logger .info (f"  : {total_neighbors }")
            logger .info (f"  : {total_context_nodes }")


            first_context =list (k_contexts .values ())[0 ]
            event_name =first_context .get ('path_metadata',{}).get ('event_name','Test Event')

            prompt =llm_analyzer .build_attacker_victim_prompt (
            list (k_contexts .values ()),event_name ,k 
            )

            logger .info (f"  Prompt: {len (prompt ):,} ")
            logger .info (f"  Token: {len (prompt )//4 :,}")


            logger .debug (f"  Prompt: {prompt [:200 ]}...")
            logger .debug (f"  Prompt: ...{prompt [-200 :]}")

        logger .info ('\n✅ K')

    except Exception as e :
        logger .error (f"❌ : {str (e )}")
        import traceback 
        traceback .print_exc ()


def detailed_context_analysis ():


    input_dir ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled'

    try :

        from contextual_path_analyzer import ContextualPathAnalyzer 
        path_analyzer =ContextualPathAnalyzer (k_paths =3 ,k_neighbors =3 )
        results =path_analyzer .analyze_with_context (input_dir )

        first_event =list (results ['path_contexts'].keys ())[0 ]
        event_contexts =results ['path_contexts'][first_event ]


        first_path_id =list (event_contexts .keys ())[0 ]
        first_context =event_contexts [first_path_id ]

        logger .info ('📊 :')
        logger .info (f": {first_event }")
        logger .info (f"ID: {first_path_id }")


        path_nodes =first_context .get ('path_nodes',[])
        logger .info (f": {len (path_nodes )}")


        neighbors =first_context .get ('neighbors',[])
        logger .info (f": {len (neighbors )}")


        node_details =first_context .get ('node_details',{})
        logger .info (f": {len (node_details )}")


        logger .info ('5:')
        for i ,neighbor in enumerate (neighbors [:5 ]):
            method =neighbor .get ('method','unknown')
            depth =neighbor .get ('depth',0 )
            fanout =neighbor .get ('fanout',0 )
            logger .info (f"  {i +1 }. {method } (:{depth }, :{fanout })")


        analyzer =KValueComparisonAnalyzer (k_paths =3 ,k_range =[0 ,1 ,2 ,3 ])

        logger .info ('\n🔍 K:')
        for k in [0 ,1 ,2 ,3 ]:
            k_contexts =analyzer ._prepare_contexts_for_k ({first_path_id :first_context },k )
            k_context =k_contexts [first_path_id ]
            k_neighbors =k_context .get ('neighbors',[])

            logger .info (f"K={k }: ={len (k_neighbors )}")


            if k_neighbors :
                depths =[n .get ('depth',0 )for n in k_neighbors ]
                logger .info (f"  : {min (depths )} - {max (depths )}")

    except Exception as e :
        logger .error (f"❌ : {str (e )}")
        import traceback 
        traceback .print_exc ()


if __name__ =='__main__':
    print (':')
    print ('1. K')
    print ('2. ')

    choice =input (' (1-2): ').strip ()

    if choice =='1':
        debug_k_value_differences ()
    elif choice =='2':
        detailed_context_analysis ()
    else :
        logger .info ('...')
        debug_k_value_differences ()