
import os 
import sys 
import json 
import pandas as pd 
import hashlib 
import requests 
import time 
import traceback 
from typing import List ,Dict ,Any ,Optional 
from pathlib import Path 
from datetime import datetime 
import logging 
from web3 import Web3 
from tqdm import tqdm 
import openpyxl 


logging .basicConfig (
level =logging .INFO ,
format ='%(asctime)s - %(levelname)s - %(message)s',
handlers =[
logging .FileHandler ('path_extraction_web3_scan.log'),
logging .StreamHandler ()
]
)

logger =logging .getLogger (__name__ )

class Web3BlockchainScanner :


    def __init__ (self ):
        try :
            sys .path .append (os .path .join (os .path .dirname (__file__ ),'src'))
            from config .settings import settings 
            self .settings =settings 
        except ImportError :
            logger .error ('❌ ')
            raise 

        self .network ='ethereum'
        self .network_config =self .settings .NETWORKS [self .network ]

        self .rpc_url =self .network_config .get ('rpc_url','https://ethereum.publicnode.com')

        try :
            self .w3 =Web3 (Web3 .HTTPProvider (self .rpc_url ))
            if self .w3 .is_connected ():
                logger .info (f"✅ : {self .rpc_url }")
                latest_block =self .w3 .eth .block_number 
                logger .info (f"📊 : {latest_block }")
            else :
                raise Exception ('Web3')
        except Exception as e :
            logger .error (f"❌ Web3: {str (e )}")
            try :
                self .rpc_url ='https://ethereum.publicnode.com'
                self .w3 =Web3 (Web3 .HTTPProvider (self .rpc_url ))
                if self .w3 .is_connected ():
                    logger .info (f"✅ : {self .rpc_url }")
                else :
                    raise Exception ('')
            except Exception as e2 :
                logger .error (f"❌ : {str (e2 )}")
                self .w3 =None 

        self .trace_url =self .network_config .get ('trace_url',self .rpc_url )
        self .trace_api_key =self .network_config .get ('trace_api_key')or os .getenv ('ANKR_API_KEY')
        self .use_local_node =self .network_config .get ('use_local_node',False )


        self .has_external_api =bool (self .trace_api_key )or self .trace_url !=self .rpc_url 

        logger .info (f"🔧 :")
        logger .info (f"  - RPC URL: {self .rpc_url }")
        logger .info (f"  - Trace URL: {self .trace_url }")
        logger .info (f"  - API: {self .has_external_api }")
        logger .info (f"  - : {self .use_local_node }")

        if not self .trace_api_key and not self .has_external_api :
            logger .warning ('⚠️ trace APItrace')

    def scan_blocks_for_transactions (self ,target_address :str ,start_block :int ,end_block :int )->List [Dict ]:

        if not self .w3 :
            logger .error ('❌ Web3')
            return []

        logger .info (f"🔍  {target_address }  {start_block }-{end_block } ")

        target_address_lower =target_address .lower ()
        relevant_transactions =[]

        try :
            for block_num in tqdm (range (start_block ,end_block +1 ),desc =''):
                try :
                    block =self .w3 .eth .get_block (block_num ,full_transactions =True )

                    for tx in block .transactions :
                        try :

                            tx_from =tx .get ('from','').lower ()if tx .get ('from')else ''
                            tx_to =tx .get ('to','').lower ()if tx .get ('to')else ''

                            is_target_sender =tx_from ==target_address_lower 
                            is_target_recipient =tx_to ==target_address_lower 
                            is_contract_creation =tx .to is None and is_target_sender 

                            if is_target_sender or is_target_recipient or is_contract_creation :
                                tx_hash =tx .hash .hex ()if isinstance (tx .hash ,bytes )else str (tx .hash )

                                input_data =tx .input .hex ()if isinstance (tx .input ,bytes )else str (tx .input )
                                method_name ='unknown'
                                if input_data and len (input_data )>=10 :
                                    method_id =input_data [:10 ]
                                    method_name =lookup_method_from_4byte (method_id )
                                elif not input_data or input_data =='0x':
                                    method_name ='eth_transfer'

                                tx_data ={
                                'tx_hash':tx_hash ,
                                'block_number':block_num ,
                                'from_address':tx_from ,
                                'to_address':tx_to ,
                                'method_name':method_name ,
                                'input_data':input_data ,
                                'value':str (tx .value ),
                                'gas':str (tx .gas ),
                                'gas_price':str (tx .gasPrice ),
                                'timestamp':datetime .fromtimestamp (block .timestamp ),
                                'is_contract_creation':is_contract_creation ,
                                'transaction_index':tx .transactionIndex 
                                }


                                if is_contract_creation :
                                    try :
                                        receipt =self .w3 .eth .get_transaction_receipt (tx .hash )
                                        if receipt and receipt .get ('contractAddress'):
                                            created_address =receipt ['contractAddress'].lower ()
                                            tx_data ['created_contract_address']=created_address 
                                            logger .info (f": {created_address }")
                                    except Exception as e :
                                        logger .warning (f": {str (e )}")

                                relevant_transactions .append (tx_data )
                                logger .info (f": {tx_hash } (: {block_num })")

                        except Exception as e :
                            logger .warning (f": {str (e )}")
                            continue 

                except Exception as e :
                    logger .warning (f" {block_num } : {str (e )}")
                    continue 

        except Exception as e :
            logger .error (f": {str (e )}")

        logger .info (f"✅  {len (relevant_transactions )} ")
        return relevant_transactions 



    def get_transaction_trace (self ,tx_hash :str )->Optional [List [Dict ]]:


        if isinstance (tx_hash ,bytes ):
            tx_hash =tx_hash .hex ()

        if not tx_hash .startswith ('0x'):
            tx_hash ='0x'+tx_hash 

        try :
            logger .info (f"🔍  {tx_hash } trace")


            use_local_node =self .use_local_node 
            trace_url =self .trace_url 

            if self .has_external_api :
                logger .info (f"API {tx_hash } ...")
                use_local_node =False 
                trace_url =self .trace_url 
            elif use_local_node :
                logger .info (f" {tx_hash } ...")
            else :
                logger .info (f" {tx_hash } ...")


            payload ={
            'jsonrpc':'2.0',
            'method':'trace_transaction',
            'params':[tx_hash ],
            'id':1 
            }


            headers ={
            'Content-Type':'application/json'
            }


            if not use_local_node and self .trace_api_key :
                headers ['Authorization']=f"Bearer {self .trace_api_key }"


            max_retries =3 
            retry_delay =2 

            for attempt in range (max_retries ):
                try :

                    response =requests .post (
                    trace_url ,
                    headers =headers ,
                    json =payload ,
                    timeout =30 
                    )

                    if response .status_code ==200 :
                        result =response .json ()
                        if 'result'in result and result ['result']is not None :
                            logger .info (f"✅  {tx_hash } ")
                            trace_data =result ['result']
                            logger .info (f"trace: {str (trace_data )[:200 ]}...")
                            return trace_data 
                        elif 'error'in result :
                            error_msg =result ['error'].get ('message','')
                            logger .warning (f": {error_msg }")


                            if use_local_node and ('method not found'in error_msg .lower ()or 'not supported'in error_msg .lower ()):
                                logger .info ('trace_transaction...')
                                return self ._get_transaction_trace_alternative (tx_hash )


                            if 'invalid argument'in error_msg .lower ():

                                if attempt ==0 :
                                    logger .info ('...')
                                    if payload ['params'][0 ].startswith ('0x'):
                                        payload ['params'][0 ]=payload ['params'][0 ][2 :]
                                    else :
                                        payload ['params'][0 ]='0x'+payload ['params'][0 ]
                                    continue 


                            return self ._get_transaction_trace_alternative (tx_hash )
                        else :
                            logger .warning ('API')
                            return self ._get_transaction_trace_alternative (tx_hash )
                    else :
                        logger .warning (f": {response .status_code }")
                        logger .warning (f": {response .text [:500 ]}...")
                        if attempt <max_retries -1 :
                            logger .info (f" {retry_delay } ...")
                            time .sleep (retry_delay )
                        else :

                            return self ._get_transaction_trace_alternative (tx_hash )

                except requests .exceptions .Timeout :
                    logger .warning (f" ( {attempt +1 }/{max_retries })")
                    if attempt <max_retries -1 :
                        logger .info (f" {retry_delay } ...")
                        time .sleep (retry_delay )
                    else :

                        return self ._get_transaction_trace_alternative (tx_hash )

                except Exception as e :
                    logger .warning (f": {str (e )}")
                    if attempt <max_retries -1 :
                        logger .info (f" {retry_delay } ...")
                        time .sleep (retry_delay )
                    else :

                        return self ._get_transaction_trace_alternative (tx_hash )


            return None 

        except Exception as e :
            logger .error (f": {str (e )}")
            traceback .print_exc ()
            return None 

    def _get_transaction_trace_alternative (self ,tx_hash :str )->Optional [Dict ]:

        logger .info (f" {tx_hash } ...")

        try :

            if not tx_hash .startswith ('0x'):
                tx_hash ='0x'+tx_hash 


            receipt =self .w3 .eth .get_transaction_receipt (tx_hash )
            if not receipt :
                logger .warning ('')
                return None 


            tx_data =None 
            try :
                tx_data =self .w3 .eth .get_transaction (tx_hash )
            except Exception as tx_error :
                logger .warning (f"eth_getTransaction: {str (tx_error )}")
                logger .info ('trace')


            trace ={
            'action':{
            'from':receipt ['from'],
            'to':receipt .get ('to','0x0000000000000000000000000000000000000000'),
            'value':str (tx_data .get ('value',0 ))if tx_data else '0',
            'gas':str (tx_data .get ('gas',receipt .get ('gasUsed',0 )))if tx_data else str (receipt .get ('gasUsed',0 )),
            'input':tx_data .get ('input','0x')if tx_data else '0x'
            },
            'result':{
            'gasUsed':str (receipt .get ('gasUsed',0 )),
            'status':'0x1'if receipt .get ('status')==1 else '0x0'
            },
            'subtraces':len (receipt .get ('logs',[])),
            'type':'call'
            }


            if not receipt .get ('to'):
                trace ['type']='create'
                trace ['result']['address']=receipt .get ('contractAddress')


            if receipt .get ('logs'):
                calls =[]
                for log in receipt .get ('logs',[]):
                    calls .append ({
                    'action':{
                    'from':receipt ['from'],
                    'to':log ['address'],
                    'input':'0x'+log ['topics'][0 ][2 :]if log ['topics']else '0x',
                    'gas':'0'
                    },
                    'result':{
                    'gasUsed':'0'
                    },
                    'type':'call'
                    })
                trace ['calls']=calls 

            logger .info (f"✅ trace")
            return trace 

        except Exception as e :
            logger .error (f": {str (e )}")
            traceback .print_exc ()
            return None 

def process_trace_to_call_hierarchy (trace_data ,scanner :Web3BlockchainScanner ,tx_info :Dict )->Dict :

    try :
        logger .info (f"🔄  {tx_info ['tx_hash']} trace")


        method_name =tx_info .get ('method_name','unknown')
        method_id =tx_info .get ('input_data','0x')[:10 ]if tx_info .get ('input_data')else '0x'


        if method_name in ['unknown','_SIMONdotBLACK_','workMyDirefulOwner']or method_name .startswith ('0x'):
            try :
                corrected_method =lookup_method_from_4byte (method_id )
                if corrected_method and corrected_method !=method_name :
                    logger .info (f"🔧 : {method_name } -> {corrected_method }")
                    method_name =corrected_method 
            except Exception as e :
                logger .warning (f": {str (e )}")

        root_node ={
        'from':tx_info ['from_address'],
        'to':tx_info ['to_address'],
        'method':method_name ,
        'method_id':method_id ,
        'input':tx_info .get ('input_data','0x'),
        'value':tx_info .get ('value','0'),
        'call_type':'root',
        'children':[]
        }


        related_contracts =set ()


        call_path =[tx_info ['to_address']]
        process_trace_without_db_checks (
        trace_data ,
        root_node ,
        related_contracts ,
        call_path ,
        0 ,
        max_depth =5 
        )


        flat_calls =extract_flat_calls_from_hierarchy_local (root_node )
        logger .info (f"✅  {len (flat_calls )} ")


        if flat_calls :
            rebuilt_hierarchy =rebuild_call_hierarchy_with_depth_local (flat_calls )
            if rebuilt_hierarchy :
                logger .info (f"✅ ")
                return rebuilt_hierarchy 
            else :
                logger .warning (f"⚠️ ")
                return root_node 
        else :
            logger .warning (f"⚠️ ")
            return root_node 

    except Exception as e :
        logger .error (f"❌ trace: {str (e )}")
        traceback .print_exc ()
        return None 

def extract_flat_calls_from_hierarchy_local (call_hierarchy ):

    if not call_hierarchy :
        return []

    flat_calls =[]

    def traverse_hierarchy (node ):

        if not node or not isinstance (node ,dict ):
            return 


        call_item ={
        'from':node .get ('from'),
        'to':node .get ('to'),
        'method':node .get ('method',node .get ('method_id','')),
        'value':node .get ('value','0')
        }


        if call_item ['from']and call_item ['to']:
            flat_calls .append (call_item )


        children =node .get ('children',[])
        if isinstance (children ,list ):
            for child in children :
                traverse_hierarchy (child )


    traverse_hierarchy (call_hierarchy )

    return flat_calls 

def rebuild_call_hierarchy_with_depth_local (flat_calls ):

    if not flat_calls or not isinstance (flat_calls ,list ):
        return None 

    if len (flat_calls )==0 :
        return None 

    def create_node (call ,index ,depth =0 ):

        node ={
        'from':call .get ('from'),
        'to':call .get ('to'),
        'method':call .get ('method'),
        'value':call .get ('value','0'),
        'children':[],
        'depth':depth ,
        'call_index':index ,
        'call_type':'function_call'
        }


        method =node .get ('method','')
        if 'mint'in method .lower ():
            node ['call_type']='mint_operation'
        elif 'swap'in method .lower ():
            node ['call_type']='swap_operation'
        elif 'transfer'in method .lower ():
            node ['call_type']='transfer_operation'
        elif 'approve'in method .lower ():
            node ['call_type']='approval_operation'
        elif 'callback'in method .lower ():
            node ['call_type']='callback'
        elif method .startswith ('0x'):
            node ['call_type']='function_call'
        else :
            node ['call_type']='function_call'

        return node 


    trees =[]
    current_parent =None 

    i =0 
    while i <len (flat_calls ):
        call =flat_calls [i ]


        if i ==0 :
            root_node =create_node (call ,i ,depth =0 )
            trees .append (root_node )
            current_parent =root_node 
            i +=1 
            continue 

        prev_call =flat_calls [i -1 ]


        if call .get ('from','').lower ()==prev_call .get ('to','').lower ():

            child_depth =current_parent ['depth']+1 


            sibling_calls =[]
            j =i 
            while j <len (flat_calls ):
                current_call =flat_calls [j ]
                if current_call .get ('from','').lower ()==call .get ('from','').lower ():
                    sibling_calls .append ((current_call ,j ))
                    j +=1 
                else :
                    break 


            for sibling_call ,call_index in sibling_calls :
                sibling_node =create_node (sibling_call ,call_index ,child_depth )
                current_parent ['children'].append (sibling_node )


            if sibling_calls :
                current_parent =current_parent ['children'][-1 ]


            i =j 
            continue 

        else :

            root_node =create_node (call ,i ,depth =0 )
            trees .append (root_node )
            current_parent =root_node 
            i +=1 


    if len (trees )==1 :
        return trees [0 ]
    elif len (trees )>1 :

        virtual_root ={
        'from':'virtual_root',
        'to':'virtual_root',
        'method':'virtual_root',
        'value':'0',
        'children':trees ,
        'depth':-1 ,
        'call_index':-1 ,
        'call_type':'virtual_root'
        }


        def adjust_depth (node ,depth_offset ):
            node ['depth']+=depth_offset 
            for child in node .get ('children',[]):
                adjust_depth (child ,depth_offset )

        for tree in trees :
            adjust_depth (tree ,1 )

        return virtual_root 
    else :
        return None 

def process_trace_without_db_checks (trace ,parent_node ,related_contracts ,call_path ,current_depth ,max_depth =5 ):

    if current_depth >=max_depth :
        return 

    try :

        if isinstance (trace ,dict ):

            if 'action'in trace :
                process_trace_action_without_db (trace ,parent_node ,related_contracts ,call_path ,current_depth ,max_depth )

            elif 'from'in trace and 'to'in trace :
                process_trace_old_format_without_db (trace ,parent_node ,related_contracts ,call_path ,current_depth ,max_depth )


        elif isinstance (trace ,list ):
            for subtrace in trace :
                process_trace_without_db_checks (subtrace ,parent_node ,related_contracts ,call_path ,current_depth ,max_depth )

    except Exception as e :
        logger .warning (f"trace{str (e )}")

def process_trace_action_without_db (call ,parent_node ,related_contracts ,call_path ,current_depth ,max_depth ):

    try :
        action =call ['action']
        from_address =action .get ('from','').lower ()if action .get ('from')else ''
        to_address =action .get ('to','').lower ()if action .get ('to')else ''
        input_data =action .get ('input','0x')
        call_type =action .get ('callType','call')
        value =action .get ('value','0x0')


        has_from =bool (from_address and Web3 .is_address (from_address ))
        has_to =bool (to_address and Web3 .is_address (to_address ))

        logger .debug (f"trace: from={from_address }({has_from }), to={to_address }({has_to }), type={call_type }")

        if has_from or has_to :

            if has_from :
                related_contracts .add (from_address )
            if has_to :
                related_contracts .add (to_address )


            method_id ='0x'
            method_name ='unknown'
            if input_data and len (input_data )>=10 :
                method_id =input_data [:10 ]


                try :

                    parsed_method =lookup_method_from_4byte (method_id )
                    if parsed_method :
                        method_name =parsed_method 
                    else :
                        method_name ='method_id'
                except Exception :
                    method_name ='method_id'
            else :

                if not input_data or input_data =='0x':
                    method_name ='eth_transfer'
                else :
                    method_name ='contract_creation'


            call_node ={
            'from':from_address if has_from else 'unknown',
            'to':to_address if has_to else 'unknown',
            'method':method_name ,
            'method_id':method_id ,
            'call_type':call_type ,
            'value':value ,
            'input':input_data ,
            'depth':current_depth +1 ,
            'children':[]
            }


            parent_node ['children'].append (call_node )


            new_call_path =call_path 
            if has_to :
                new_call_path =call_path +[to_address ]


            if 'subtraces'in call and call ['subtraces']>0 :
                if 'calls'in call and isinstance (call ['calls'],list ):
                    for subcall in call ['calls']:
                        process_trace_without_db_checks (
                        subcall ,
                        call_node ,
                        related_contracts ,
                        new_call_path ,
                        current_depth +1 ,
                        max_depth 
                        )
    except Exception as e :
        logger .warning (f"trace action: {str (e )}")

def process_trace_old_format_without_db (trace ,parent_node ,related_contracts ,call_path ,current_depth ,max_depth ):

    try :
        from_address =trace .get ('from','').lower ()if trace .get ('from')else ''
        to_address =trace .get ('to','').lower ()if trace .get ('to')else ''


        has_from =bool (from_address and Web3 .is_address (from_address ))
        has_to =bool (to_address and Web3 .is_address (to_address ))

        if has_from or has_to :

            if has_from :
                related_contracts .add (from_address )
            if has_to :
                related_contracts .add (to_address )


            method_id =trace .get ('method_id','0x')
            method_name ='unknown'
            if method_id and method_id !='0x':
                try :
                    parsed_method =lookup_method_from_4byte (method_id )
                    if parsed_method :
                        method_name =parsed_method 
                    else :
                        method_name ='method_id'
                except Exception :
                    method_name ='method_id'
            else :
                method_name ='eth_transfer'


            call_node ={
            'from':from_address if has_from else 'unknown',
            'to':to_address if has_to else 'unknown',
            'method':method_name ,
            'method_id':method_id ,
            'call_type':trace .get ('type','call'),
            'value':trace .get ('value','0x0'),
            'depth':current_depth +1 ,
            'children':[]
            }


            parent_node ['children'].append (call_node )


            new_call_path =call_path 
            if has_to :
                new_call_path =call_path +[to_address ]


            if 'children'in trace and isinstance (trace ['children'],list ):
                for child in trace ['children']:
                    process_trace_without_db_checks (
                    child ,
                    call_node ,
                    related_contracts ,
                    new_call_path ,
                    current_depth +1 ,
                    max_depth 
                    )
    except Exception as e :
        logger .warning (f"trace: {str (e )}")

def lookup_method_from_4byte (selector ):

    try :
        if not selector or selector =='0x'or len (selector )!=10 :
            return 'contract_creation_or_eth_transfer'

        hex_method_id =selector if selector .startswith ('0x')else f'0x{selector }'

        url =f"https://www.4byte.directory/api/v1/signatures/?hex_signature={hex_method_id }"
        response =requests .get (url ,timeout =5 )
        response .raise_for_status ()

        data =response .json ()

        if data and data .get ('results'):
            results =sorted (data ['results'],key =lambda x :x ['id'])
            return results [0 ]['text_signature']

        return f"{selector }"

    except Exception :
        return f"lookup_error({selector })"

def extract_all_paths_from_call_tree (call_hierarchy :Dict )->List [List [Dict ]]:

    all_paths =[]

    def dfs (node ,current_path =None ,depth =0 ):

        if current_path is None :
            current_path =[]


        node_info ={
        'from':node .get ('from',''),
        'to':node .get ('to',''),
        'method':node .get ('method',''),
        'method_id':node .get ('method_id',''),
        'value':node .get ('value','0'),
        'depth':node .get ('depth',depth ),
        'call_type':node .get ('call_type','function_call'),
        'input':node .get ('input',''),
        'address':node .get ('to','').lower (),
        'call_index':node .get ('call_index',-1 )
        }


        new_path =current_path +[node_info ]


        children =node .get ('children',[])

        if not children :

            all_paths .append (new_path .copy ())
            logger .debug (f"✅ : {len (new_path )}, : {node_info ['depth']}")
        else :

            for child in children :
                dfs (child ,new_path ,depth +1 )


    if call_hierarchy :

        if call_hierarchy .get ('method')=='virtual_root':
            logger .info (f"🔄 ...")
            for child_tree in call_hierarchy .get ('children',[]):
                logger .info (f"🔄 : {child_tree .get ('from','unknown')} -> {child_tree .get ('to','unknown')}")
                dfs (child_tree ,[],0 )
        else :
            logger .info (f"🔄 DFS: {call_hierarchy .get ('from','unknown')} -> {call_hierarchy .get ('to','unknown')}")
            dfs (call_hierarchy ,[],0 )

        logger .info (f"✅ DFS {len (all_paths )} ")
    else :
        logger .warning ('❌ ')

    return all_paths 

def read_security_events (excel_file :str ,max_rows :int =None )->List [Dict ]:

    try :
        df =pd .read_excel (excel_file )

        if max_rows :
            df =df .head (max_rows )

        events =[]
        for index ,row in df .iterrows ():
            if pd .notna (row .get ('Address'))and pd .notna (row .get ('Blockstart'))and pd .notna (row .get ('Blockend')):
                event ={
                'event_id':f'event_{index +1 }',
                'name':row .get ('Name',f'Event_{index +1 }'),
                'address':str (row ['Address']).strip ().lower (),
                'blockstart':int (row ['Blockstart']),
                'blockend':int (row ['Blockend']),
                'type':row .get ('Type','Unknown'),
                'date':row .get ('Date','Unknown'),
                }
                events .append (event )

        logger .info (f" {len (events )} ")
        return events 

    except Exception as e :
        logger .error (f"Excel: {str (e )}")
        return []

def extract_path_features (path :List [Dict ],tx_hash :str ,event_info :Dict ,tx_info :Dict )->Dict :

    if not path :
        return {}


    path_content ='->'.join ([f"{node ['from'][:10 ]}:{node ['to'][:10 ]}:{node ['method']}"for node in path ])
    path_id =hashlib .md5 (f"{tx_hash }_{path_content }".encode ()).hexdigest ()[:16 ]


    methods =[node ['method']for node in path if node ['method']]
    unique_methods =list (set (methods ))


    addresses =set ()
    for node in path :
        if node ['from']and node ['from']!='unknown':
            addresses .add (node ['from'])
        if node ['to']and node ['to']!='unknown':
            addresses .add (node ['to'])
    unique_addresses =list (addresses )


    max_depth =max ([node ['depth']for node in path ])if path else 0 


    total_value =0 
    for node in path :
        try :
            value =node ['value']
            if isinstance (value ,str ):
                if value .startswith ('0x'):
                    total_value +=int (value ,16 )
                elif value .isdigit ():
                    total_value +=int (value )
        except :
            pass 


    call_types =[node ['call_type']for node in path ]
    call_type_counts ={ct :call_types .count (ct )for ct in set (call_types )}


    path_nodes_detail =[]
    for i ,node in enumerate (path ):
        node_detail ={
        'step':i +1 ,
        'from':node ['from'],
        'to':node ['to'],
        'method':node ['method'],
        'method_id':node ['method_id'],
        'depth':node ['depth'],
        'call_type':node ['call_type'],
        'value':node ['value'],
        'input':node ['input']
        }
        path_nodes_detail .append (node_detail )

    return {
    'path_id':path_id ,
    'event_id':event_info ['event_id'],
    'event_name':event_info ['name'],
    'attacker_address':event_info ['address'],
    'tx_hash':tx_hash ,
    'tx_block_number':tx_info ['block_number'],
    'tx_method_name':tx_info ['method_name'],
    'path_length':len (path ),
    'max_depth':max_depth ,
    'path_content':path_content ,
    'methods':methods ,
    'unique_methods':unique_methods ,
    'method_count':len (unique_methods ),
    'addresses':unique_addresses ,
    'address_count':len (unique_addresses ),
    'total_value':total_value ,
    'call_type_distribution':call_type_counts ,
    'contains_create':any ('create'in node ['call_type']for node in path ),
    'contains_transfer':any ('transfer'in node ['method'].lower ()for node in path ),
    'contains_swap':any ('swap'in node ['method'].lower ()for node in path ),
    'contains_approve':any ('approve'in node ['method'].lower ()for node in path ),
    'block_range_start':event_info ['blockstart'],
    'block_range_end':event_info ['blockend'],
    'event_type':event_info ['type'],
    'path_nodes_detail':path_nodes_detail ,
    'extraction_timestamp':datetime .now ().isoformat ()
    }

def process_single_event (event :Dict ,scanner :Web3BlockchainScanner ,max_transactions :int =None )->List [Dict ]:

    logger .info (f": {event ['name']} (: {event ['address']})")


    transactions =scanner .scan_blocks_for_transactions (
    event ['address'],
    event ['blockstart'],
    event ['blockend']
    )

    if not transactions :
        logger .warning (f" {event ['name']} ")
        return []


    if max_transactions :
        transactions =transactions [:max_transactions ]
        logger .info (f": {max_transactions }")

    all_path_features =[]

    for i ,tx in enumerate (transactions ,1 ):
        try :
            logger .info (f"🔄  {i }/{len (transactions )}: {tx ['tx_hash']}")


            trace_data =scanner .get_transaction_trace (tx ['tx_hash'])

            if not trace_data :
                logger .warning (f"❌  {tx ['tx_hash']} trace")
                continue 


            call_hierarchy =process_trace_to_call_hierarchy (trace_data ,scanner ,tx )

            if not call_hierarchy :
                logger .warning (f"❌  {tx ['tx_hash']} ")
                continue 


            all_paths =extract_all_paths_from_call_tree (call_hierarchy )

            logger .info (f"✅  {tx ['tx_hash']}  {len (all_paths )} ")


            for path_idx ,path in enumerate (all_paths ,1 ):
                if path :
                    logger .debug (f" {path_idx }/{len (all_paths )}: {' -> '.join ([node .get ('to','unknown')for node in path ])}")
                    path_features =extract_path_features (path ,tx ['tx_hash'],event ,tx )
                    if path_features :
                        all_path_features .append (path_features )

        except Exception as e :
            logger .error (f"❌  {tx ['tx_hash']} : {str (e )}")
            traceback .print_exc ()
            continue 

    logger .info (f"🎯  {event ['name']}  {len (all_path_features )} ")
    return all_path_features 

def save_event_dataset (path_features :List [Dict ],event_info :Dict ,output_format :str ='csv',output_dir :str ='path_datasets')->str :

    Path (output_dir ).mkdir (exist_ok =True )

    timestamp =datetime .now ().strftime ('%Y%m%d_%H%M%S')

    safe_event_name =''.join (c for c in event_info ['name']if c .isalnum ()or c in (' ','-','_')).strip ()
    safe_event_name =safe_event_name .replace (' ','_')[:50 ]
    event_address_short =event_info ['address'][:10 ]

    filename =f"event_{event_info ['event_id']}_{safe_event_name }_{event_address_short }_{timestamp }"

    if not path_features :
        logger .warning (f" {event_info ['name']} ")
        return ''


    df =pd .DataFrame (path_features )


    df ['methods_str']=df ['methods'].apply (lambda x :'|'.join (x )if x else '')
    df ['unique_methods_str']=df ['unique_methods'].apply (lambda x :'|'.join (x )if x else '')
    df ['addresses_str']=df ['addresses'].apply (lambda x :'|'.join (x )if x else '')
    df ['call_type_distribution_str']=df ['call_type_distribution'].apply (lambda x :json .dumps (x )if x else '{}')
    df ['path_nodes_detail_str']=df ['path_nodes_detail'].apply (lambda x :json .dumps (x )if x else '[]')


    df_save =df .drop (['methods','unique_methods','addresses','call_type_distribution','path_nodes_detail'],axis =1 )

    try :
        if output_format .lower ()=='csv':
            output_path =os .path .join (output_dir ,f"{filename }.csv")
            df_save .to_csv (output_path ,index =False ,encoding ='utf-8')
        elif output_format .lower ()=='excel':
            output_path =os .path .join (output_dir ,f"{filename }.xlsx")
            df_save .to_excel (output_path ,index =False ,engine ='openpyxl')
        elif output_format .lower ()=='parquet':
            output_path =os .path .join (output_dir ,f"{filename }.parquet")
            df_save .to_parquet (output_path ,index =False )
        else :
            raise ValueError (f": {output_format }")

        logger .info (f"📁  {event_info ['name']} : {output_path }")
        logger .info (f"📊  {len (df_save )} ")


        logger .info (f"📈  {event_info ['name']} :")
        logger .info (f"- : {event_info ['type']}")
        logger .info (f"- : {event_info ['address']}")
        logger .info (f"- : {event_info ['blockstart']} - {event_info ['blockend']}")
        logger .info (f"- : {df_save ['tx_hash'].nunique ()}")
        logger .info (f"- : {len (df_save )}")
        logger .info (f"- : {df_save ['path_length'].mean ():.2f}")
        logger .info (f"- : {df_save ['max_depth'].max ()}")
        logger .info (f"- : {df_save ['contains_transfer'].sum ()}")
        logger .info (f"- : {df_save ['contains_swap'].sum ()}")
        logger .info (f"- : {df_save ['contains_create'].sum ()}")
        logger .info (f"- : {df_save ['contains_approve'].sum ()}")

        return output_path 

    except Exception as e :
        logger .error (f" {event_info ['name']} : {str (e )}")
        return ''

def save_dataset_summary (all_events_summary :List [Dict ],output_format :str ='csv',output_dir :str ='path_datasets')->str :

    Path (output_dir ).mkdir (exist_ok =True )

    timestamp =datetime .now ().strftime ('%Y%m%d_%H%M%S')
    filename =f"events_summary_{timestamp }"

    if not all_events_summary :
        logger .warning ('')
        return ''


    df =pd .DataFrame (all_events_summary )

    try :
        if output_format .lower ()=='csv':
            output_path =os .path .join (output_dir ,f"{filename }.csv")
            df .to_csv (output_path ,index =False ,encoding ='utf-8')
        elif output_format .lower ()=='excel':
            output_path =os .path .join (output_dir ,f"{filename }.xlsx")
            df .to_excel (output_path ,index =False ,engine ='openpyxl')
        elif output_format .lower ()=='parquet':
            output_path =os .path .join (output_dir ,f"{filename }.parquet")
            df .to_parquet (output_path ,index =False )
        else :
            raise ValueError (f": {output_format }")

        logger .info (f"📁 : {output_path }")
        logger .info (f"📊  {len (df )} ")

        return output_path 

    except Exception as e :
        logger .error (f": {str (e )}")
        return ''

def main ():

    logger .info ('🚀 Web3')


    excel_file ='SecurityEvent_dataset_v1.xlsx'
    max_events =20 
    max_transactions_per_event =1000 
    output_format ='excel'
    output_dir ='path_datasets'


    if not os .path .exists (excel_file ):
        logger .error (f"Excel: {excel_file }")
        return 


    ankr_key ='0e6456645648a5ce03caff65736c8b2bb1856fafa4ab1e3d6eadcce0ce0217a5'
    if not ankr_key :
        logger .error ('❌ ANKR_API_KEY')
        logger .error ('.env: ANKR_API_KEY=your_api_key')
        return 


    scanner =Web3BlockchainScanner ()
    if not scanner .w3 :
        logger .error ('❌ Web3')
        return 

    logger .info ('🔧 Web3')


    logger .info (f"📖 Excel: {excel_file }")
    events =read_security_events (excel_file ,max_events )

    if not events :
        logger .error ('')
        return 

    logger .info (f"📋  {len (events )} ")


    saved_files =[]
    events_summary =[]
    total_paths =0 

    for i ,event in enumerate (events ,1 ):
        try :
            logger .info (f"🎯  {i }/{len (events )} : {event ['name']}")
            logger .info (f"📊 : {event ['type']} | : {event ['address']} | : {event ['blockstart']}-{event ['blockend']}")


            path_features =process_single_event (event ,scanner ,max_transactions_per_event )

            if path_features :

                output_path =save_event_dataset (path_features ,event ,output_format ,output_dir )

                if output_path :
                    saved_files .append (output_path )
                    total_paths +=len (path_features )


                    event_summary ={
                    'event_id':event ['event_id'],
                    'event_name':event ['name'],
                    'event_type':event ['type'],
                    'attacker_address':event ['address'],
                    'block_start':event ['blockstart'],
                    'block_end':event ['blockend'],
                    'date':event .get ('date','Unknown'),
                    'total_paths':len (path_features ),
                    'unique_transactions':len (set (p ['tx_hash']for p in path_features )),
                    'avg_path_length':sum (p ['path_length']for p in path_features )/len (path_features ),
                    'max_depth':max (p ['max_depth']for p in path_features ),
                    'contains_transfer_count':sum (p ['contains_transfer']for p in path_features ),
                    'contains_swap_count':sum (p ['contains_swap']for p in path_features ),
                    'contains_create_count':sum (p ['contains_create']for p in path_features ),
                    'contains_approve_count':sum (p ['contains_approve']for p in path_features ),
                    'output_file':os .path .basename (output_path )
                    }
                    events_summary .append (event_summary )

                    logger .info (f"✅  {event ['name']} ")
                else :
                    logger .warning (f"⚠️  {event ['name']} ")
            else :
                logger .warning (f"⚠️  {event ['name']} ")

        except Exception as e :
            logger .error (f"❌  {event ['name']} : {str (e )}")
            traceback .print_exc ()
            continue 


    if events_summary :
        summary_path =save_dataset_summary (events_summary ,output_format ,output_dir )
        if summary_path :
            saved_files .append (summary_path )


    logger .info ('🎉 ')
    logger .info (f"📊 :")
    logger .info (f"- : {len (events_summary )}/{len (events )}")
    logger .info (f"- : {total_paths }")
    logger .info (f"- : {len (saved_files )}")
    logger .info (f"📁 :")
    for file_path in saved_files :
        logger .info (f"  - {file_path }")
    logger .info ('🔗 Web3 + Ankr trace + analyze_user_behavior.py')

if __name__ =='__main__':
    main ()