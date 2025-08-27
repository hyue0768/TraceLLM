


import pandas as pd 
import numpy as np 
from typing import Dict ,List ,Tuple ,Optional ,Set ,Any 
from collections import defaultdict ,deque 
import logging 

logger =logging .getLogger (__name__ )


class CallTreeNode :


    def __init__ (self ,method :str ='',depth :int =0 ,node_id :int =0 ):
        self .method =method 
        self .depth =depth 
        self .node_id =node_id 
        self .children ={}
        self .parent =None 
        self .is_leaf =False 
        self .path_info ={}


        self .is_suspicious_path =False 
        self .related_path_ids =set ()
        self .suspicious_path_ids =set ()

    def add_child (self ,method :str ,node_id :int )->'CallTreeNode':

        if method not in self .children :
            child =CallTreeNode (method ,self .depth +1 ,node_id )
            child .parent =self 
            self .children [method ]=child 
        return self .children [method ]

    def get_fanout (self )->int :

        return len (self .children )

    def get_all_neighbors (self )->Set ['CallTreeNode']:

        neighbors =set ()


        if self .parent :
            neighbors .add (self .parent )


        neighbors .update (self .children .values ())

        return neighbors 

    def get_k_neighbors (self ,k :int )->Set ['CallTreeNode']:

        if k ==0 :
            return set ()

        neighbors =set ()
        visited ={self }
        queue =deque ([(self ,0 )])

        while queue :
            current_node ,distance =queue .popleft ()


            if distance >0 :
                neighbors .add (current_node )


            if distance <k :

                if current_node .parent and current_node .parent not in visited :
                    visited .add (current_node .parent )
                    queue .append ((current_node .parent ,distance +1 ))


                for child in current_node .children .values ():
                    if child not in visited :
                        visited .add (child )
                        queue .append ((child ,distance +1 ))

        return neighbors 

    def mark_as_suspicious (self ,path_id :str ):

        self .is_suspicious_path =True 
        self .suspicious_path_ids .add (path_id )

    def add_path_id (self ,path_id :str ):

        self .related_path_ids .add (path_id )


class TransactionCallTree :


    def __init__ (self ,tx_hash :str ):
        self .tx_hash =tx_hash 
        self .root =CallTreeNode ('ROOT',0 ,0 )
        self .nodes =[self .root ]
        self .path_to_leaf ={}
        self .path_to_nodes ={}
        self .node_count =1 
        self .suspicious_path_ids =set ()

    def add_path (self ,path_data :Dict )->CallTreeNode :

        path_id =path_data ['path_id']
        methods_str =str (path_data .get ('methods_str','')).strip ()


        if methods_str and methods_str not in ['','nan','None']:
            methods =[m .strip ()for m in methods_str .split ('|')if m .strip ()]
        else :
            methods =[]


        current =self .root 
        path_nodes =[current ]


        current .add_path_id (path_id )

        for method in methods :
            if method not in current .children :

                current .add_child (method ,self .node_count )
                self .nodes .append (current .children [method ])
                self .node_count +=1 
            current =current .children [method ]
            current .add_path_id (path_id )
            path_nodes .append (current )


        current .is_leaf =True 
        current .path_info =path_data .copy ()
        self .path_to_leaf [path_id ]=current 
        self .path_to_nodes [path_id ]=path_nodes 

        return current 

    def mark_suspicious_paths (self ,suspicious_path_ids :List [str ]):

        self .suspicious_path_ids =set (suspicious_path_ids )

        for path_id in suspicious_path_ids :
            if path_id in self .path_to_nodes :

                for node in self .path_to_nodes [path_id ]:
                    node .mark_as_suspicious (path_id )

        logger .debug (f" {self .tx_hash }:  {len (suspicious_path_ids )} ")

    def get_path_context (self ,path_id :str ,k :int )->Dict [str ,Any ]:

        if path_id not in self .path_to_nodes :
            return {}

        path_nodes =self .path_to_nodes [path_id ]
        context_nodes =set (path_nodes )


        for node in path_nodes :
            neighbors =node .get_k_neighbors (k )
            context_nodes .update (neighbors )


        context_edges =[]
        for node in context_nodes :

            if node .parent and node .parent in context_nodes :
                context_edges .append ((node .parent .node_id ,node .node_id ))

            for child in node .children .values ():
                if child in context_nodes :
                    context_edges .append ((node .node_id ,child .node_id ))


        layer_distribution ={}
        for node in path_nodes :

            visited ={node }
            queue =deque ([(node ,0 )])

            while queue :
                current_node ,distance =queue .popleft ()

                if distance >0 and distance <=k :
                    layer =distance 
                    if layer not in layer_distribution :
                        layer_distribution [layer ]=0 
                    layer_distribution [layer ]+=1 

                if distance <k :
                    if current_node .parent and current_node .parent not in visited :
                        visited .add (current_node .parent )
                        queue .append ((current_node .parent ,distance +1 ))

                    for child in current_node .children .values ():
                        if child not in visited :
                            visited .add (child )
                            queue .append ((child ,distance +1 ))

        return {
        'path_id':path_id ,
        'path_nodes':[node .node_id for node in path_nodes ],
        'context_nodes':[node .node_id for node in context_nodes ],
        'context_edges':context_edges ,
        'k_layers':k ,
        'layer_distribution':layer_distribution ,
        'node_details':{
        node .node_id :{
        'method':node .method ,
        'depth':node .depth ,
        'is_leaf':node .is_leaf ,
        'is_suspicious':node .is_suspicious_path ,
        'fanout':node .get_fanout (),
        'path_info':node .path_info if node .is_leaf else None ,
        'related_paths':list (node .related_path_ids ),
        'suspicious_paths':list (node .suspicious_path_ids )
        }
        for node in context_nodes 
        }
        }

    def get_path_context_with_expansion (self ,path_id :str ,k :int )->Dict [str ,Any ]:

        if path_id not in self .path_to_nodes :
            return {}

        target_path_nodes =self .path_to_nodes [path_id ]
        if not target_path_nodes :
            return {}


        target_methods =[node .method for node in target_path_nodes ]


        current_paths ={
        f"{path_id }_original":target_path_nodes 
        }


        all_generated_paths ={f"{path_id }_original":target_path_nodes }
        layer_path_counts ={0 :1 }

        if k >0 :

            if k >=1 :
                new_paths ={}


                for i ,node in enumerate (target_path_nodes ):

                    for child_method ,child_node in node .children .items ():

                        if i ==0 :

                            extended_path_nodes =[node ,child_node ]
                        else :

                            extended_path_nodes =target_path_nodes [:i +1 ]+[child_node ]

                        extended_path_key =f"{path_id }_k1_from_{node .method }_to_{child_method }"


                        if (extended_path_key not in all_generated_paths and 
                        extended_path_nodes !=target_path_nodes ):
                            new_paths [extended_path_key ]=extended_path_nodes 
                            all_generated_paths [extended_path_key ]=extended_path_nodes 

                layer_path_counts [1 ]=len (new_paths )
                current_paths =new_paths 

                logger .info (f" {path_id }: K=1 {len (new_paths )}  {len (all_generated_paths )}")
                if new_paths :
                    logger .info (f"  : {list (new_paths .keys ())[:3 ]}...")


            for layer in range (2 ,k +1 ):
                if not current_paths :
                    break 

                new_paths ={}


                for current_path_key ,current_path_nodes in current_paths .items ():

                    leaf_node =current_path_nodes [-1 ]


                    for child_method ,child_node in leaf_node .children .items ():

                        extended_path_nodes =current_path_nodes +[child_node ]
                        extended_path_key =f"{current_path_key }_k{layer }_{child_method }"


                        if extended_path_key not in all_generated_paths :
                            new_paths [extended_path_key ]=extended_path_nodes 
                            all_generated_paths [extended_path_key ]=extended_path_nodes 

                layer_path_counts [layer ]=len (new_paths )
                current_paths =new_paths 


                logger .info (f" {path_id }: K={layer } {len (new_paths )}  {len (all_generated_paths )}")
                if new_paths :
                    logger .info (f"  : {list (new_paths .keys ())[:3 ]}...")

                if not new_paths :
                    logger .info (f" {path_id }: {layer }")
                    break 


        all_nodes =set ()
        for path_nodes in all_generated_paths .values ():
            all_nodes .update (path_nodes )


        path_connections =[]
        for path_key_1 ,nodes_1 in all_generated_paths .items ():
            for path_key_2 ,nodes_2 in all_generated_paths .items ():
                if path_key_1 >=path_key_2 :
                    continue 

                if len (nodes_1 )<len (nodes_2 ):
                    if nodes_2 [:len (nodes_1 )]==nodes_1 :
                        path_connections .append ((path_key_1 ,path_key_2 ))
                elif len (nodes_2 )<len (nodes_1 ):
                    if nodes_1 [:len (nodes_2 )]==nodes_2 :
                        path_connections .append ((path_key_2 ,path_key_1 ))


        all_edges =[]
        for node in all_nodes :
            if node .parent and node .parent in all_nodes :
                all_edges .append ((node .parent .node_id ,node .node_id ))

        return {
        'target_path_id':path_id ,
        'k_layers':k ,
        'related_paths':{
        path_key :[node .node_id for node in nodes ]
        for path_key ,nodes in all_generated_paths .items ()
        },
        'path_connections':path_connections ,
        'all_nodes':[node .node_id for node in all_nodes ],
        'all_edges':all_edges ,
        'layer_statistics':{
        'total_paths':len (all_generated_paths ),
        'total_nodes':len (all_nodes ),
        'target_path_length':len (target_path_nodes ),
        'expansion_layers':k ,
        'layer_path_counts':layer_path_counts ,
        'actual_expansion_depth':max (layer_path_counts .keys ())if layer_path_counts else 0 
        },
        'node_details':{
        node .node_id :{
        'method':node .method ,
        'depth':node .depth ,
        'is_leaf':node .is_leaf ,
        'is_suspicious':node .is_suspicious_path ,
        'fanout':node .get_fanout (),
        'path_info':node .path_info if node .is_leaf else None ,
        'in_paths':[path_key for path_key ,pnodes in all_generated_paths .items ()if node in pnodes ]
        }for node in all_nodes 
        },
        'path_details':{
        path_key :{
        'nodes':[node .node_id for node in nodes ],
        'methods':[node .method for node in nodes ],
        'is_target':path_key .endswith ('_original'),
        'length':len (nodes ),
        'generation_layer':0 if path_key .endswith ('_original')else int (path_key .split ('_ext_')[1 ].split ('_')[0 ])if '_ext_'in path_key else 0 
        }for path_key ,nodes in all_generated_paths .items ()
        }
        }

    def get_all_suspicious_contexts (self ,k :int )->Dict [str ,Dict ]:

        contexts ={}
        for path_id in self .suspicious_path_ids :
            contexts [path_id ]=self .get_path_context (path_id ,k )
        return contexts 

    def get_edges (self )->List [Tuple [int ,int ]]:

        edges =[]

        def dfs (node ):
            for child in node .children .values ():
                edges .append ((node .node_id ,child .node_id ))
                dfs (child )

        dfs (self .root )
        return edges 

    def get_tree_statistics (self )->Dict [str ,Any ]:

        total_nodes =len (self .nodes )
        leaf_nodes =sum (1 for node in self .nodes if node .is_leaf )
        suspicious_nodes =sum (1 for node in self .nodes if node .is_suspicious_path )
        max_depth =max (node .depth for node in self .nodes )if self .nodes else 0 

        return {
        'tx_hash':self .tx_hash ,
        'total_nodes':total_nodes ,
        'leaf_nodes':leaf_nodes ,
        'suspicious_nodes':suspicious_nodes ,
        'max_depth':max_depth ,
        'total_paths':len (self .path_to_nodes ),
        'suspicious_paths':len (self .suspicious_path_ids )
        }


class CallTreeBuilder :


    def __init__ (self ):
        self .tx_trees ={}

    def build_transaction_trees (self ,df :pd .DataFrame )->Dict [str ,TransactionCallTree ]:

        logger .info ('...')

        tx_trees ={}

        for tx_hash ,tx_group in df .groupby ('tx_hash'):
            tree =TransactionCallTree (tx_hash )


            for _ ,row in tx_group .iterrows ():
                path_data ={
                'path_id':row ['path_id'],
                'methods_str':row .get ('methods_str',''),
                'label':int (row .get ('label',0 )),
                'path_length':int (row .get ('path_length',0 )),
                'max_depth':self ._safe_float (row .get ('max_depth',0 )),
                'method_count':self ._safe_float (row .get ('method_count',0 )),
                'address_count':self ._safe_float (row .get ('address_count',0 )),
                'total_value':self ._safe_float (row .get ('total_value',0 )),
                'contains_create':self ._safe_bool (row .get ('contains_create',0 )),
                'contains_transfer':self ._safe_bool (row .get ('contains_transfer',0 )),
                'contains_swap':self ._safe_bool (row .get ('contains_swap',0 )),
                'contains_approve':self ._safe_bool (row .get ('contains_approve',0 )),

                'event_name':row .get ('event_name','unknown'),
                'attacker_address':row .get ('attacker_address','unknown'),
                'source_file':row .get ('source_file','unknown')
                }
                tree .add_path (path_data )

            tx_trees [tx_hash ]=tree 

        self .tx_trees =tx_trees 
        logger .info (f" {len (tx_trees )} ")
        return tx_trees 

    def mark_suspicious_paths_in_trees (self ,suspicious_results :Dict [str ,List [str ]]):

        logger .info ('...')

        total_marked =0 

        for tx_hash ,tree in self .tx_trees .items ():

            tx_suspicious_paths =[]

            for source_file ,path_ids in suspicious_results .items ():
                for path_id in path_ids :
                    if path_id in tree .path_to_nodes :
                        tx_suspicious_paths .append (path_id )

            if tx_suspicious_paths :
                tree .mark_suspicious_paths (tx_suspicious_paths )
                total_marked +=len (tx_suspicious_paths )

        logger .info (f" {total_marked } ")

    def extract_path_contexts (self ,suspicious_results :Dict [str ,List [str ]],
    k :int )->Dict [str ,Dict [str ,Dict ]]:

        logger .info (f"K={k }...")


        self .mark_suspicious_paths_in_trees (suspicious_results )

        all_contexts ={}

        for source_file ,path_ids in suspicious_results .items ():
            file_contexts ={}

            for path_id in path_ids :

                found =False 
                for tx_hash ,tree in self .tx_trees .items ():
                    if path_id in tree .path_to_nodes :
                        context =tree .get_path_context_with_expansion (path_id ,k )
                        if context :
                            context ['tx_hash']=tx_hash 
                            context ['source_file']=source_file 
                            file_contexts [path_id ]=context 
                            found =True 
                            logger .debug (f" {path_id }: K={k } {context ['layer_statistics']['total_paths']} ")
                        break 

                if not found :
                    logger .warning (f" {path_id } ")

            if file_contexts :
                all_contexts [source_file ]=file_contexts 
                logger .info (f" {source_file }:  {len (file_contexts )} ")

        total_contexts =sum (len (contexts )for contexts in all_contexts .values ())
        logger .info (f" {total_contexts } ")

        return all_contexts 

    def get_global_statistics (self )->Dict [str ,Any ]:

        if not self .tx_trees :
            return {}

        stats =[]
        for tree in self .tx_trees .values ():
            stats .append (tree .get_tree_statistics ())

        total_nodes =sum (s ['total_nodes']for s in stats )
        total_paths =sum (s ['total_paths']for s in stats )
        total_suspicious =sum (s ['suspicious_paths']for s in stats )
        max_depth =max (s ['max_depth']for s in stats )if stats else 0 

        return {
        'total_transactions':len (self .tx_trees ),
        'total_nodes':total_nodes ,
        'total_paths':total_paths ,
        'total_suspicious_paths':total_suspicious ,
        'max_depth':max_depth ,
        'avg_nodes_per_tx':total_nodes /len (self .tx_trees )if self .tx_trees else 0 ,
        'avg_paths_per_tx':total_paths /len (self .tx_trees )if self .tx_trees else 0 
        }

    def _safe_float (self ,value )->float :

        if value is None or value =='':
            return 0.0 
        if isinstance (value ,(int ,float )):
            return float (value )
        if isinstance (value ,str ):
            value =value .strip ().lower ()
            if value in ['','nan','none','null']:
                return 0.0 
            try :
                return float (value )
            except ValueError :
                return 0.0 
        return 0.0 

    def _safe_bool (self ,value )->bool :

        if value is None or value =='':
            return False 
        if isinstance (value ,bool ):
            return value 
        if isinstance (value ,(int ,float )):
            return bool (value )
        if isinstance (value ,str ):
            value =value .strip ().lower ()
            return value in ['true','1','yes']
        return False 


def format_path_context_for_display (context :Dict [str ,Any ],
show_neighbors :bool =True )->str :

    if not context :
        return ''

    lines =[]
    lines .append (f"ID: {context ['path_id']}")
    lines .append (f"Hash: {context .get ('tx_hash','unknown')}")
    lines .append (f": {context .get ('source_file','unknown')}")

    path_nodes =context ['path_nodes']
    context_nodes =context ['context_nodes']
    node_details =context ['node_details']

    lines .append (f": {len (path_nodes )}")
    lines .append (f": {len (context_nodes )}")
    lines .append (f": {len (context .get ('context_edges',[]))}")


    path_methods =[]
    for node_id in path_nodes :
        if node_id in node_details :
            method =node_details [node_id ]['method']
            if method =='ROOT':
                path_methods .append ('ROOT')
            else :
                path_methods .append (method )

    lines .append (f": {' -> '.join (path_methods )}")

    if show_neighbors :

        neighbor_nodes =[nid for nid in context_nodes if nid not in path_nodes ]
        if neighbor_nodes :
            lines .append (f" ({len (neighbor_nodes )} ):")
            for node_id in neighbor_nodes [:5 ]:
                if node_id in node_details :
                    detail =node_details [node_id ]
                    lines .append (f"  - {node_id }: {detail ['method']} (:{detail ['depth']}, :{detail ['fanout']})")
            if len (neighbor_nodes )>5 :
                lines .append (f"  ...  {len (neighbor_nodes )-5 } ")

    return '\n'.join (lines )


if __name__ =='__main__':

    import sys 
    sys .path .append ('/home/os/shuzheng/whole_pipeline')
    from utils_scoring import parse_csv 

    logging .basicConfig (level =logging .INFO ,format ='%(asctime)s - %(levelname)s - %(message)s')


    test_file ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled/event_event_2_Barley_Finance_0x356e7481_20250806_104404_labeled.csv'

    try :
        df =parse_csv (test_file )
        df ['source_file']='test_file'


        builder =CallTreeBuilder ()
        trees =builder .build_transaction_trees (df [:50 ])


        suspicious_results ={
        'test_file':list (df ['path_id'].head (5 ))
        }


        contexts =builder .extract_path_contexts (suspicious_results ,k =3 )

        print (f" {len (trees )} ")
        print (f" {sum (len (c )for c in contexts .values ())} ")


        if contexts :
            first_file =list (contexts .keys ())[0 ]
            first_context =list (contexts [first_file ].values ())[0 ]
            print ('\n:')
            print (format_path_context_for_display (first_context ))


        stats =builder .get_global_statistics ()
        print (f"\n: {stats }")

    except Exception as e :
        print (f": {e }")
        import traceback 
        traceback .print_exc ()