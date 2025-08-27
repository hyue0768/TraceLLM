



import os 
import sys 
import json 
import argparse 
import logging 
from pathlib import Path 
from typing import List ,Set ,Tuple ,Dict 

import pandas as pd 



logging .basicConfig (
level =logging .INFO ,
format ='%(asctime)s - %(levelname)s - %(message)s',
)
logger =logging .getLogger (__name__ )



def list_dataset_files (input_path :str )->List [Path ]:

    p =Path (input_path )
    files :List [Path ]=[]
    if p .is_dir ():
        patterns =[
        'event_*.csv',
        'event_*.xlsx',
        'event_*.parquet',
        ]
        for pat in patterns :
            files .extend (sorted (p .glob (pat )))
    elif p .is_file ():
        files =[p ]
    else :
        logger .error (f": {input_path }")
    return files 


def read_dataset (path :Path )->pd .DataFrame :

    suffix =path .suffix .lower ()
    if suffix =='.csv':
        return pd .read_csv (path )
    if suffix in ['.xlsx','.xls']:
        return pd .read_excel (path )
    if suffix =='.parquet':
        return pd .read_parquet (path )
    raise ValueError (f": {path }")


def write_dataset (df :pd .DataFrame ,input_file :Path ,output_dir :Path )->Path :

    output_dir .mkdir (parents =True ,exist_ok =True )
    stem =input_file .stem 
    suffix =input_file .suffix .lower ()
    labeled_name =f"{stem }_labeled{suffix }"
    out_path =output_dir /labeled_name 
    if suffix =='.csv':
        df .to_csv (out_path ,index =False ,encoding ='utf-8')
    elif suffix in ['.xlsx','.xls']:
        df .to_excel (out_path ,index =False ,engine ='openpyxl')
    elif suffix =='.parquet':
        df .to_parquet (out_path ,index =False )
    else :
        raise ValueError (f": {out_path }")
    return out_path 


def normalize_address (addr :str )->str :
    if not isinstance (addr ,str ):
        return ''
    a =addr .strip ().lower ()
    return a 


def normalize_method_name (method :str )->Tuple [str ,str ]:

    if not isinstance (method ,str ):
        return '',''
    m =method .strip ()
    if not m :
        return '',''
    m_lower =m .lower ()
    if m_lower .startswith ('0x')and len (m_lower )in (10 ,8 ,66 ):

        return m_lower ,m_lower 
    base =m_lower .split ('(')[0 ]
    return m_lower ,base 


def load_attackers (addresses_excel :str =None ,addresses_file :str =None ,addresses_list :str =None )->Set [str ]:
    attackers :Set [str ]=set ()

    if addresses_excel :
        try :
            df =pd .read_excel (addresses_excel )
            col ='Address'if 'Address'in df .columns else ('address'if 'address'in df .columns else None )
            if col :
                attackers .update (df [col ].dropna ().astype (str ).map (normalize_address ).tolist ())
        except Exception as e :
            logger .warning (f"Excel: {e }")

    if addresses_file and Path (addresses_file ).exists ():
        try :
            p =Path (addresses_file )
            if p .suffix .lower ()=='.json':
                data =json .loads (p .read_text (encoding ='utf-8'))
                if isinstance (data ,list ):
                    attackers .update (normalize_address (x )for x in data )
            else :

                raw =p .read_text (encoding ='utf-8')
                parts =[x .strip ()for x in raw .replace ('\n',',').split (',')if x .strip ()]
                attackers .update (normalize_address (x )for x in parts )
        except Exception as e :
            logger .warning (f": {e }")

    if addresses_list :

        if isinstance (addresses_list ,list ):
            parts :List [str ]=[]
            for token in addresses_list :
                if token :
                    parts .extend ([x .strip ()for x in str (token ).replace ('\n',',').split (',')if x .strip ()])
        else :
            parts =[x .strip ()for x in str (addresses_list ).replace ('\n',',').split (',')if x .strip ()]
        attackers .update (normalize_address (x )for x in parts )
    return {a for a in attackers if a }


def load_malicious_methods (methods_file :str =None ,methods_list :List [str ]|str =None )->Tuple [Set [str ],Set [str ]]:

    methods :List [str ]=[]
    if methods_file and Path (methods_file ).exists ():
        try :
            p =Path (methods_file )
            if p .suffix .lower ()=='.json':
                data =json .loads (p .read_text (encoding ='utf-8'))
                if isinstance (data ,list ):
                    methods .extend ([str (x )for x in data ])
            else :
                raw =p .read_text (encoding ='utf-8')
                methods .extend ([x .strip ()for x in raw .replace ('\n',',').split (',')if x .strip ()])
        except Exception as e :
            logger .warning (f": {e }")
    if methods_list :

        if isinstance (methods_list ,list ):
            for token in methods_list :
                if token :
                    methods .extend ([x .strip ()for x in str (token ).replace ('\n',',').split (',')if x .strip ()])
        else :
            methods .extend ([x .strip ()for x in str (methods_list ).replace ('\n',',').split (',')if x .strip ()])

    full_set :Set [str ]=set ()
    base_set :Set [str ]=set ()
    for m in methods :
        full ,base =normalize_method_name (m )
        if full :
            full_set .add (full )
        if base :
            base_set .add (base )
    return full_set ,base_set 


def row_involves_attackers (row :pd .Series ,attacker_set :Set [str ])->bool :


    addresses :Set [str ]=set ()
    if 'addresses_str'in row and isinstance (row ['addresses_str'],str )and row ['addresses_str']:
        addresses .update (normalize_address (x )for x in row ['addresses_str'].split ('|')if x )


    if 'path_nodes_detail_str'in row and isinstance (row ['path_nodes_detail_str'],str )and row ['path_nodes_detail_str']:
        try :
            nodes =json .loads (row ['path_nodes_detail_str'])
            if isinstance (nodes ,list ):
                for n in nodes :
                    f =normalize_address (n .get ('from',''))if isinstance (n ,dict )else ''
                    t =normalize_address (n .get ('to',''))if isinstance (n ,dict )else ''
                    if f :
                        addresses .add (f )
                    if t :
                        addresses .add (t )
        except Exception :
            pass 


    if 'attacker_address'in row and isinstance (row ['attacker_address'],str ):
        aa =normalize_address (row ['attacker_address'])
        if aa :
            addresses .add (aa )

    return len (addresses .intersection (attacker_set ))>0 


def row_contains_malicious_methods (row :pd .Series ,mal_full :Set [str ],mal_base :Set [str ])->bool :

    methods :Set [str ]=set ()


    if 'methods_str'in row and isinstance (row ['methods_str'],str )and row ['methods_str']:
        for m in row ['methods_str'].split ('|'):
            full ,base =normalize_method_name (m )
            if full :
                methods .add (full )
            if base :
                methods .add (base )


    if 'path_nodes_detail_str'in row and isinstance (row ['path_nodes_detail_str'],str )and row ['path_nodes_detail_str']:
        try :
            nodes =json .loads (row ['path_nodes_detail_str'])
            if isinstance (nodes ,list ):
                for n in nodes :
                    if isinstance (n ,dict ):
                        m =n .get ('method','')
                        full ,base =normalize_method_name (m )
                        if full :
                            methods .add (full )
                        if base :
                            methods .add (base )
        except Exception :
            pass 


    if methods .intersection (mal_full ):
        return True 
    if methods .intersection (mal_base ):
        return True 
    return False 


def label_dataframe (df :pd .DataFrame ,attacker_set :Set [str ],mal_full :Set [str ],mal_base :Set [str ])->pd .DataFrame :

    if df is None or df .empty :
        return df 

    def label_row (row :pd .Series )->int :
        involves =row_involves_attackers (row ,attacker_set )
        contains =row_contains_malicious_methods (row ,mal_full ,mal_base )
        return int (involves and contains )

    df =df .copy ()
    df ['label']=df .apply (label_row ,axis =1 )
    return df 



def parse_args (argv :List [str ])->argparse .Namespace :
    parser =argparse .ArgumentParser (description ='Script 2: Label Attack Paths')
    parser .add_argument ('--input',required =True ,help =' event_*.csv/xlsx/parquet')
    parser .add_argument ('--output-dir',default ='path_datasets_labeled',help =' path_datasets_labeled')


    parser .add_argument ('--attackers-excel',help =' Address  Excel  Script 1 ')
    parser .add_argument ('--attackers-file',help ='txt/csv/json')
    parser .add_argument ('--attackers-list',nargs ='+',help ='--attackers-list 0xabc 0xdef  "0xabc,0xdef"')


    parser .add_argument ('--malicious-file',help ='/txt/csv/json')
    parser .add_argument ('--malicious-list',nargs ='+',help ='//--malicious-list borrow getUnderlyingPrice  "borrow,getUnderlyingPrice"')

    parser .add_argument ('--merge-output',action ='store_true',help =' all_events_labeled.csv')
    return parser .parse_args (argv )


def main (argv :List [str ]=None ):
    args =parse_args (argv or sys .argv [1 :])


    files =list_dataset_files (args .input )
    if not files :
        logger .error ('')
        sys .exit (1 )
    logger .info (f" {len (files )} ")


    attacker_set =load_attackers (
    addresses_excel =args .attackers_excel ,
    addresses_file =args .attackers_file ,
    addresses_list =args .attackers_list ,
    )
    if not attacker_set :
        logger .warning (' attacker_address ')
    else :
        logger .info (f" {len (attacker_set )} ")


    mal_full ,mal_base =load_malicious_methods (
    methods_file =args .malicious_file ,
    methods_list =args .malicious_list ,
    )
    if not (mal_full or mal_base ):
        logger .error ('')
        sys .exit (1 )
    logger .info (f"/ {len (mal_full )}  {len (mal_base )} ")


    output_dir =Path (args .output_dir )
    labeled_paths :List [Path ]=[]
    merged_frames :List [pd .DataFrame ]=[]

    for idx ,f in enumerate (files ,1 ):
        try :
            logger .info (f"[{idx }/{len (files )}] : {f .name }")
            df =read_dataset (f )
            if df is None or df .empty :
                logger .warning (f": {f }")
                continue 

            df_labeled =label_dataframe (df ,attacker_set ,mal_full ,mal_base )
            out_path =write_dataset (df_labeled ,f ,output_dir )
            labeled_paths .append (out_path )
            merged_frames .append (df_labeled )
            logger .info (f"✅ : {out_path }")
        except Exception as e :
            logger .error (f" {f }: {e }")


    if args .merge_output and merged_frames :
        try :
            merged =pd .concat (merged_frames ,ignore_index =True )
            merged_out =output_dir /'all_events_labeled.csv'
            merged .to_csv (merged_out ,index =False ,encoding ='utf-8')
            logger .info (f"📦 : {merged_out }")
        except Exception as e :
            logger .error (f": {e }")


    logger .info ('🎉 ')
    for p in labeled_paths :
        logger .info (f"  - {p }")


if __name__ =='__main__':
    main ()

