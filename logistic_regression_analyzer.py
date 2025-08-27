



import os 
import sys 
import pandas as pd 
import numpy as np 
import logging 
from typing import Dict ,List ,Tuple ,Any ,Optional 
from sklearn .model_selection import LeaveOneGroupOut 
from sklearn .linear_model import LogisticRegression 
from sklearn .feature_extraction .text import TfidfVectorizer 
from sklearn .preprocessing import StandardScaler 
from sklearn .pipeline import Pipeline 
from sklearn .compose import ColumnTransformer 
import warnings 


sys .path .append ('/home/os/shuzheng/whole_pipeline')
from utils_scoring import (
parse_csv ,compute_F_D_S_Fr ,normalize_per_tx ,
DEFAULT_SUSPICIOUS_METHODS 
)

warnings .filterwarnings ('ignore')
logger =logging .getLogger (__name__ )


class LogisticRegressionAnalyzer :


    def __init__ (self ,
    k :int =30 ,
    suspicious_methods :Optional [List [str ]]=None ,
    random_state :int =42 ):

        self .k =k 
        self .suspicious_methods =suspicious_methods or DEFAULT_SUSPICIOUS_METHODS 
        self .random_state =random_state 


        self .tfidf_vectorizer =TfidfVectorizer (
        max_features =1000 ,
        ngram_range =(1 ,2 ),
        lowercase =True ,
        token_pattern ='\\w+'
        )

        self .scaler =StandardScaler ()

        self .model =LogisticRegression (
        random_state =random_state ,
        class_weight ='balanced',
        max_iter =1000 ,
        solver ='liblinear'
        )

        logger .info (f"LogisticRegressionK={k }")

    def extract_advanced_features (self ,df :pd .DataFrame )->pd .DataFrame :

        logger .info ('...')

        feature_df =df .copy ()


        numeric_features =['path_length','max_depth','method_count','address_count','total_value']
        for col in numeric_features :
            if col in feature_df .columns :
                feature_df [col ]=pd .to_numeric (feature_df [col ],errors ='coerce').fillna (0 )


        bool_features =['contains_create','contains_transfer','contains_swap','contains_approve']
        for col in bool_features :
            if col in feature_df .columns :
                feature_df [col ]=feature_df [col ].astype (str ).str .lower ().isin (['true','1','yes']).astype (int )


        factors =compute_F_D_S_Fr (feature_df ,self .suspicious_methods )
        normalized_factors =normalize_per_tx (factors )


        feature_df ['F_fanout']=0.0 
        feature_df ['D_depth']=0.0 
        feature_df ['S_semantic']=0.0 
        feature_df ['Fr_frequency']=0.0 
        feature_df ['F_norm']=0.0 
        feature_df ['D_norm']=0.0 

        for _ ,row in feature_df .iterrows ():
            tx_hash =row ['tx_hash']
            path_id =row ['path_id']

            if tx_hash in normalized_factors and path_id in normalized_factors [tx_hash ]:
                factor_data =normalized_factors [tx_hash ][path_id ]
                idx =feature_df .index [(feature_df ['tx_hash']==tx_hash )&(feature_df ['path_id']==path_id )][0 ]

                feature_df .loc [idx ,'F_fanout']=factor_data ['F']
                feature_df .loc [idx ,'D_depth']=factor_data ['D']
                feature_df .loc [idx ,'S_semantic']=factor_data ['S']
                feature_df .loc [idx ,'Fr_frequency']=factor_data ['Fr']
                feature_df .loc [idx ,'F_norm']=factor_data ['F_norm']
                feature_df .loc [idx ,'D_norm']=factor_data ['D_norm']


        if 'total_value'in feature_df .columns :
            feature_df ['log_total_value']=np .log1p (feature_df ['total_value'].astype (float ))

        if 'path_length'in feature_df .columns and 'address_count'in feature_df .columns :
            feature_df ['complexity_ratio']=feature_df ['path_length']/np .maximum (feature_df ['address_count'],1 )


        feature_df ['methods_length']=feature_df ['methods_str'].astype (str ).str .len ()
        feature_df ['unique_methods_length']=feature_df ['unique_methods_str'].astype (str ).str .len ()


        feature_df ['suspicious_method_ratio']=0.0 
        for idx ,row in feature_df .iterrows ():
            methods_str =str (row .get ('methods_str','')).lower ()
            if methods_str and methods_str not in ['','nan','none']:
                methods =methods_str .split ('|')
                if methods :
                    suspicious_count =sum (
                    1 for method in methods 
                    if any (sus_method .lower ()in method for sus_method in self .suspicious_methods )
                    )
                    feature_df .loc [idx ,'suspicious_method_ratio']=suspicious_count /len (methods )

        logger .info (f": {len (feature_df .columns )}")
        return feature_df 

    def prepare_features (self ,df :pd .DataFrame )->Tuple [np .ndarray ,np .ndarray ]:


        numeric_features =[
        'path_length','max_depth','method_count','address_count',
        'F_fanout','D_depth','S_semantic','Fr_frequency','F_norm','D_norm',
        'log_total_value','complexity_ratio','methods_length','unique_methods_length',
        'suspicious_method_ratio'
        ]


        bool_features =['contains_create','contains_transfer','contains_swap','contains_approve']


        available_numeric =[col for col in numeric_features if col in df .columns ]
        available_bool =[col for col in bool_features if col in df .columns ]

        logger .info (f": {len (available_numeric )}")
        logger .info (f": {len (available_bool )}")


        feature_columns =available_numeric +available_bool 
        X_numeric =df [feature_columns ].values .astype (float )


        methods_text =df ['methods_str'].fillna ('').astype (str )

        methods_text =methods_text .str .replace ('|',' ')


        y =df ['label'].values .astype (int )

        return X_numeric ,methods_text ,y 

    def select_top_k_dedup (self ,df :pd .DataFrame ,scores :np .ndarray )->Tuple [List [str ],pd .DataFrame ]:


        result_df =df .copy ()
        result_df ['score']=scores 


        result_df ['sig_normalized']=result_df ['methods_str'].astype (str ).str .strip ().str .lower ()


        dedup_indices =[]
        sig_groups =result_df .groupby ('sig_normalized')

        for sig ,group in sig_groups :
            if len (group )>1 :

                best_idx =group ['score'].idxmax ()
                dedup_indices .append (best_idx )
            else :

                dedup_indices .append (group .index [0 ])


        dedup_df =result_df .loc [dedup_indices ].copy ()


        dedup_df_sorted =dedup_df .sort_values (['score','path_id'],ascending =[False ,True ])


        actual_k =min (self .k ,len (dedup_df_sorted ))
        top_k_paths =dedup_df_sorted .head (actual_k )

        logger .info (f": {len (dedup_df )}, top-{actual_k }")

        return top_k_paths ['path_id'].tolist (),dedup_df 

    def analyze_single_file (self ,train_df :pd .DataFrame ,test_df :pd .DataFrame )->Dict [str ,Any ]:


        train_features =self .extract_advanced_features (train_df )
        test_features =self .extract_advanced_features (test_df )


        X_train_numeric ,train_methods_text ,y_train =self .prepare_features (train_features )
        X_test_numeric ,test_methods_text ,y_test =self .prepare_features (test_features )


        X_train_tfidf =self .tfidf_vectorizer .fit_transform (train_methods_text )
        X_test_tfidf =self .tfidf_vectorizer .transform (test_methods_text )


        X_train_numeric_scaled =self .scaler .fit_transform (X_train_numeric )
        X_test_numeric_scaled =self .scaler .transform (X_test_numeric )


        X_train =np .hstack ([X_train_numeric_scaled ,X_train_tfidf .toarray ()])
        X_test =np .hstack ([X_test_numeric_scaled ,X_test_tfidf .toarray ()])


        self .model .fit (X_train ,y_train )


        test_scores =self .model .predict_proba (X_test )[:,1 ]


        top_k_path_ids ,dedup_df =self .select_top_k_dedup (test_df ,test_scores )


        dedup_df ['predicted']=dedup_df ['path_id'].isin (top_k_path_ids ).astype (int )


        y_dedup =dedup_df ['label'].values .astype (int )
        y_pred_dedup =dedup_df ['predicted'].values 

        TP =int (((y_pred_dedup ==1 )&(y_dedup ==1 )).sum ())
        FP =int (((y_pred_dedup ==1 )&(y_dedup ==0 )).sum ())
        FN =int (((y_pred_dedup ==0 )&(y_dedup ==1 )).sum ())
        TN =int (((y_pred_dedup ==0 )&(y_dedup ==0 )).sum ())


        precision =TP /(TP +FP )if (TP +FP )>0 else 0.0 
        recall =TP /(TP +FN )if (TP +FN )>0 else 0.0 
        accuracy =(TP +TN )/(TP +TN +FP +FN )if len (dedup_df )>0 else 0.0 
        f1 =2 *precision *recall /(precision +recall )if (precision +recall )>0 else 0.0 


        total_attack_paths_dedup =(y_dedup ==1 ).sum ()
        hit_attack_paths =TP 
        attack_hit_rate =hit_attack_paths /total_attack_paths_dedup if total_attack_paths_dedup >0 else 0.0 


        test_df_with_scores =test_df .copy ()
        test_df_with_scores ['score']=test_scores 
        test_df_with_scores ['predicted']=test_df_with_scores ['path_id'].isin (top_k_path_ids ).astype (int )

        return {
        'top_k_path_ids':top_k_path_ids ,
        'test_df_with_scores':test_df_with_scores ,
        'dedup_df':dedup_df ,
        'metrics':{
        'TP':TP ,'FP':FP ,'FN':FN ,'TN':TN ,
        'precision':precision ,
        'recall':recall ,
        'accuracy':accuracy ,
        'f1':f1 ,
        'attack_hit_rate':attack_hit_rate ,
        'total_attack_paths':int (total_attack_paths_dedup ),
        'hit_attack_paths':int (hit_attack_paths ),
        'actual_k':len (top_k_path_ids ),
        'total_paths_after_dedup':len (dedup_df ),
        'original_paths':len (test_df )
        }
        }

    def analyze_all_files (self ,input_dir :str )->Dict [str ,Any ]:

        logger .info (f"LOGO: {input_dir }")


        csv_files =[f for f in os .listdir (input_dir )if f .endswith ('.csv')]
        if not csv_files :
            raise ValueError (f" {input_dir } CSV")

        logger .info (f" {len (csv_files )} CSV")


        all_dfs =[]
        for csv_file in csv_files :
            file_path =os .path .join (input_dir ,csv_file )
            try :
                df =parse_csv (file_path )
                df ['source_file']=csv_file 
                all_dfs .append (df )
                logger .info (f" {csv_file }: {len (df )} ")
            except Exception as e :
                logger .error (f" {csv_file } : {e }")
                continue 

        if not all_dfs :
            raise ValueError ('')


        combined_df =pd .concat (all_dfs ,ignore_index =True )
        logger .info (f": {len (combined_df )}  {len (csv_files )} ")


        groups =combined_df ['source_file'].values 


        logo =LeaveOneGroupOut ()
        results ={}

        for train_idx ,test_idx in logo .split (combined_df ,combined_df ['label'],groups ):
            train_df =combined_df .iloc [train_idx ]
            test_df =combined_df .iloc [test_idx ]
            test_file =test_df ['source_file'].iloc [0 ]

            logger .info (f": {test_file } (: {len (train_df )} , : {len (test_df )} )")

            try :
                result =self .analyze_single_file (train_df ,test_df )
                results [test_file ]=result 

                metrics =result ['metrics']
                logger .info (f"  : ={metrics ['attack_hit_rate']:.3f}, "
                f"F1={metrics ['f1']:.3f}, ={metrics ['actual_k']}/{metrics ['total_paths_after_dedup']}, "
                f"={metrics ['original_paths']}, ={metrics ['total_attack_paths']}/{metrics ['hit_attack_paths']}")

            except Exception as e :
                logger .error (f"  : {e }")
                import traceback 
                traceback .print_exc ()
                continue 


        valid_results =[r for r in results .values ()if 'metrics'in r ]
        if valid_results :

            macro_metrics ={}
            for metric in ['attack_hit_rate','precision','recall','f1','accuracy']:
                values =[r ['metrics'][metric ]for r in valid_results ]
                macro_metrics [f'macro_{metric }']=np .mean (values )


            total_tp =sum (r ['metrics']['TP']for r in valid_results )
            total_fp =sum (r ['metrics']['FP']for r in valid_results )
            total_fn =sum (r ['metrics']['FN']for r in valid_results )
            total_tn =sum (r ['metrics']['TN']for r in valid_results )

            micro_precision =total_tp /(total_tp +total_fp )if (total_tp +total_fp )>0 else 0.0 
            micro_recall =total_tp /(total_tp +total_fn )if (total_tp +total_fn )>0 else 0.0 
            micro_f1 =2 *micro_precision *micro_recall /(micro_precision +micro_recall )if (micro_precision +micro_recall )>0 else 0.0 

            macro_metrics .update ({
            'micro_precision':micro_precision ,
            'micro_recall':micro_recall ,
            'micro_f1':micro_f1 
            })
        else :
            macro_metrics ={}

        final_result ={
        'per_file_results':results ,
        'global_metrics':macro_metrics ,
        'total_files':len (results ),
        'successful_files':len (valid_results )
        }

        logger .info (f"LOGO: {len (valid_results )}/{len (csv_files )} ")
        if macro_metrics :
            logger .info (f": ={macro_metrics ['macro_attack_hit_rate']:.3f}, "
            f"F1={macro_metrics ['macro_f1']:.3f}")

        return final_result 


if __name__ =='__main__':

    logging .basicConfig (level =logging .INFO ,format ='%(asctime)s - %(levelname)s - %(message)s')

    input_dir ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled'


    analyzer =LogisticRegressionAnalyzer (k =30 )


    try :
        results =analyzer .analyze_all_files (input_dir )
        print (f": {results ['successful_files']}/{results ['total_files']} ")

        if results ['global_metrics']:
            print (f": {results ['global_metrics']['macro_attack_hit_rate']:.3f}")
            print (f"F1: {results ['global_metrics']['macro_f1']:.3f}")

    except Exception as e :
        print (f": {e }")
        import traceback 
        traceback .print_exc ()