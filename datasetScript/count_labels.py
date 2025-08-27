



import os 
import sys 
import csv 
import argparse 
from pathlib import Path 


def count_labels_in_csv (csv_path :Path )->tuple [int ,int ]:

    total_rows =0 
    label_ones =0 
    try :
        with csv_path .open ('r',encoding ='utf-8')as f :
            reader =csv .DictReader (f )
            for row in reader :
                total_rows +=1 
                label_val =row .get ('label')
                if label_val is None :
                    continue 

                if str (label_val ).strip ()=='1':
                    label_ones +=1 
    except UnicodeDecodeError :

        with csv_path .open ('r',encoding ='utf-8-sig',errors ='replace')as f :
            reader =csv .DictReader (f )
            for row in reader :
                total_rows +=1 
                label_val =row .get ('label')
                if label_val is None :
                    continue 
                if str (label_val ).strip ()=='1':
                    label_ones +=1 
    return total_rows ,label_ones 


def main (argv =None ):
    parser =argparse .ArgumentParser (description ='CSVlabel=1')
    parser .add_argument (
    '--dir',
    default ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled',
    help ='/home/os/shuzheng/whole_pipeline/path_datasets_labeled'
    )
    args =parser .parse_args (argv )

    target_dir =Path (args .dir )
    if not target_dir .exists ()or not target_dir .is_dir ():
        print (f': {target_dir }')
        sys .exit (1 )

    csv_files =sorted (target_dir .glob ('*.csv'))
    if not csv_files :
        print (f'CSV: {target_dir }')
        sys .exit (0 )

    grand_total =0 
    grand_label_ones =0 

    for csv_file in csv_files :
        total ,ones =count_labels_in_csv (csv_file )
        grand_total +=total 
        grand_label_ones +=ones 

    print (':')
    print (f'- : {target_dir }')
    print (f'- CSV : {len (csv_files )}')
    print (f'- : {grand_total }')
    print (f'- label=1 : {grand_label_ones }')
    if grand_total >0 :
        ratio =grand_label_ones /grand_total *100.0 
        print (f'- : {ratio :.2f}%')


if __name__ =='__main__':
    main ()

