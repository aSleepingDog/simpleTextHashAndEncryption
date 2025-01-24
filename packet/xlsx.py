import openpyxl
from tqdm import tqdm

Table=openpyxl.load_workbook('tabelBack.xlsx')
Sheet1=Table.active

with open("result1.txt","r",encoding="utf-8") as f:
    lines=f.readlines()
    for i in tqdm(range(len(lines))):
        lineItem=lines[i].strip().split("|")
        for j in range(len(lineItem)):
            Sheet1[f"{chr(65+j)}{i+1}"]=lineItem[j]
tqdm(Table.save('tabelBack.xlsx'))