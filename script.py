import re
from datetime import date
from time import sleep
from pathlib import Path
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager
import url as urlmodule

url = urlmodule.url
Path("./browser_profile").mkdir(parents=True, exist_ok=True)
####### user webdriver to open the page for raw log file
service = ChromeService(executable_path=ChromeDriverManager().install())
options = ChromeOptions()
options.add_argument("user-data-dir=./browser_profile")
driver = webdriver.Chrome(service=service, options=options)

driver.get(url)
el = WebDriverWait(driver, timeout=90).until(lambda d: d.find_element_by_css_selector("body > pre"))
scan_report = el.text
driver.quit()
lines = scan_report.splitlines()

###### process log
# line_num
i = 0 
line_i = lines[i]
while i<len(lines) and "Scan results for: image" not in line_i:
    i +=1
    line_i = lines[i]

# parse docker image name
p = re.compile(r'.*Scan results for: image (.*) sha.*$')
m = p.search(line_i)
image_name = m.group(1)

# process the table lines of vulnerabilities
p_delimiter = re.compile(r'\d{4}-\d{2}-\d{2}T(?:\d{2}:?){3}[.].*Z [+](-+[+])+')
p_content = re.compile(r'\d{4}-\d{2}-\d{2}T(?:\d{2}:?){3}[.].*Z [|].*[|]$')
table_list = []

i += 1
while i<len(lines) and not p_delimiter.match(lines[i]):
    table= []
    i += 1
    while i<len(lines) and p_delimiter.match(lines[i]):
        i += 1
        if p_content.match(lines[i]):
            lines_i = re.sub(r'\x1b\[\dm', '', lines[i])
            lines_i = re.sub(r'\x1b\[\d{2};1m', '', lines_i)
            fields = list(field_i.strip() for field_i in lines_i.split('|'))[1:]
            i += 1
            while p_content.match(lines[i]):
                lines_i = re.sub(r'\x1b\[\dm', '', lines[i])
                lines_i = re.sub(r'\x1b\[\d{2};1', '', lines_i)
                fields = list(' '.join(filter(None, [field_pre, field_cur.strip()])) 
                    for field_pre, field_cur in zip(fields, lines_i.split('|')[1:]))
                i += 1
            table.append(fields)
        else:
            table_list.append(table)

f_vuls = pd.DataFrame(table_list[0][1:], columns=table_list[0][0])
f_comps = pd.DataFrame(table_list[1][1:], columns=table_list[1][0])

f_vuls.to_excel(f'{date.today()}_vulnerability_report.xlsx', sheet_name = 'sheet1')
f_comps.to_excel(f'{date.today()}_compliancy_report.xlsx', sheet_name = 'sheet1')