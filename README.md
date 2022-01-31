# prismas_scan_report_conversion script
This script is used to covert raw log of Prismas scan into Excel file for analysis

## application setup
* Python 3.9 (other later Python could be also applicable)
* Pip

## Use
1. Clone the project
2. Install Pipenv via Pip ```pip install pipenv```
3. Create virtual environment for this project ```pipenv --python 3```
4. Install project dependencies ```pipenv install```
5. Paste the url of raw log in the *url* varaible in url.py
6. Run the script with ```python script```, vulnerability and compliancy reports will be generated in project folder with date stamp
