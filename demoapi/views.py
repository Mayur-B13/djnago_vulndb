from urllib import response
from django.shortcuts import render
from django.http import HttpResponse
import requests, json
import pandas as pd
from django.core.paginator import Paginator

def cves(req):
    try:
        response = requests.get("https://plasticuproject.pythonanywhere.com/nvd-api/v1/recent")
        vulns = response.json()
    
    except AttributeError:
        pass
        
    # Load the JSON data from the response
    jd = json.loads(response.text)

    # Initialize empty lists
    id_list = []
    last_modified_date_list = []
    desc_value_list = []
    severity_list = []

    # Iterate over the list of dictionaries
    for entry in jd:
        # Extract values and append them to respective lists
        id_list.append(entry["cve"]["CVE_data_meta"]["ID"])
        last_modified_date_list.append(entry["lastModifiedDate"])
        desc_value_list.append(entry["cve"]["description"]["description_data"][0]["value"])
        
        impact = entry.get('impact',{})
        
        severity = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'severity level not available')
        
        severity_list.append(severity)

    info = {'ID':id_list,'DATES':last_modified_date_list,'DESC':desc_value_list,'SEVERITY':severity_list}
    
    df = pd.DataFrame.from_dict(info)
    
    jrec = df.reset_index().to_json(orient='records')
    data = []
    data = json.loads(jrec)
    
    # Creating our paginator object
    paginator = Paginator(data, 30)  # Show 30 records per page.
    
    # Get current page number from query string. (If not provided, defaults to 1)
    page_number = req.GET.get('page', 1)

    # Get records in current page
    page_of_data = paginator.get_page(page_number)
	
    # Add pagination data to context
    context = {'c': page_of_data}

    return render(req, "vuln.html", context)
