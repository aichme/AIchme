from pprint import pprint 
import config 
import json 

def load_cves_dataset():
    """ 
    Loads the available CVE names and returns them in a list. 
    """
    with open(config.FILENAMES_PATH, 'r') as f:
        CVES = json.load(f)
        CVES = [cve.rsplit('.',1)[0] for cve in CVES]
    return CVES

def parse_list_response(response):
    """
    Receives a multi-line response and parses the response to a list.
    Each new line of the response that starts with the character '*' will be a list element.
    """
    list_items = []
    lines = response.split("\n")
    for line in lines:
        if line.strip().startswith(('*')):
            list_items.append(line[1:].strip())
    return list_items


def calculate_possible_actors(matches: list):
    """
    Given a list of matches, where each match is a dictionary,
    this function creates a dictionary with the following keys:
    - actors: A list of all the different APTs found in the matches
    - counts: A list of the number of matcher for each actor
    """
    name_count = {}
    
    for item in matches:
        name = item['APT']  
        if name in name_count:
            name_count[name] += 1 
        else:
            name_count[name] = 1  
    
    print('Calculating possible APTs...')
    print('# of possible APTs: ', len(name_count))
    final_dict = {'actors': list(name_count.keys()), 'counts': list(name_count.values())}
    pprint(final_dict)
    return final_dict


def count_matches_per_method(matches: list):
    """
    Given a list of matches, where each match is a dictionary, 
    this function returns the following:
    1. final_matches_count: A dictionary that contains the keys:
       a) id: List of all the method IDs found in the matches.
       b) matches: List of the number of matches that correspond to that method ID.
    2. matches_per_method: Dictionary that has the method IDs as its keys and a list of the corresponding matches for each ID as its values. 
    """
    matches_count = {}
    matches_per_method = {}
    for match in matches:
        method_id = match['Method']
        if matches_count.get(method_id):
            matches_count[method_id] += 1
        else:
            matches_count[method_id] = 1
        
        if matches_per_method.get(method_id):
            matches_per_method[method_id].append(match)
        else:
            matches_per_method[method_id] = [match]

    final_matches_count = {'id': [f'Method #{key}' for key in matches_count.keys()], 'matches': list(matches_count.values())}
    return final_matches_count, matches_per_method