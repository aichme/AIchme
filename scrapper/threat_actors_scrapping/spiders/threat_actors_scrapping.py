import scrapy
import json
import traceback
from tqdm import tqdm 

class MitreSpider(scrapy.Spider):
    """
    Scrap the APTs usages from MITRE ATT&CK website.

    Input:
        - json file with the URLs for all the APTs of the website.

    Output:
        - Folder with the scrapped results for all the APTs. Each APT information is stored in a unique JSON file. 
    """
    name = "mitre"
    previous_domain = None
    previous_main_id = None
    input_path = 'inputs/urls.json'
    output_path = 'outputs/threat_actors_data'

    def start_requests(self):
        with open(self.input_path, 'r') as f:
            groups = json.load(f)

        for group, name in groups.items():
            final_url = f"https://attack.mitre.org/groups/{group}"
            yield scrapy.Request(url=final_url, callback=self.parse, cb_kwargs={'group_name': name})

    def parse(self, response, group_name):
        techniques = response.css(".techniques-used tbody tr")
        techniques_output = []

        for technique in techniques:
            technique_info = self.create_dict(technique, group_name)
            techniques_output.append(technique_info)
        
        
        with open(f'{self.output_path}/{group_name}.json', 'w') as f:
            json.dump(techniques_output, f, indent=4, ensure_ascii=False)


    def create_dict(self, technique, name):
        try:
            if 'sub technique' in technique.attrib.get('class', None):
                domain = technique.css('td:nth-child(1)::text').get(default="").strip()
                if domain == '':
                    domain = self.previous_domain
                else:
                    self.previous_domain = domain
                main_id = technique.css('td:nth-child(2) a::text').get(default="").strip()
                if main_id == '':
                    main_id = self.previous_main_id
                else:
                    self.previous_main_id = main_id
                sub_id = technique.css('td:nth-child(3) a::text').get(default="").strip()
                technique_name = technique.css('td:nth-child(4) a::text').getall()
                use_text = technique.css('td:nth-child(5) *::text').getall()
                use_text = " ".join([text.strip() for text in use_text if text.strip()])

                full_id = main_id + sub_id if sub_id else main_id
                full_technique_name = ': '.join(technique_name) if len(technique_name) > 1 else technique_name[0]

                return {
                    "Domain": domain,
                    "ID": full_id,
                    "Technique": full_technique_name,
                    "Use": use_text
                }
            else:
                domain = technique.css('td:nth-child(1)::text').get(default="").strip()
                full_id = technique.css('td:nth-child(2) a::text').get(default="").strip()
                technique_name = technique.css('td:nth-child(3) a::text').getall()
                use_text = technique.css('td:nth-child(4) *::text').getall()
                use_text = " ".join([text.strip() for text in use_text if text.strip()])

                full_technique_name = ': '.join(technique_name) if len(technique_name) > 1 else technique_name[0]

                return {
                    "Domain": domain,
                    "ID": full_id,
                    "Technique": full_technique_name,
                    "Use": use_text
                }
        except Exception:
            with open('console_error.txt', 'a') as f:
                f.write(f"Group Name: {name}\n")
                f.write(f"Something went wrong in technique: {technique}\n")
                f.write(f"{traceback.format_exc()}\n\n")



class CVEsSpider(scrapy.Spider):
    """
    Scrap the CVE name and description from services.nvd.nist.gov website.

    Input:
        - JSON file with a list of the CVE names we wish to scrap.

    Output:
        - JSON file, dictionary, with keys the CVE IDs and each value is a dictionary, 
        with keys the CVE name and the CVE description.
    """

    name = "cve_titles"
    cve_dict = {}
    input_path = 'inputs/cve_names.json'
    output_path = 'outputs/cve_outputs.json'

    def start_requests(self):
        with open(self.input_path, 'r') as f:
            cve_names = json.load(f)

        for cve in tqdm(cve_names):
            final_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
            yield scrapy.Request(url=final_url, callback=self.parse, cb_kwargs={'cve': cve})


    def parse(self, response, cve):
        print(response.json())
        cve_response = response.json()['vulnerabilities'][0]['cve']
        name = cve_response.get('cisaVulnerabilityName', '')
        lang_descriptions = cve_response.get('descriptions', [])
        for lang_description in lang_descriptions:
            if lang_description['lang'] == 'en':
                description = lang_description['value']
                break 
                
        self.cve_dict[cve]= {
            'name': name,
            'description': description
        }
        return 
    
    def close(self, reason):
        with open(self.output_path, 'w') as f:
            json.dump(self.cve_dict, f, indent=4, ensure_ascii=False)
        