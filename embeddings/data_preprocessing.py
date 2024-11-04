import os
import json
import re
import argparse
from nemo_curator.download.doc_builder import DocumentIterator, DocumentExtractor
from typing import Tuple, Set, List, Optional

class ThreatActorIterator(DocumentIterator):
    SEPARATOR_TOKEN = "},"
 
    def __init__(self):
        super().__init__()
        self._counter = -1
 
    def iterate(self, file_path: str):
        self._counter = -1
        file_name = os.path.basename(file_path).split('.')[0]
 
        with open(file_path, "r") as file:
            example = []
 
            def split_meta(example):
                if example:
                    self._counter += 1
                    content = "\n".join(example)
                    meta = {
                        "filename": file_name,
                        "id": f"{file_name}-{self._counter}",
                    }
 
                    return meta, content
 
            for line in file:
                if line.strip() == ThreatActorIterator.SEPARATOR_TOKEN:
                    if example:
                        yield split_meta(example)
                        example = []
                else:
                    example.append(line.strip())
 
            if example:
                yield split_meta(example)


class ThreatActorExtractor(DocumentExtractor):
    def __init__(self, path_to_cve_json: Optional[str] = None):
        super().__init__()
        if path_to_cve_json:
            with open(path_to_cve_json, 'r') as f:
                self.cve_knowledge_base = json.load(f)
            self.generate_knowledge = False
        else:
            self.cve_knowledge_base = {}
  
    def extract(self, content: str, basename:str) -> Tuple[Set, str]:
        if content == '[]':
            return {}, None
        if content[0] == '[' and content[-1] == ']':
            content = content[1:]
            content = content[:-1]
        elif content[0] == '[':
            content = content[1:]
            content += '}'
        elif content[-1] == ']':
            content = content[:-1]
        else:
            content += '}'
            
        use_col = json.loads(content)['Use']
        use_col = use_col.replace(basename,'')
        use_col = re.sub(r'\[\d+\]', '', use_col)

        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, use_col)

        for CVE in cve_matches:
            cve_dict = self.cve_knowledge_base.get(CVE, {})
            if cve_dict:
                name = cve_dict.get('name','')
                if name == '':
                    name = cve_dict.get('description', '')
            use_col = use_col.replace(CVE, name).strip()
        return {}, use_col

def get_json_files(folder_path: str):
    json_files = []
    for file in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file)
        if os.path.isfile(file_path) and (file.endswith('.json') or file.endswith('.jsonl')):
            json_files.append(file_path)
    
    return json_files

def dump_to_file(to_dump: str, output_filename: str):
    """Helper function to facilitate dumping to file."""
    with open(output_filename, "w") as output_file:
        output_file.writelines(to_dump)
     
def write_jsonl(input_filenames: List[str], output_filename: str, path_to_cve: Optional[str] = None):
    to_dump = []
    for input_filename in input_filenames:
        basename = os.path.basename(input_filename).split('.')[0]
        iterator = ThreatActorIterator()
        extractor = ThreatActorExtractor(path_to_cve_json=path_to_cve)
     
        for item in iterator.iterate(input_filename):
            record_meta, content = item
            extracted = extractor.extract(content, basename)
     
            if extracted is None:
                continue
     
            text_meta, text = extracted
     
            if text is None:
                continue
     
            line = {
                "text": text,
                **text_meta,
                **record_meta,
            }
            json_out = json.dumps(line, ensure_ascii=False)
            to_dump.append(json_out + "\n")

    dump_to_file(to_dump, output_filename)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process threat actor data to a unified jsonl file.')
    parser.add_argument('-d', '--threat_actor_data', help='Threat actor data folder', required=True)
    parser.add_argument('-o', '--output_filename', help='Output jsonl filename', required=True)
    parser.add_argument('--cve_data', help='json file with the CVE names and descriptions', required=True)
    args = parser.parse_args()

    threat_actors = get_json_files(args.threat_actor_data)
    write_jsonl(input_filenames=threat_actors, output_filename=args.output_filename, path_to_cve=args.cve_data)