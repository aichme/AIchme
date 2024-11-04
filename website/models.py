from llama_index.llms.nvidia import NVIDIA
from llama_index.core.llms import ChatMessage, MessageRole
import parsers

def init_llm(temperature=0.7):
    """ 
    Function that makes a connection with the local hosted LLM.
    Receives as input the value of the temperature (default: 0.7, range:[0,1])
    """
    llm = NVIDIA(
        base_url="http://localhost:8001/v1", 
        model="meta/llama-3.1-8b-instruct",
        temperature=temperature,
        max_tokens=2048
    )
    return llm 


def extract_methods_from_cve(description:str) -> list:
    """
    Extract methods out of the CVE description.

    Expects:
        - description: The description of the CVE.

    Returns:
        - methods: List of methods, as they were extracted from the LLM.
    """
    llm = init_llm(temperature=0)
    prompt = create_prompt_for_methods_extraction(description=description)
    response = llm.chat(prompt)
    list_resp = parsers.parse_list_response(response.message.content)
    return list_resp


def create_prompt_for_methods_extraction(description:str):
    """
    Prompt creation for extracting methods out of the CVE description. 
    """
    return [
        ChatMessage(
            role=MessageRole.SYSTEM,
            content=(
                "You are an ethical hacker, specialized on extracting the techniques used on CVEs.\n"
                "Your job is to read carefully a CVE and extract the techniques that are mentioned in the CVE.\n"
                "You must follow the format in the Adversarial Tactics, Techniques, and Common Knowledge (MITRE ATT&CK)\n"
                "Keep all responses short, factual, and to the point. Avoid adding unnecessary explanations or descriptions.\n"
                "Summarize the information with only the essential points and no elaboration.\n"
            )
        ),
        ChatMessage(
            role=MessageRole.USER,
            content=(
                f"EXAMPLE OUTPUT\n" 
                f"* Used blogs and WordPress for C2 infrastructure.\n" 
                f"* Has sent emails with malicious Microsoft Office documents and PDFs attached.\n" 
                f"* Used PowerShell commands to execute payloads.\n" 
                f"* Has used direct Windows system calls by leveraging Dumpert.\n" 
                f"* Has used malicious DLLs that setup persistence in the Registry Key HKCU\\Software\\Microsoft\\Windows\\Current Version\\Run\n" 
                f"\n" 
                f"DESCRIPTION\n" 
                f"{description}\n" 
                f"\n"
                f"INSTRUCTIONS\n"
                f"Provide a list with possible candidates of technique uses exracted from the above description.\n" 
                f"Skip any preambles on your response.\n" 
                f"Try to match the level of verbosity in the examples.\n" 
                f"Do not output the name of the technique alone, but the description of the use as in the examples!\n" 
                f"Provide a list of only the most essential items that fully capture all the important information, combining similar points where possible and omitting unnecessary details.\n"
            )
        )
    ]


def create_prompt_for_summarization(methods:list, matches_per_method:dict, description:str):
    """
    Prompt creation for the summarization task, where the LLM receives as input the methods, the matches for each method and the CVE description.
    """
    usr_promt = 'CVE DESCRIPTION:\n'
    usr_promt += description
    usr_promt += "\n"

    for i,method in enumerate(methods):
        matches = matches_per_method.get(i+1, [])
        if len(matches) == 0:
            continue

        usr_promt += (
            f"TECHNIQUE\n"
            f"{method}\n"
            f"| Score  | APT | Technique |\n"
            f"|--------|-----|-----------|\n"
        )
        for match in matches:
            usr_promt += f"| {match['Score']:.4f} | {match['APT']} | {match['Usage']} |\n"
            
    return [
        ChatMessage(
            role=MessageRole.SYSTEM,
            content=(
                "You are a cybersecurity expert specializing in the analysis of Advanced Persistent Threats (APTs) and their attack techniques. "
                "Your task is to generate concise summaries that correlate the tactics and techniques used by APTs with the behaviors observed in specific Common Vulnerabilities and Exposures (CVEs).\n"
                "\n"
                "You will be provided with:\n"
                "* A description of the techniques observed in the CVE.\n"
                "* A table that matches these techniques to known APT techniques, including the APT's name and technique description.\n"
                "* A similarity score indicating how closely the APT's techniques align with those in the CVE (where a lower score means higher similarity).\n"
                "Using this information:\n"
                "\n"
                "1. Identify and summarize the key APT techniques that match the observed CVE behavior.\n"
                "2. Focus on correlating the tactics and techniques between the APTs and the CVE.\n"
                "3. Exclude any mention of similarity scores in your response.\n"
                "4. Your output should be concise, focusing only on relevant techniques, avoiding unnecessary details, and written in a clear, informative manner.\n"
            )
        ),
        ChatMessage(
            role=MessageRole.USER,
            content=(
                f"{usr_promt}\n"
                f"\n"
                f"INSTRUCTIONS\n"
                f"Based on the relevance between each APT's techniques and the CVE's techniques, assess the likelihood of each APT exploiting the CVE. "
                f"Summarize the overall potential of the CVE being used by these APTs, focusing on the CVE itself rather than individual techniques.\n"
                f"\n"
                f"In your response:\n"
                f"\n"
                f"* Highlight the relevance of each APT based on the technique matches, without mentioning the scores.\n"
                f"* Explain why certain APTs are more likely to exploit the CVE, using the similarity of their techniques as a basis.\n"
                f"* Provide a simple, concise output that combines all relevant information, ideally with a length of a page.\n"
                f"* Avoid any mention of scores and use markdown." 
            )
        )
    ]


def create_prompt_for_filtering(matches:list, description:str):
    """
    Prompt creation for filtering the extracted matches.
    """
    usr_promt = 'CVE DESCRIPTION:\n'
    usr_promt += description
    usr_promt += "\n"
    usr_promt += (
        "| ID  | Technique |\n"
        "|-----|-----------|\n"
    )

    for match in matches:
        usr_promt += f"| {match['id']} | {match['usage']} |\n"
            
    return [
        ChatMessage(
            role=MessageRole.SYSTEM,
            content=(
                "You are a cybersecurity expert specializing in the analysis of Advanced Persistent Threats (APTs) and their attack techniques.\n"
                "Your task is to filter out each technique provided in a table, if it doesn't fit on the CVE description.\n"
                "\n"
                "You will be provided with:\n"
                "* A CVE description\n"
                "* A table that contains a list of APT techniques.\n"
            )
        ),
        ChatMessage(
            role=MessageRole.USER,
            content=(
                f"{usr_promt}\n"
                f"\n"
                f"INSTRUCTIONS\n"
                "Based on the CVE description, you should check each entry in the table.\n"
                "In case that the technique in the table is described in the CVE description, add its ID to the final response.\n"
                "You should exclude only those techniques that you are certain that they can't fit in the description.\n"
                "If you are unsure about a specific technique, keep it in the list of IDs.\n"
                "Your response should be a list of IDs. Skip any preambles on your response.\n"
                f"EXAMPLE OUTPUT\n" 
                f"* ID24231\n" 
                f"* ID2385\n" 
                f"* ANOTHER_ID_865\n" 
                f"\n" 
            )
        )
    ]
